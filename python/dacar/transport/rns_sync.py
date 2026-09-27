"""Direct-link Delta push over a real RNS Link (§11, work doc #16 Phase 4a).

Optional, ``rns``-dependent transport wiring around the already pure-and-tested
receive boundary (``DeltaReceiver``). The use case is a constrained node — e.g.
an MCU running microReticulum — that cannot subscribe to rfed or run an LXMF
router: it exposes the ``dacar.sync.v1`` destination, and a peer pushes raw
§5.3 Delta payloads to it over Link requests. Verify-on-ingest (§11.2.4)
authenticates each Delta by the *issuer's* signature, so the transport adds no
trust — the same precedent as optical Paper Messages (§11.3). The pusher
therefore needs no Dacar state at all; its identity hash is just a grantee.

Three pieces:

  * :func:`handle_push` is the transport-free inbound seam: it applies one
    request payload (a raw §5.3 Delta, or a §11.1 batch of them) to a
    :class:`~dacar.delta.DeltaReceiver` and returns the applied count.
  * :func:`delta_request_handler` wraps that into the RNS
    ``response_generator`` a server registers on the ``delta`` request path;
    the response is the ack — a MessagePack map ``{"applied": <n>}``.
  * :class:`RnsSyncServer` exposes a node identity on ``dacar.sync.v1``,
    accepts Links, registers the handler, and announces.
  * :func:`push_deltas` is the client side: resolve the target's
    ``dacar.sync.v1`` destination from its recalled identity, open a Link,
    and send one request per Delta, collecting the per-Delta acceptance
    flags from the acks.

An ``applied == 0`` ack means the node decoded the request but accepted
nothing (unknown issuer, bad signature, stale §9 / future-skewed §12, or a
§9-horizon-expired duplicate); a missing/undecodable response counts as
failure. CRDT merge is idempotent, so re-pushing after either outcome is
always safe — the outbox drains only on ``applied >= 1``.

Importing the pure ``dacar`` core does NOT import this module, so the core
stays free of the ``rns`` dependency. Requires Reticulum (``pip install rns``).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, List, Optional

import RNS

from dacar import serialization
from dacar.delta import DeltaReceiver
from dacar.naming import APP_NAME, SYNC_ASPECTS
from dacar.transport.rns_challenge import establish_link

#: The RNS request path Deltas are pushed on.
SYNC_REQUEST_PATH = "delta"
#: Default per-Delta round-trip timeout in seconds.
DEFAULT_PUSH_TIMEOUT = 15.0
#: Default wait for the target's path-response announce, in seconds.
DEFAULT_PATH_TIMEOUT = 15.0
#: Extra slack beyond the RNS request timeout before the client gives up, so a
#: response arriving a hair after RNS's own timeout is still collected.
DEFAULT_TIMEOUT_GRACE = 2.0
#: Default Link establishment timeout in seconds.
DEFAULT_ESTABLISH_TIMEOUT = 15.0

__all__ = [
    "SYNC_REQUEST_PATH",
    "DEFAULT_PUSH_TIMEOUT",
    "DEFAULT_PATH_TIMEOUT",
    "DEFAULT_ESTABLISH_TIMEOUT",
    "pack_ack",
    "unpack_ack",
    "handle_push",
    "delta_request_handler",
    "RnsSyncServer",
    "ensure_destination_path",
    "push_deltas",
]


def pack_ack(applied: int) -> bytes:
    """Encode the push ack: a MessagePack map ``{"applied": <n>}``."""
    return serialization.packb({"applied": int(applied)})


def unpack_ack(data: Optional[bytes]) -> Optional[int]:
    """Decode a push ack; ``None`` when missing/undecodable (counts as failure).

    Returns the applied count (``0`` = the node refused the Delta — kept in
    the sender's outbox; ``>= 1`` = accepted and merged).
    """
    if not data:
        return None
    try:
        decoded = serialization.unpackb(bytes(data))
    except (ValueError, TypeError):
        return None
    if not isinstance(decoded, dict):
        return None
    applied = decoded.get("applied")
    if not isinstance(applied, int) or isinstance(applied, bool) or applied < 0:
        return None
    return applied


def handle_push(receiver: DeltaReceiver, data: bytes) -> int:
    """Transport-free inbound seam: apply one push request to ``receiver``.

    Tries the payload as a single raw §5.3 Delta first, then as a §11.1 batch
    (a MessagePack array of Delta payloads). The two shapes are unambiguous:
    an Operation payload is an 8-element mixed array, a batch is an array of
    binary elements. Returns the number of Deltas applied (0 = decoded but
    nothing accepted, or undecodable garbage — never raises: a request
    handler must not crash on arbitrary bytes).
    """
    data = bytes(data)
    if not data:
        return 0
    if receiver.apply_payload(data):
        return 1
    try:
        applied = receiver.apply_payloads(data)
    except Exception:
        return 0
    return int(applied)


#: RNS ``response_generator(path, data, request_id, link_id, remote_identity,
#: requested_at) -> response_bytes | None``.
ResponseGenerator = Callable[
    [str, bytes, bytes, bytes, "Any", float], Optional[bytes]
]


def delta_request_handler(receiver: DeltaReceiver) -> ResponseGenerator:
    """Build the RNS response_generator ingesting pushed Deltas (§11).

    The returned callable matches the RNS ``response_generator`` contract: it
    feeds ``data`` to :func:`handle_push` and returns the ack bytes. Every
    outcome yields a response — even ``{"applied": 0}`` — so the pusher can
    distinguish "node refused (kept in outbox)" from "request lost (retry)".
    """

    def handler(
        path: str,
        data: bytes,
        request_id: bytes,
        link_id: bytes,
        remote_identity: Any,
        requested_at: float,
    ) -> Optional[bytes]:
        try:
            return pack_ack(handle_push(receiver, data))
        except Exception:
            return None

    return handler


class RnsSyncServer:
    """Direct-link Delta ingestion endpoint over RNS Links (§11, doc #16 4a).

    Creates the ``dacar.sync.v1`` destination for ``identity``, enables Link
    acceptance, registers the Delta push request handler, and (by default)
    announces so pushers can resolve a path. A running ``RNS.Reticulum`` is
    assumed. This is also the seam an MCU firmware's request handler mirrors:
    verified Link identity → :meth:`DeltaReceiver.apply_payload` → act.
    """

    REQUEST_PATH = SYNC_REQUEST_PATH

    def __init__(
        self,
        identity: "RNS.Identity",
        receiver: DeltaReceiver,
        *,
        app_name: str = APP_NAME,
        aspects: tuple = SYNC_ASPECTS,
        allow: int = RNS.Destination.ALLOW_ALL,
        announce: bool = True,
    ) -> None:
        self._receiver = receiver
        self._destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects
        )
        self._destination.accepts_links(True)
        self._destination.register_request_handler(
            self.REQUEST_PATH,
            response_generator=delta_request_handler(receiver),
            allow=allow,
        )
        if announce:
            self._destination.announce()

    @property
    def receiver(self) -> DeltaReceiver:
        return self._receiver

    @property
    def destination(self) -> "RNS.Destination":
        return self._destination

    @property
    def destination_hash(self) -> bytes:
        return self._destination.hash

    def announce(self, app_data: Optional[bytes] = None) -> None:
        """(Re)announce the destination so pushers can resolve a path to it."""
        self._destination.announce(app_data=app_data)


def ensure_destination_path(
    identity_hash: bytes,
    *,
    app_name: str = APP_NAME,
    aspects: tuple = SYNC_ASPECTS,
    timeout: float = DEFAULT_PATH_TIMEOUT,
    poll_interval: float = 0.25,
    on_request: Optional[Callable[[], None]] = None,
) -> "RNS.Destination":
    """Build the OUT ``dacar.sync.v1`` destination for an identity and wait
    for a transport path to it.

    ``identity_hash`` must be recallable (an earlier announce or the durable
    keyring path — the CLI seeds both before calling). Sends a ``path?``
    request for the derived destination hash and polls until the node's
    path-response announce populates the path table. Raises ``ValueError``
    when the identity is unknown, and ``TimeoutError`` when no path resolves
    within ``timeout``.
    """
    identity = RNS.Identity.recall(bytes(identity_hash))
    if identity is None:
        raise ValueError(
            f"node identity unknown for {bytes(identity_hash).hex()}; "
            "wait for its announce (or `dacar identity remember` it)"
        )
    destination = RNS.Destination(
        identity, RNS.Destination.OUT, RNS.Destination.SINGLE, app_name, *aspects
    )
    if RNS.Transport.has_path(destination.hash):
        return destination
    if on_request is not None:
        on_request()
    RNS.Transport.request_path(destination.hash)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if RNS.Transport.has_path(destination.hash):
            return destination
        time.sleep(poll_interval)
    raise TimeoutError(
        f"no path to {destination.hash.hex()} ({app_name}.{'.'.join(aspects)}) "
        f"resolved within {timeout}s (is the node announcing and reachable?)"
    )


def push_deltas(
    payloads: List[bytes],
    target_hash: bytes,
    *,
    request_path: str = SYNC_REQUEST_PATH,
    timeout: float = DEFAULT_PUSH_TIMEOUT,
    establish_timeout: float = DEFAULT_ESTABLISH_TIMEOUT,
    path_timeout: float = DEFAULT_PATH_TIMEOUT,
    on_request: Optional[Callable[[], None]] = None,
) -> List[bool]:
    """Push raw §5.3 Delta payloads to a node over one Link (§11, doc #16 4a).

    ``target_hash`` is the *node identity hash* (16 bytes) — the sync
    destination ``dacar.sync.v1`` is derived from it. Opens one Link, sends
    one request per payload, and parses each ack: ``applied >= 1`` → accepted
    (``True``); ``applied == 0`` → the node refused (``False`` — e.g. unknown
    issuer, stale §9, future-skewed §12); no/undecodable response → ``False``
    (lost request — retry is safe, CRDT merge is idempotent).

    Returns the per-payload acceptance flags. The caller records accepted
    Deltas in the sent box / drains them from the outbox (work doc #11 — the
    same durable-issuance lifecycle as rfed/LXMF publishes).
    """
    destination = ensure_destination_path(
        bytes(target_hash),
        timeout=path_timeout,
        on_request=on_request,
    )
    link = establish_link(destination, timeout=establish_timeout)
    if link is None:
        return [False] * len(payloads)

    accepted: List[bool] = []
    try:
        for payload in payloads:
            accepted.append(
                _push_one(link, request_path, bytes(payload), timeout)
            )
    finally:
        try:
            link.teardown()
        except Exception:
            pass  # teardown is best-effort; results already collected
    return accepted


def _push_one(
    link: "RNS.Link", request_path: str, payload: bytes, timeout: float
) -> bool:
    """Send one Delta as a Link request and wait for the ack."""
    if getattr(link, "status", None) != RNS.Link.ACTIVE:
        return False
    box: dict = {}
    done = threading.Event()

    def on_response(receipt: Any) -> None:
        box["response"] = getattr(receipt, "response", None)
        done.set()

    def on_failed(receipt: Any) -> None:
        done.set()

    sent = link.request(
        request_path,
        payload,
        response_callback=on_response,
        failed_callback=on_failed,
        timeout=timeout,
    )
    if sent is False:
        return False
    if not done.wait(timeout + DEFAULT_TIMEOUT_GRACE):
        return False
    applied = unpack_ack(box.get("response"))
    return applied is not None and applied >= 1
