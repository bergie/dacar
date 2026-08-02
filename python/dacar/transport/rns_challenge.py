"""§8 Strict Consistency Challenge over a real RNS Link.

Optional, ``rns``-dependent transport wiring around the already pure-and-tested
§8 logic (``Challenge``, ``AuthoritativeServer``, ``Receipt``).

  * :func:`challenge_request_handler` builds the RNS *response_generator* a
    server registers on the ``dacar.auth.v1`` destination: it feeds each incoming
    challenge payload to :meth:`AuthoritativeServer.handle` and returns the
    signed Freshness Receipt bytes.
  * :class:`RnsChallengeServer` exposes an Authoritative Identity on
    ``dacar.auth.v1``, accepts Links, and registers that handler.
  * :class:`RnsLinkTransport` is the client-side
    :data:`~dacar.challenge.Transport` callable: it sends a challenge payload
    over an established Link and blocks for the signed receipt, returning
    ``None`` on timeout/partition (which §8 treats as DENY).
  * :func:`establish_link` opens a Link and blocks until ACTIVE.

Importing the pure ``dacar`` core does NOT import this module, so the core
stays free of the ``rns`` dependency. Requires Reticulum (``pip install rns``).
The Dacar-specific glue (handler wrapping, synchronous request/response wait,
partition -> DENY) is covered by injected-fake unit tests; a live two-node RNS
round-trip is the natural CI integration test on top.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Optional

import RNS

from dacar.challenge import AuthoritativeServer
from dacar.naming import APP_NAME, CHALLENGE_ASPECTS

#: The RNS request path used for the Challenge exchange.
CHALLENGE_REQUEST_PATH = "challenge"
#: Default Challenge round-trip timeout in seconds. Partition -> §8 DENY.
DEFAULT_CHALLENGE_TIMEOUT = 15.0
#: Extra slack beyond the RNS request timeout before the client gives up, so a
#: response arriving a hair after RNS's own timeout is still collected.
DEFAULT_TIMEOUT_GRACE = 2.0
#: Default Link establishment timeout in seconds.
DEFAULT_ESTABLISH_TIMEOUT = 15.0


#: RNS ``response_generator(path, data, request_id, link_id, remote_identity,
#: requested_at) -> response_bytes | None``.
ResponseGenerator = Callable[
    [str, bytes, bytes, bytes, "Any", float], Optional[bytes]
]


def challenge_request_handler(server: AuthoritativeServer) -> ResponseGenerator:
    """Build the RNS response_generator answering Challenge requests (§8.4).

    The returned callable matches the RNS ``response_generator`` contract: it
    feeds ``data`` (the §8.3 challenge payload) to
    :meth:`AuthoritativeServer.handle` and returns the signed Receipt payload.
    Malformed or unprocessable challenges yield ``None`` (no response), which
    the client treats as a partition -> DENY (§8.6).
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
            return server.handle(data)
        except Exception:
            return None

    return handler


class RnsChallengeServer:
    """Authoritative endpoint: answers Challenge requests over RNS Links (§8).

    Creates the ``dacar.auth.v1`` destination for ``identity``, enables Link
    acceptance, registers the Challenge request handler, and (by default)
    announces so clients can find it. A running ``RNS.Reticulum`` is assumed.
    """

    REQUEST_PATH = CHALLENGE_REQUEST_PATH

    def __init__(
        self,
        identity: "RNS.Identity",
        server: AuthoritativeServer,
        *,
        app_name: str = APP_NAME,
        aspects: tuple = CHALLENGE_ASPECTS,
        allow: int = RNS.Destination.ALLOW_ALL,
        announce: bool = True,
    ) -> None:
        self._server = server
        self._destination = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, app_name, *aspects
        )
        self._destination.accepts_links(True)
        self._destination.register_request_handler(
            self.REQUEST_PATH,
            response_generator=challenge_request_handler(server),
            allow=allow,
        )
        if announce:
            self._destination.announce()

    @property
    def server(self) -> AuthoritativeServer:
        return self._server

    @property
    def destination(self) -> "RNS.Destination":
        return self._destination

    @property
    def destination_hash(self) -> bytes:
        return self._destination.hash

    def announce(self, app_data: Optional[bytes] = None) -> None:
        """(Re)announce the destination so clients can resolve a path to it."""
        self._destination.announce(app_data=app_data)


class RnsLinkTransport:
    """Client-side :data:`~dacar.challenge.Transport` over an established Link.

    Call it with the §8.3 challenge payload: it issues an RNS request on the
    link and blocks until the signed Receipt arrives (or the request fails /
    times out). Returns the receipt bytes, or ``None`` on any failure -- which
    :class:`~dacar.challenge.ChallengeClient` treats as a partition -> DENY (§8).
    """

    REQUEST_PATH = CHALLENGE_REQUEST_PATH

    def __init__(
        self,
        link: "RNS.Link",
        *,
        request_path: str = CHALLENGE_REQUEST_PATH,
        timeout: float = DEFAULT_CHALLENGE_TIMEOUT,
        grace: float = DEFAULT_TIMEOUT_GRACE,
    ) -> None:
        self._link = link
        self._path = request_path
        self._timeout = timeout
        self._grace = grace

    def __call__(self, challenge_payload: bytes) -> Optional[bytes]:
        link = self._link
        if getattr(link, "status", None) != RNS.Link.ACTIVE:
            return None  # link not ready -> partition -> DENY (§8)
        box: dict = {}
        done = threading.Event()

        def on_response(receipt: Any) -> None:
            box["response"] = getattr(receipt, "response", None)
            done.set()

        def on_failed(receipt: Any) -> None:
            done.set()

        sent = link.request(
            self._path,
            challenge_payload,
            response_callback=on_response,
            failed_callback=on_failed,
            timeout=self._timeout,
        )
        if sent is False:
            return None  # could not send -> DENY
        if not done.wait(self._timeout + self._grace):
            return None  # timed out -> partition -> DENY (§8)
        return box.get("response")


def establish_link(
    destination: "RNS.Destination",
    *,
    timeout: float = DEFAULT_ESTABLISH_TIMEOUT,
) -> Optional["RNS.Link"]:
    """Open an RNS Link to ``destination`` and block until ACTIVE (§8.2).

    Returns the active Link, or ``None`` if it could not be established within
    ``timeout`` (partition -> §8 DENY). Requires a running ``RNS.Reticulum``
    and a reachable, announced destination.
    """
    ready = threading.Event()
    result: dict = {}

    def on_established(link: "RNS.Link") -> None:
        result["link"] = link
        ready.set()

    link = RNS.Link(destination, established_callback=on_established)
    if ready.wait(timeout) and result.get("link") is not None:
        return result["link"]
    try:
        link.teardown()
    except Exception:
        pass
    return None
