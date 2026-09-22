"""LXMF session helpers for online commands (work doc #14).

One-shot, store-and-forward LXMF delivery/receive for the CLI, mirroring
``dacar.cli.rns`` for the rfed path: senders push to a propagation node
(proprietor) in a transient session and exit; receivers wake, pull pending
messages from the proprietor, apply them via verify-on-ingest, and exit. No
daemon anywhere — the proprietor queues everything (§11.2.3 wake → pull →
decrypt → apply).

The testable cores (:func:`run_lxmf_publish`, :func:`run_lxmf_sync`) take an
explicit ``router`` (LXMRouter or a compatible fake) so tests inject doubles
without booting RNS; the ``cmd_*`` wrappers in ``commands.py`` handle RNS boot,
the announce invariant (§11.2.4 — unlike RFed's RTID prelude, LXMF receivers
recall the *issuer* from the announce store, so announcing is required, not
hygiene), and router creation.
"""

from __future__ import annotations

import os
import time
from typing import List, Optional, Tuple

import LXMF
import RNS

__all__ = [
    "DEFAULT_SEND_TIMEOUT",
    "DEFAULT_SYNC_TIMEOUT",
    "LXMF_CHUNK_BUDGET",
    "boot_lxmf_router",
    "lxmf_out_destination",
    "uri_to_paper_bytes",
    "run_lxmf_publish",
    "run_lxmf_sync",
]

#: Seconds to wait for one outbound message to reach a terminal state. A
#: PROPAGATED send must establish a link to the proprietor and transfer the
#: message (an RNS Resource), which dominates the wait.
DEFAULT_SEND_TIMEOUT = 60

#: Seconds to wait for a proprietor sync to complete (link + message list +
#: downloads). Generous: a catch-up sync may transfer many messages.
DEFAULT_SYNC_TIMEOUT = 180

#: Content budget for propagated batch chunks. Propagation submits travel as
#: RNS Resources (no single-packet MDU), but chunks stay modest so a proprietor
#: never buffers one enormous message and a lost transfer is retried at chunk
#: granularity. Cross-implementation chunk *boundaries* are irrelevant — only
#: the batch codec must interop.
LXMF_CHUNK_BUDGET = 16 * 1024

#: Terminal LXMF message states (accepted or rejected) for send polling.
_ACCEPTED_STATES = (LXMF.LXMessage.SENT, LXMF.LXMessage.DELIVERED)
_FAILED_STATES = (
    LXMF.LXMessage.FAILED,
    LXMF.LXMessage.REJECTED,
    LXMF.LXMessage.CANCELLED,
)

#: Proprietor sync states that abort the wait (everything >= 0xf0 is failure).
_SYNC_FAILED_MIN = LXMF.LXMRouter.PR_NO_PATH


def boot_lxmf_router(identity, store_path: str, enforce_ratchets: bool = False):
    """Create an :class:`LXMF.LXMRouter` with storage under ``<store>/lxmf/``.

    The router registers the node's ``lxmf.delivery`` destination with ratchets
    **enabled** (§11.2.1 — required to decrypt propagated messages; the strict
    ``enforce_ratchets`` mode is a later deployment decision). Router state
    (ratchets, ingested-message IDs) persists across one-shot invocations, so
    forward secrecy survives process exits. RNS must already be booted.

    Routers are cached per ``(store, identity)`` within the process: RNS
    Transport rejects registering the same destination twice, and repeated
    one-shot invocations sharing a process (tests, embedding) must attach to
    the existing router — the in-process analogue of attach-or-spawn.
    """
    import os

    path = os.path.join(str(store_path), "lxmf")
    os.makedirs(path, exist_ok=True)
    cached = _ROUTERS.get((path, identity.hash))
    if cached is not None:
        return cached
    router = LXMF.LXMRouter(
        identity=identity, storagepath=path, enforce_ratchets=enforce_ratchets
    )
    router.register_delivery_identity(identity)
    _ROUTERS[(path, identity.hash)] = router
    return router


#: Per-process router cache (see :func:`boot_lxmf_router`).
_ROUTERS: dict = {}


def lxmf_out_destination(target_hash: bytes):
    """The recipient's OUT ``lxmf.delivery`` destination (for sending).

    Recalls the target's identity from RNS's announce store; raises
    ``ValueError`` when unknown — the sender must have seen (or be told) the
    recipient's announce first (``sync`` / a shared network does this).
    """
    identity = RNS.Identity.recall(bytes(target_hash))
    if identity is None:
        raise ValueError(
            f"unknown LXMF destination {RNS.hexrep(target_hash)} — wait for its "
            "announce (run dacar sync) or verify the hash"
        )
    return RNS.Destination(
        identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
    )


def uri_to_paper_bytes(uri: str) -> bytes:
    """Decode an ``lxm://`` Paper Message URI back to its encrypted bytes.

    Mirror of LXMF's ``LXMessage.as_uri`` (URL-safe base64, padding stripped),
    byte-compatible with reticulum-js's ``paperDataFromUri`` (including its
    leniency toward stray ``/`` in the body).
    """
    import base64

    text = uri.strip()
    prefix = "lxm://"
    if not text.lower().startswith(prefix):
        raise ValueError(f"not an lxm:// paper URI: {uri[:64]!r}")
    body = text[len(prefix):].replace("/", "")
    return base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))


def _wait_send(lxmessage, timeout: float) -> bool:
    """Poll an outbound message to a terminal state; True iff accepted.

    For PROPAGATED sends, ``SENT`` means the proprietor acknowledged the
    transfer (store-and-forward acceptance, not final delivery — the target
    pulls later). ``DELIVERED`` (direct sends) is likewise acceptance.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if lxmessage.state in _ACCEPTED_STATES:
            return True
        if lxmessage.state in _FAILED_STATES:
            return False
        time.sleep(0.05)
    return False


def run_lxmf_publish(
    payloads: List[bytes],
    target_hash: bytes,
    proprietor: Optional[bytes],
    router,
    delivery,
    *,
    direct: bool = False,
    chunk_budget: int = LXMF_CHUNK_BUDGET,
    timeout: float = DEFAULT_SEND_TIMEOUT,
    on_send=None,
) -> Tuple[List[bool], int]:
    """Send signed Deltas to one recipient via LXMF (§11.2, work doc #14).

    Testable core: takes an explicit ``router`` (with the node identity
    registered) and a :class:`~dacar.transport.lxmf_sync.LxmfDeltaDelivery`.
    PROPAGATED by default (store-and-forward: the proprietor queues for the
    offline target; ``proprietor`` must be its destination hash) — a blocking
    direct attempt against an offline node would defeat the one-shot model, so
    direct delivery is the explicit ``direct=True`` exception.

    Batches multiple Deltas into as few messages as ``chunk_budget`` allows
    (single-Delta sends keep the wire-compatible ``dacar/sync/delta`` title;
    batches use ``dacar/sync/batch``). Returns ``(per-Delta transport
    acceptance flags in original order, message count)``; the caller records
    accepted deltas in the sent box (work doc #11).
    """
    from dacar.transport.lxmf_sync import pack_chunks

    if not direct:
        if proprietor is None:
            raise ValueError(
                "no LXMF proprietor configured (use --proprietor <hash> or set "
                "[lxmf] proprietor in config) — or pass --direct for opportunistic "
                "direct delivery"
            )
        router.set_outbound_propagation_node(bytes(proprietor))
        desired_method = LXMF.LXMessage.PROPAGATED
    else:
        desired_method = LXMF.LXMessage.DIRECT

    destination = lxmf_out_destination(bytes(target_hash))
    source = _router_source_destination(router)

    accepted: List[bool] = []
    messages = 0
    if len(payloads) == 1:
        message = delivery.make_message(payloads[0], destination, source, desired_method)
        router.handle_outbound(message)
        messages = 1
        ok = _wait_send(message, timeout)
        if on_send is not None:
            on_send(message, ok)
        accepted = [ok]
    else:
        for chunk in pack_chunks(payloads, chunk_budget):
            message = delivery.deliver_batch(chunk, destination, source, desired_method)
            messages += 1
            ok = _wait_send(message, timeout)
            if on_send is not None:
                on_send(message, ok)
            accepted.extend([ok] * len(chunk))
    return accepted, messages


def _router_source_destination(router):
    """The router's own ``lxmf.delivery`` destination (message source).

    Falls back to ``router.delivery_destination`` for fakes that expose the
    single-destination attribute directly.
    """
    destinations = getattr(router, "delivery_destinations", None)
    if destinations:
        return next(iter(destinations.values()))
    return getattr(router, "delivery_destination", None)


def run_lxmf_sync(
    receiver,
    identity,
    proprietor: bytes,
    router,
    delivery,
    *,
    timeout: float = DEFAULT_SYNC_TIMEOUT,
    verbose: bool = False,
) -> int:
    """Pull pending LXMF messages from the proprietor and apply (§11.2.3).

    Testable core: registers the delivery callback (title filter → shared
    ``receiver`` with verify-on-ingest), asks the proprietor for pending
    messages, and polls ``propagation_transfer_state`` to completion. Returns
    the number of applied Dacar Deltas; the caller persists the CRDT if > 0.
    """
    applied = 0

    def _callback(message):
        nonlocal applied
        if delivery.handle_delivery(message):
            applied += 1

    router.register_delivery_callback(_callback)
    router.set_outbound_propagation_node(bytes(proprietor))
    router.request_messages_from_propagation_node(identity)

    deadline = time.time() + timeout
    while time.time() < deadline:
        state = getattr(router, "propagation_transfer_state", None)
        if state == LXMF.LXMRouter.PR_COMPLETE:
            break
        if state is not None and state >= _SYNC_FAILED_MIN:
            raise RuntimeError(
                f"proprietor sync failed (state {state:#x})"
            )
        time.sleep(0.05)

    return applied
