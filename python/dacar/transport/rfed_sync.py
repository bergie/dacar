"""§11.1 eventual consistency via RFed (Reticulum Federation).

Global convergence of the CRDT is handled by RFed's many-to-many broadcast:
each node publishes its signed Operations (§5.3 Deltas) to a shared channel
(default ``dacar.policy.v1``, deployment-overridable), and receives peers'
Deltas via RFed fanout. Because every Delta is individually Ed25519-signed,
RFed need not be trusted: received bytes flow through the *same* verify-on-
ingest seam (:meth:`DeltaReceiver.apply_payload`, §11.2.4) as LXMF and optical
delivery — **never** through the unauthenticated :meth:`StateVector.merge`
path. A forged or stale Delta is simply dropped before it can mutate state.

:class:`RfedDeltaSync` wraps a :class:`dacar.rfed.client.RFedClient`. A Delta
is wrapped as the LXMF *content* of a channel message under the fixed
``dacar/sync/delta`` title; on receipt the channel is the feed discriminator
(every message on it is a Dacar Delta), and the content bytes are fed to the
:class:`DeltaReceiver`.

§11.3 air-gapped/optical transport is served by :mod:`dacar.transport.lxmf_sync`
(Paper Messages); RFed is the online many-to-many path.

This module is part of the optional transport layer: importing the pure core
never pulls it in. It depends only on ``rns`` + ``msgpack`` (both already
declared), so — unlike the LXMF adapters — it needs no extra beyond the
``transport`` extra's ``rns`` base. It mirrors
``javascript/src/transport/rfedSync.js``.

Typical use::

    client = RFedClient(identity=me, rns=rns)
    sync = RfedDeltaSync(receiver=DeltaReceiver(state, resolver), client=client)
    sync.subscribe(node_hash)        # cache the channel's stamp cost
    sync.listen()                    # receive live fanout Deltas (callback)
    sync.publish(delta_payload, node_hash)
    sync.pull(node_hash)             # drain the deferred queue (offline catch-up)
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

from dacar.delta import DeltaReceiver
from dacar.naming import LXMF_DELIVERY_TITLE, RFED_TOPIC
from dacar.rfed._lxmf import LxmfMessage
from dacar.rfed.blob import unwrap_channel_message
from dacar.rfed.channel import delivery_hash_for, derive_channel

__all__ = ["RfedDeltaSync", "message_content"]


def message_content(message: Any) -> bytes:
    """Best-effort content of an rfed-decoded LXMF message as bytes (the Delta).

    The :class:`dacar.rfed._lxmf.LxmfMessage` codec keeps ``content`` as raw
    bytes (no UTF-8 corruption), so this is the faithful recovery of what a
    peer sent as ``content=<delta bytes>``. Tolerates a ``str`` content for
    symmetry with the LXMF adapter. Mirrors ``messageContent`` in
    ``javascript/src/transport/lxmfSync.js``.
    """
    c = getattr(message, "content", b"")
    if isinstance(c, str):
        return c.encode("utf-8")
    if isinstance(c, (bytes, bytearray)):
        return bytes(c)
    return b""


class RfedDeltaSync:
    """§11.1 RFed Delta broadcast + receive, routed through verify-on-ingest.

    Mirrors ``RfedDeltaSync`` in ``javascript/src/transport/rfedSync.js``. The
    ``client`` is the minimal :class:`~dacar.rfed.client.RFedClient` surface
    this adapter relies on; tests may inject a fake.

    Parameters
    ----------
    receiver:
        The shared :class:`DeltaReceiver` (state + key resolver). May be
        ``None`` on a publish-only node (then :meth:`listen`/:meth:`pull`
        raise if called).
    client:
        A :class:`~dacar.rfed.client.RFedClient` (or compatible fake). Required.
    topic:
        RFed channel name (default :data:`~dacar.naming.RFED_TOPIC`).
    """

    #: Default RFed channel (deployment-overridable, spec §11.1).
    DEFAULT_TOPIC = RFED_TOPIC

    def __init__(
        self,
        *,
        receiver: Optional[DeltaReceiver] = None,
        client: Any,
        topic: str = RFED_TOPIC,
    ) -> None:
        if client is None:
            raise TypeError("RfedDeltaSync requires an RFedClient")
        self._receiver: Optional[DeltaReceiver] = receiver
        self._client = client
        self._topic = topic

    @property
    def topic(self) -> str:
        """The configured RFed channel name."""
        return self._topic

    # -- §11.1 publish -----------------------------------------------------

    def make_message(self, delta_payload: bytes) -> LxmfMessage:
        """Build the LXMF channel message wrapping one §5.3 Delta payload.

        The message's ``destination_hash``/``source_hash`` are placeholders: the
        rfed Phase-0 codec (:func:`dacar.rfed.blob.wrap_channel_message`)
        overwrites them with the channel's ``lxmf.delivery`` hashes before
        serialization, so the classic "source_hash is the bare identity hash"
        bug cannot occur.
        """
        if not isinstance(delta_payload, (bytes, bytearray)):
            raise TypeError("delta_payload must be bytes")
        return LxmfMessage(
            destination_hash=b"\x00" * 16,
            source_hash=b"\x00" * 16,
            content=bytes(delta_payload),
            title=LXMF_DELIVERY_TITLE,
        )

    def subscribe(self, node_hash: bytes) -> Any:
        """Subscribe to the channel on a node, caching its advertised stamp cost.

        Call at least once per session and after any publish seems dropped.
        """
        return self._client.subscribe(node_hash, self._topic)

    def unsubscribe(self, node_hash: bytes) -> Any:
        """Remove the subscription."""
        return self._client.unsubscribe(node_hash, self._topic)

    def publish(self, delta_payload: bytes, node_hash: bytes) -> LxmfMessage:
        """Publish a Delta to the channel (fire-and-forget, §11.1).

        Call :meth:`subscribe` first so the channel's stamp cost is cached; an
        unstamped publish may be silently dropped by a cost-enforcing node.
        """
        message = self.make_message(delta_payload)
        self._client.publish(node_hash, self._topic, message)
        return message

    # -- §11.1 receive (live fanout) ---------------------------------------

    def listen(self) -> bytes:
        """Start listening for live fanout Deltas and route each through
        verify-on-ingest (§11.1, §11.2.4).

        The channel is the feed discriminator, so every received message is a
        Dacar Delta; :meth:`DeltaReceiver.apply_payload` authenticates it by
        signature and swallows any malformed/forged payload so a bad message
        can never crash the transport or mutate state.

        Returns the local ``rfed.delivery`` destination hash.
        """
        if self._receiver is None:
            raise RuntimeError("RfedDeltaSync.listen requires a receiver")
        receiver = self._receiver

        def on_message(decoded: Any) -> None:
            try:
                receiver.apply_payload(message_content(decoded.message))
            except Exception:
                # A malformed/forged fanout payload is dropped, not fatal —
                # matches DeltaReceiver.apply_payload's own swallow contract.
                pass

        return self._client.listen(on_message)

    # -- §11.1 receive (offline catch-up via deferred-queue pull) ----------

    def pull(self, node_hash: bytes) -> int:
        """Drain the node's deferred queue (offline catch-up) and route each
        blob through verify-on-ingest (§11.1).

        Each blob is EC-decrypted with the derived channel identity and the
        recovered LXMF message's content is applied. Foreign/undecryptable
        blobs are dropped, not fatal. Repeats until the node reports no more
        pending pages. Returns the count of Deltas newly applied to the CRDT.
        """
        if self._receiver is None:
            raise RuntimeError("RfedDeltaSync.pull requires a receiver")
        channel_identity, _channel_hash = derive_channel(self._topic)
        channel_delivery_hash = delivery_hash_for(channel_identity)
        receiver = self._receiver
        applied = 0
        more_pending = True
        while more_pending:
            page = self._client.pull(node_hash, self._topic)
            for item in getattr(page, "items", ()):  # PullItem / dict-like
                blob = getattr(item, "blob", None)
                if blob is None and isinstance(item, dict):
                    blob = item.get("blob")
                if blob is None:
                    continue
                try:
                    decoded = unwrap_channel_message(
                        inner_blob=blob,
                        channel_identity=channel_identity,
                        channel_delivery_hash=channel_delivery_hash,
                    )
                    if receiver.apply_payload(message_content(decoded.message)):
                        applied += 1
                except Exception:
                    # a foreign/undecryptable blob is dropped, never fatal
                    pass
            more_pending = bool(getattr(page, "more_pending", False))
        return applied

    # -- convenience: build a batch payload from signed ops -----------------

    @staticmethod
    def pack_payloads(operation_payloads: Tuple[bytes, ...]) -> bytes:
        """Encode signed §5.3 Operation payloads as an authenticated batch.

        Thin alias for :meth:`DeltaReceiver.pack_payloads` so a publisher need
        not import the receiver just to batch. The inverse (authenticated
        application) is :meth:`DeltaReceiver.apply_payloads`.
        """
        return DeltaReceiver.pack_payloads(list(operation_payloads))
