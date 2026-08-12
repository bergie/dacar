"""§11.1 eventual consistency via RFed (Reticulum Federation).

Global convergence of the CRDT is handled by RFed's many-to-many broadcast:
each node publishes its signed Operations (§5.3 Deltas) to a shared channel
(default ``dacar.policy.v1``, deployment-overridable), and receives peers'
Deltas via RFed fanout. Because every Delta is individually Ed25519-signed,
RFed need not be trusted: received bytes flow through the *same* verify-on-
ingest seam (:meth:`DeltaReceiver.apply_payload`, §11.2) as LXMF and optical
delivery — **never** through the unauthenticated :meth:`StateVector.merge`
path. A forged or stale Delta is simply dropped before it can mutate state.

:class:`RfedDeltaSync` wraps a :class:`dacar.rfed.client.RFedClient`. A Delta
travels in Dacar's **compact inner format** (§11.1): the raw §5.3 payload is
placed straight after the RTID source-identity prelude and EC-encrypted to the
derived channel identity — no LXMF envelope, which would only duplicate the
Delta's own destination/source/signature/timestamp and push a typical 170-byte
Delta past the 500-byte RNS MTU. On receipt the channel is the feed
discriminator (every message on it is a Dacar Delta), and the recovered Delta
bytes are fed to the :class:`DeltaReceiver`.

§11.2 targeted delivery and §11.3 air-gapped/optical transport still use full
LXMF framing (:mod:`dacar.transport.lxmf_sync`, Paper Messages); only the RFed
broadcast channel uses the compact format.

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

from typing import Any, Optional

from dacar.delta import DeltaReceiver
from dacar.naming import RFED_TOPIC
from dacar.rfed.blob import unwrap_dacar_delta, wrap_dacar_delta
from dacar.rfed.channel import derive_channel

__all__ = ["RfedDeltaSync"]


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

    def make_payload(self, delta_payload: bytes) -> bytes:
        """Wrap one §5.3 Delta payload in the Dacar compact inner format.

        Returns the full ``rfed_payload``
        (``channel_hash ‖ inner_blob ‖ stamp``), EC-encrypted to the derived
        channel identity and stamped with the cost cached from the last
        :meth:`subscribe`. The caller sends it via ``client.send_publish``.
        """
        if not isinstance(delta_payload, (bytes, bytearray)):
            raise TypeError("delta_payload must be bytes")
        channel = self._client.channel(self._topic)
        wrapped = wrap_dacar_delta(
            channel_identity=channel["identity"],
            sender_identity=self._client.identity,
            delta=bytes(delta_payload),
            stamp_cost=self._client.stamp_cost(self._topic),
        )
        return wrapped.rfed_payload

    def subscribe(self, node_hash: bytes) -> Any:
        """Subscribe to the channel on a node, caching its advertised stamp cost.

        Call at least once per session and after any publish seems dropped.
        """
        return self._client.subscribe(node_hash, self._topic)

    def unsubscribe(self, node_hash: bytes) -> Any:
        """Remove the subscription."""
        return self._client.unsubscribe(node_hash, self._topic)

    def publish(self, delta_payload: bytes, node_hash: bytes) -> bool:
        """Publish a Delta to the channel (fire-and-forget, §11.1).

        Wraps the Delta in the Dacar compact inner format and sends it as a
        fire-and-forget DATA packet via :meth:`RFedClient.send_publish`. Call
        :meth:`subscribe` first so the channel's stamp cost is cached; an
        unstamped publish may be silently dropped by a cost-enforcing node.
        Returns ``True`` if the transport accepted the outbound packet,
        ``False`` otherwise (fire-and-forget: transport acceptance ≠ node
        storage). Returns the wrapped ``rfed_payload``.
        """
        rfed_payload = self.make_payload(delta_payload)
        return self._client.send_publish(node_hash, rfed_payload)

    # -- §11.1 receive (live fanout) ---------------------------------------

    def listen(self) -> bytes:
        """Start listening for live fanout Deltas and route each through
        verify-on-ingest (§11.1, §11.2).

        Each delivered ``inner_blob`` is EC-decrypted with the derived channel
        identity and the recovered Delta is fed to
        :meth:`DeltaReceiver.apply_payload`, which authenticates it by
        signature and swallows any malformed/forged payload so a bad message
        can never crash the transport or mutate state.

        Returns the local ``rfed.delivery`` destination hash.
        """
        if self._receiver is None:
            raise RuntimeError("RfedDeltaSync.listen requires a receiver")
        receiver = self._receiver

        def on_fanout(channel_name: str, channel_identity: Any, inner_blob: bytes) -> None:
            try:
                decoded = unwrap_dacar_delta(
                    inner_blob=inner_blob, channel_identity=channel_identity
                )
                receiver.apply_payload(decoded.delta)
            except Exception:
                # A malformed/forged fanout payload is dropped, not fatal —
                # matches DeltaReceiver.apply_payload's own swallow contract.
                pass

        return self._client.listen_raw(on_fanout)

    # -- §11.1 receive (offline catch-up via deferred-queue pull) ----------

    def pull(self, node_hash: bytes) -> int:
        """Drain the node's deferred queue (offline catch-up) and route each
        blob through verify-on-ingest (§11.1).

        Each blob is EC-decrypted with the derived channel identity and the
        recovered Dacar Delta is applied. Foreign/undecryptable blobs are
        dropped, not fatal. Repeats until the node reports no more pending
        pages. Returns the count of Deltas newly applied to the CRDT.
        """
        if self._receiver is None:
            raise RuntimeError("RfedDeltaSync.pull requires a receiver")
        channel_identity, _channel_hash = derive_channel(self._topic)
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
                    decoded = unwrap_dacar_delta(
                        inner_blob=blob, channel_identity=channel_identity
                    )
                    if receiver.apply_payload(decoded.delta):
                        applied += 1
                except Exception:
                    # a foreign/undecryptable blob is dropped, never fatal
                    pass
            more_pending = bool(getattr(page, "more_pending", False))
        return applied
