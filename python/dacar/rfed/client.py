"""rfed channel client — subscribe, publish, receive, and pull against a rfed
federation node.

Speaks the modern split rfed destinations (``RFed/SPEC.md`` §2), all sharing
the node's single identity:

  - ``rfed.channel.subscribe`` — ``/rfed/subscribe`` request (caches stamp cost)
  - ``rfed.channel.unsubscribe`` — ``/rfed/unsubscribe`` request
  - ``rfed.channel.publish``   — fire-and-forget DATA SEND (wrapped Phase-0 blob)
  - ``rfed.channel.pull``      — ``/rfed/pull`` paging (caller-identified)

Delivery arrives on the client's own inbound ``rfed.delivery`` destination as a
fanout payload ``[ channel_hash(16) ‖ inner_blob ]``, which is split and fed to
:func:`dacar.rfed.blob.unwrap_channel_message`.

This module is RNS-transport-dependent: it needs a running
:class:`RNS.Reticulum` (creating :class:`RNS.Destination` /
:class:`RNS.Link` requires an initialised transport). Construction itself is
offline-safe — destinations are created lazily inside each method. The pure
codec (:mod:`dacar.rfed.blob`, :mod:`dacar.rfed.channel`, :mod:`dacar.rfed.stamp`)
is testable without a running Reticulum.

Mirrors ``@reticulum/core``'s ``src/rfed/client.js``.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import msgpack
import RNS

from dacar.rfed.blob import (
    DecodedChannelMessage,
    parse_fanout_payload,
    wrap_channel_message,
)
from dacar.rfed.channel import delivery_hash_for, derive_channel
from dacar.rfed.constants import (
    CHANNEL_PUBLISH_NAME,
    CHANNEL_PULL_NAME,
    CHANNEL_SUBSCRIBE_NAME,
    CHANNEL_UNSUBSCRIBE_NAME,
    DELIVERY_NAME,
    PULL_PATH,
    SUBSCRIBE_PATH,
    UNSUBSCRIBE_PATH,
)

__all__ = [
    "RFedClient",
    "SubscribeResult",
    "PullPage",
    "PullItem",
    "DEFAULT_REQUEST_TIMEOUT",
    "DEFAULT_ESTABLISH_TIMEOUT",
]

#: Default request round-trip timeout in seconds.
DEFAULT_REQUEST_TIMEOUT = 15.0
#: Default link establishment timeout in seconds.
DEFAULT_ESTABLISH_TIMEOUT = 15.0


class SubscribeResult:
    """A ``/rfed/subscribe`` (or unsubscribe) response."""

    __slots__ = ("ok", "stamp_cost")

    def __init__(self, ok: bool, stamp_cost: Optional[int] = None) -> None:
        self.ok = ok
        self.stamp_cost = stamp_cost

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"SubscribeResult(ok={self.ok}, stamp_cost={self.stamp_cost})"


class PullItem:
    """One deferred-queue blob entry."""

    __slots__ = ("channel_hash", "blob")

    def __init__(self, channel_hash: bytes, blob: bytes) -> None:
        self.channel_hash = bytes(channel_hash)
        self.blob = bytes(blob)


class PullPage:
    """One page of a ``/rfed/pull`` response."""

    __slots__ = ("items", "more_pending")

    def __init__(self, items: List[PullItem], more_pending: bool) -> None:
        self.items = items
        self.more_pending = more_pending


def _split_name(name: str) -> Tuple[str, Tuple[str, ...]]:
    """Split a dotted destination name into (app_name, aspects)."""
    parts = name.split(".")
    if len(parts) < 2:
        raise ValueError(f"invalid rfed destination name: {name!r}")
    return parts[0], tuple(parts[1:])


def _hex(b: bytes) -> str:
    return bytes(b).hex()


def _signed_channel_payload(
    identity: RNS.Identity, channel_hash: bytes
) -> bytes:
    """Build the msgpack ``[channel_hash, pubkey, sig]`` subscribe payload.

    Signs the channel hash with the subscriber identity. Matches the Rust
    ``verify_signed_payload`` contract.
    """
    pubkey = identity.get_public_key()
    sig = identity.sign(bytes(channel_hash))
    return msgpack.packb([bytes(channel_hash), pubkey, sig], use_bin_type=True)


def _decode_subscribe_response(response: Any) -> SubscribeResult:
    """Decode a ``/rfed/subscribe`` response into :class:`SubscribeResult`.

    Wire form is ``msgpack [bool ok, uint stamp_cost | nil]``; ``0`` and ``nil``
    both mean stamping is disabled. Legacy nodes reply with a bare boolean.
    """
    if isinstance(response, (list, tuple)):
        ok = response[0] is True if response else False
        stamp_cost = response[1] if len(response) > 1 else None
        return SubscribeResult(ok, stamp_cost if stamp_cost else None)
    return SubscribeResult(response is True, None)


class RFedClient:
    """A rfed channel client.

    Parameters
    ----------
    identity:
        The subscriber's Identity; owns the ``rfed.delivery`` destination that
        receives fanout.
    rns:
        The Reticulum instance used as the destinations' interface layer (its
        transport routes packets). A running :class:`RNS.Reticulum` is assumed
        for all network operations.
    """

    def __init__(self, identity: RNS.Identity, rns: Any) -> None:
        self.identity = identity
        self.rns = rns
        #: Cached channel derivations: channel name → derivation entry.
        self.channels: Dict[str, Dict[str, Any]] = {}
        #: Cached advertised stamp costs: hex(channelHash) → cost (or None).
        self.stamp_costs: Dict[str, Optional[int]] = {}
        #: The inbound ``rfed.delivery`` destination, once :meth:`listen` is called.
        self.delivery_dest: Optional[RNS.Destination] = None
        #: Callback invoked for each decoded fanout message.
        self.on_message: Optional[Callable[[DecodedChannelMessage], None]] = None

    # -- channel cache -----------------------------------------------------

    def _channel(self, name: str) -> Dict[str, Any]:
        """Resolve (and cache) a channel's derived identity and hashes."""
        cached = self.channels.get(name)
        if cached:
            return cached
        identity, channel_hash = derive_channel(name)
        entry = {
            "identity": identity,
            "channel_hash": channel_hash,
            "delivery_hash": delivery_hash_for(identity),
        }
        self.channels[name] = entry
        return entry

    def _channel_by_hash(self, channel_hash: bytes) -> Optional[Dict[str, Any]]:
        """Look up a cached channel derivation by its channel hash."""
        needle = _hex(channel_hash)
        for name, entry in self.channels.items():
            if _hex(entry["channel_hash"]) == needle:
                return {**entry, "name": name}
        return None

    def _node_identity(self, node_hash: bytes) -> RNS.Identity:
        """Recall the node's shared identity from any of its destination hashes."""
        identity = RNS.Identity.recall(bytes(node_hash))
        if identity is None:
            raise ValueError(
                f"rfed node identity unknown for {_hex(node_hash)}; "
                "wait for its announce"
            )
        return identity

    def _out_destination(self, name: str, node_identity: RNS.Identity) -> RNS.Destination:
        app, aspects = _split_name(name)
        return RNS.Destination(node_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, app, *aspects)

    # -- RNS link/request helpers (blocking) -------------------------------

    def _establish_link(
        self, destination: RNS.Destination, *, timeout: float = DEFAULT_ESTABLISH_TIMEOUT
    ) -> RNS.Link:
        """Open an RNS Link to ``destination`` and block until ACTIVE."""
        ready = threading.Event()
        result: Dict[str, Any] = {}

        def on_established(link: RNS.Link) -> None:
            result["link"] = link
            ready.set()

        link = RNS.Link(destination, established_callback=on_established)
        if not ready.wait(timeout) or result.get("link") is None:
            raise TimeoutError(f"rfed link to {_hex(destination.hash)} not established")
        return result["link"]

    def _request(
        self,
        link: RNS.Link,
        path: str,
        data: bytes,
        *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        grace: float = 2.0,
    ) -> Any:
        """Send an RNS request on an established link and block for the response.

        Returns the response data, or ``None`` on failure/timeout.
        """
        if getattr(link, "status", None) != RNS.Link.ACTIVE:
            return None
        box: Dict[str, Any] = {}
        done = threading.Event()

        def on_response(receipt: Any) -> None:
            box["response"] = getattr(receipt, "response", None)
            done.set()

        def on_failed(receipt: Any) -> None:
            done.set()

        sent = link.request(
            path,
            data,
            response_callback=on_response,
            failed_callback=on_failed,
            timeout=timeout,
        )
        if sent is False:
            return None
        if not done.wait(timeout + grace):
            return None
        return box.get("response")

    # -- subscribe / unsubscribe -------------------------------------------

    def subscribe(
        self,
        node_hash: bytes,
        channel_name: str,
        *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> SubscribeResult:
        """Subscribe to a channel on a node and cache the advertised PoW stamp cost.

        Opens a link to the node's ``rfed.channel.subscribe`` destination,
        identifies as the subscriber, and sends ``/rfed/subscribe`` with the
        signed channel hash. Re-subscribing refreshes the cached stamp cost —
        do this at least once per session and after any publish rejection.
        """
        channel = self._channel(channel_name)
        node_identity = self._node_identity(node_hash)
        payload = _signed_channel_payload(self.identity, channel["channel_hash"])

        dest = self._out_destination(CHANNEL_SUBSCRIBE_NAME, node_identity)
        link = self._establish_link(dest)
        link.identify(self.identity)
        # RNS already msgpack-unpacks the request response into a Python object
        # (see RequestReceipt.response_received), so decode it directly — do not
        # double-unpack with msgpack.unpackb, which would raise on a list.
        raw = self._request(link, SUBSCRIBE_PATH, payload, timeout=timeout)
        decoded = _decode_subscribe_response(raw if raw is not None else False)
        if decoded.ok:
            self.stamp_costs[_hex(channel["channel_hash"])] = decoded.stamp_cost
        return decoded

    def unsubscribe(
        self,
        node_hash: bytes,
        channel_name: str,
        *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> SubscribeResult:
        """Remove a subscription. Same payload shape as :meth:`subscribe`."""
        channel = self._channel(channel_name)
        node_identity = self._node_identity(node_hash)
        payload = _signed_channel_payload(self.identity, channel["channel_hash"])

        dest = self._out_destination(CHANNEL_UNSUBSCRIBE_NAME, node_identity)
        link = self._establish_link(dest)
        link.identify(self.identity)
        # RNS already msgpack-unpacks the request response into a Python object;
        # decode it directly (mirrors the JS reference's link.request usage).
        raw = self._request(link, UNSUBSCRIBE_PATH, payload, timeout=timeout)
        decoded = _decode_subscribe_response(raw if raw is not None else False)
        return SubscribeResult(ok=decoded.ok)

    # -- publish -----------------------------------------------------------

    def publish(
        self, node_hash: bytes, channel_name: str, lxm_message: Any
    ) -> None:
        """Publish a message to a channel (fire-and-forget SEND).

        Wraps the LXMF message with the Phase-0 codec using the cached stamp
        cost (from the last :meth:`subscribe`) and sends it as an encrypted DATA
        packet to the node's ``rfed.channel.publish`` destination. If no stamp
        cost is cached, the message is sent without a stamp.

        SEND is fire-and-forget — there is no acceptance response. Call
        :meth:`subscribe` again to refresh the stamp cost if publishes seem
        dropped (the node silently rejects under-stamped blobs).
        """
        channel = self._channel(channel_name)
        node_identity = self._node_identity(node_hash)
        sender_delivery_hash = delivery_hash_for(self.identity)

        stamp_cost = self.stamp_costs.get(_hex(channel["channel_hash"]))
        wrapped = wrap_channel_message(
            channel_identity=channel["identity"],
            sender_identity=self.identity,
            sender_lxm_delivery_hash=sender_delivery_hash,
            lxm_message=lxm_message,
            stamp_cost=stamp_cost,
        )

        dest = self._out_destination(CHANNEL_PUBLISH_NAME, node_identity)
        packet = RNS.Packet(dest, wrapped.rfed_payload)
        packet.send()

    # -- pull --------------------------------------------------------------

    def pull(
        self,
        node_hash: bytes,
        channel_name: str,
        *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> PullPage:
        """Pull one page of pending blobs for a channel (user-initiated paging).

        Opens an identified link to ``rfed.channel.pull`` and sends
        ``/rfed/pull`` with the channel hash. The response is
        ``[[[channel_hash, blob], …], more_pending]``; repeat while
        ``more_pending`` is ``True`` to drain the queue.
        """
        channel = self._channel(channel_name)
        node_identity = self._node_identity(node_hash)

        dest = self._out_destination(CHANNEL_PULL_NAME, node_identity)
        link = self._establish_link(dest)
        link.identify(self.identity)
        # RNS already msgpack-unpacks the request response into a Python object;
        # ``raw`` is the decoded ``[[[channel_hash, blob], ...], more_pending]``
        # structure (or None on failure), not raw bytes.
        raw = self._request(link, PULL_PATH, bytes(channel["channel_hash"]), timeout=timeout)
        if not isinstance(raw, (list, tuple)) or len(raw) < 2:
            return PullPage([], False)
        pairs = raw[0]
        more_pending = raw[1] is True
        items = [
            PullItem(channel_hash=pair[0], blob=pair[1])
            for pair in (pairs if isinstance(pairs, (list, tuple)) else [])
        ]
        return PullPage(items=items, more_pending=more_pending)

    # -- listen (inbound fanout) -------------------------------------------

    def listen(
        self, on_message: Callable[[DecodedChannelMessage], None]
    ) -> bytes:
        """Start listening for live fanout deliveries on ``rfed.delivery``.

        Creates and announces the inbound ``rfed.delivery`` destination. Each
        incoming fanout payload ``[ channel_hash ‖ inner_blob ]`` is matched to a
        subscribed channel, EC-decrypted, and passed to ``on_message`` along with
        the verified LXMF message. Returns the ``rfed.delivery`` destination hash.
        """
        self.on_message = on_message
        if self.delivery_dest is None:
            dest = RNS.Destination(
                self.identity,
                RNS.Destination.IN,
                RNS.Destination.SINGLE,
                *_split_name(DELIVERY_NAME),
            )
            dest.set_packet_callback(self._handle_delivery)
            self.delivery_dest = dest
        self.delivery_dest.announce()
        return self.delivery_dest.hash

    def _handle_delivery(self, data: bytes, packet: Any) -> None:
        """Split and decode a fanout delivery plaintext.

        A foreign/unparsable fanout packet is dropped, not fatal.
        """
        try:
            channel_hash, inner_blob = parse_fanout_payload(bytes(data))
            channel = self._channel_by_hash(channel_hash)
            if channel is None:
                return  # not subscribed to this channel
            decoded = unwrap_channel_message(
                inner_blob=inner_blob,
                channel_identity=channel["identity"],
                channel_delivery_hash=channel["delivery_hash"],
            )
            if self.on_message:
                self.on_message(decoded)
        except Exception:
            # A foreign/unparsable fanout packet is dropped, not fatal.
            pass
