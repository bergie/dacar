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

import RNS

from dacar.rfed.blob import (
    DecodedChannelMessage,
    parse_fanout_payload,
    unwrap_channel_message,
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
#: Default path-request wait timeout in seconds. Mirrors rngit's ``PATH_TIMEOUT``
#: and ``@reticulum/core``'s ``PATH_REQUEST_WAIT_MS`` (7 s): long enough for a
#: path-response announce to traverse a few hops, short enough that a one-shot
#: CLI isn't stuck when no node is reachable.
DEFAULT_PATH_TIMEOUT = 15.0


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
) -> list:
    """Build the ``[channel_hash, pubkey, sig]`` subscribe payload.

    Signs the channel hash with the subscriber identity. Matches the Rust
    ``verify_signed_payload`` contract and ``@reticulum/core``'s JS
    ``signedChannelPayload``.

    Returns the **list** (not pre-packed bytes): RNS's ``Link.request`` msgpack-
    encodes its ``data`` argument as part of the outer ``[time, path_hash, data]``
    request envelope, so a pre-packed ``bytes`` payload would arrive at the node
    as an opaque ``bin`` blob — failing the node's ``Array.isArray(data)`` check
    in ``_verifySignedPayload`` and silently yielding ``[false, null]`` (no
    subscription created). Returning the list lets RNS embed it as a nested
    array, which the node unpacks and verifies.
    """
    pubkey = identity.get_public_key()
    sig = identity.sign(bytes(channel_hash))
    return [bytes(channel_hash), pubkey, sig]


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
        #: Callback invoked for each decoded fanout message (LXMF path).
        self.on_message: Optional[Callable[[DecodedChannelMessage], None]] = None
        #: Callback invoked for each raw fanout delivery (compact inner format
        #: path); receives ``(channel_name, channel_identity, inner_blob)``.
        self.on_fanout: Optional[Callable[[str, RNS.Identity, bytes], None]] = None
        #: The active delivery dispatcher (set by :meth:`listen` / :meth:`listen_raw`).
        self._dispatch: Optional[Callable[[Dict[str, Any], bytes], None]] = None

    # -- channel cache -----------------------------------------------------

    def channel(self, name: str) -> Dict[str, Any]:
        """A channel's derived identity, channel hash, and delivery hash.

        Public, cached view of :meth:`_channel` for callers that build their
        own ``inner_blob`` (e.g. Dacar's compact Delta format, §11.1) and send it
        via :meth:`send_publish`. The returned dict holds ``identity`` (the
        derived channel :class:`RNS.Identity`), ``channel_hash`` (16 bytes),
        and ``delivery_hash`` (the channel's ``lxmf.delivery`` hash).
        """
        return self._channel(name)

    def stamp_cost(self, name: str) -> Optional[int]:
        """The cached PoW stamp cost advertised by the node for ``name``.

        ``None`` means stamping is disabled (or :meth:`subscribe` has not yet
        been called for the channel this session).
        """
        entry = self._channel(name)
        return self.stamp_costs.get(_hex(entry["channel_hash"]))

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

    def _ensure_path(
        self, destination_hash: bytes, *, timeout: float = DEFAULT_PATH_TIMEOUT
    ) -> None:
        """Ensure a transport path to ``destination_hash`` before linking/sending.

        RNS's :class:`RNS.Link` does **not** automatically request a path when
        none is known (unlike ``@reticulum/core``'s JS ``Link``): a
        ``LINKREQUEST`` addressed to a destination with no route is broadcast
        and silently dropped by multi-hop peers, so the link times out. This
        mirrors rngit's ``connect_server`` (``RNS.Transport.await_path``) and
        the JS reference's ``_requestAndAwaitPath``: send a ``path?`` request
        for the *specific* derived channel destination and wait for the node's
        path-response announce to populate the path table.

        No-op when a path is already known (the destination announced recently).
        Raises :class:`TimeoutError` if none is found within ``timeout`` — a
        clearer error than the subsequent link-establishment timeout, and the
        same wording rngit uses. The rfed node announces every ``rfed.*``
        destination under one shared identity, so a path request for any of
        them is answered with that destination's path-response announce.
        """
        if not RNS.Transport.await_path(bytes(destination_hash), timeout=timeout):
            raise TimeoutError(
                f"no path to {_hex(destination_hash)} could be resolved "
                f"within {timeout:.0f}s (is the rfed node announcing and reachable?)"
            )

    def _establish_link(
        self, destination: RNS.Destination, *, timeout: float = DEFAULT_ESTABLISH_TIMEOUT
    ) -> RNS.Link:
        """Open an RNS Link to ``destination`` and block until ACTIVE."""
        self._ensure_path(destination.hash)
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
        """Publish an LXMF message to a channel (fire-and-forget SEND).

        Wraps the LXMF message with the Phase-0 codec using the cached stamp
        cost (from the last :meth:`subscribe`) and sends it as an encrypted DATA
        packet to the node's ``rfed.channel.publish`` destination. If no stamp
        cost is cached, the message is sent without a stamp.

        SEND is fire-and-forget — there is no acceptance response. Call
        :meth:`subscribe` again to refresh the stamp cost if publishes seem
        dropped (the node silently rejects under-stamped blobs). The publish
        destination does NOT accept link requests, so the payload must fit
        within the RNS MTU (default 500 bytes). For application-specific inner
        formats that skip the LXMF envelope (e.g. Dacar's compact Delta
        format, §11.1), build the ``rfed_payload`` yourself and send it via
        :meth:`send_publish`.
        """
        channel = self._channel(channel_name)
        sender_delivery_hash = delivery_hash_for(self.identity)

        stamp_cost = self.stamp_costs.get(_hex(channel["channel_hash"]))
        wrapped = wrap_channel_message(
            channel_identity=channel["identity"],
            sender_identity=self.identity,
            sender_lxm_delivery_hash=sender_delivery_hash,
            lxm_message=lxm_message,
            stamp_cost=stamp_cost,
        )
        self.send_publish(node_hash, wrapped.rfed_payload)

    def send_publish(self, node_hash: bytes, rfed_payload: bytes) -> bool:
        """Fire-and-forget SEND of a pre-wrapped ``rfed_payload``.

        The general publish primitive, independent of the inner format:
        ``rfed_payload`` must already be fully wrapped
        (``channel_hash ‖ inner_blob ‖ stamp``) and fit within the RNS MTU.
        Use this for application-specific inner formats that don't use the LXMF
        message envelope (e.g. Dacar's compact Delta format, §11.1) — build
        the payload with the channel codec (e.g.
        :func:`dacar.rfed.blob.wrap_dacar_delta`) and send it here.

        SEND is fire-and-forget — there is no acceptance response, and the
        ``rfed.channel.publish`` destination does NOT accept link requests
        (per the Rust reference implementation), so oversized payloads are
        silently dropped (RNS raises ``IOError`` if the *packet* exceeds the
        MTU, but a within-MTU packet may still be dropped by the node, e.g. an
        under-stamped blob). Returns ``True`` if the transport accepted the
        outbound packet (a path was known and an interface could process it),
        ``False`` otherwise — this is transport acceptance, **not** confirmation
        that the node stored the blob.
        """
        node_identity = self._node_identity(node_hash)
        dest = self._out_destination(CHANNEL_PUBLISH_NAME, node_identity)
        # Ensure path to destination before sending. The publish destination
        # accepts DATA packets but does NOT accept link requests, so payloads
        # must be <= RNS MTU.
        self._ensure_path(dest.hash)
        receipt = RNS.Packet(dest, bytes(rfed_payload)).send()
        return receipt is not False

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
        subscribed channel, EC-decrypted, LXMF-decoded, and passed to
        ``on_message`` along with the verified LXMF message. Returns the
        ``rfed.delivery`` destination hash.

        For application-specific inner formats that don't use the LXMF
        envelope (e.g. Dacar's compact Delta format, §11.1), use
        :meth:`listen_raw` instead.
        """
        self.on_message = on_message
        self.on_fanout = None
        self._dispatch = self._dispatch_lxmf
        return self._start_delivery()

    def listen_raw(
        self, on_fanout: Callable[[str, RNS.Identity, bytes], None]
    ) -> bytes:
        """Start listening for raw fanout deliveries (no LXMF decode).

        Like :meth:`listen`, but the ``inner_blob`` is handed to ``on_fanout``
        **undecoded** — ``on_fanout(channel_name, channel_identity, inner_blob)``
        performs the application-specific decrypt/decode (e.g.
        :func:`dacar.rfed.blob.unwrap_dacar_delta` for Dacar Deltas, §11.1).
        Use this when the channel carries a non-LXMF inner format. Returns the
        ``rfed.delivery`` destination hash.
        """
        self.on_fanout = on_fanout
        self.on_message = None
        self._dispatch = self._dispatch_raw
        return self._start_delivery()

    def _start_delivery(self) -> bytes:
        """Create/announce the inbound ``rfed.delivery`` destination once."""
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

    def _dispatch_lxmf(self, channel: Dict[str, Any], inner_blob: bytes) -> None:
        decoded = unwrap_channel_message(
            inner_blob=inner_blob,
            channel_identity=channel["identity"],
            channel_delivery_hash=channel["delivery_hash"],
        )
        if self.on_message:
            self.on_message(decoded)

    def _dispatch_raw(self, channel: Dict[str, Any], inner_blob: bytes) -> None:
        if self.on_fanout:
            self.on_fanout(channel["name"], channel["identity"], inner_blob)

    def _handle_delivery(self, data: bytes, packet: Any) -> None:
        """Split a fanout delivery plaintext and dispatch it.

        A foreign/unparsable fanout packet is dropped, not fatal.
        """
        try:
            channel_hash, inner_blob = parse_fanout_payload(bytes(data))
            channel = self._channel_by_hash(channel_hash)
            if channel is None:
                return  # not subscribed to this channel
            dispatch = self._dispatch
            if dispatch is not None:
                dispatch(channel, inner_blob)
        except Exception:
            # A foreign/unparsable fanout packet is dropped, not fatal.
            pass
