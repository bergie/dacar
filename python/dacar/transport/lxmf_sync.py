"""§11.2 targeted Delta delivery + §11.3 Paper Messages over LXMF.

LXMF gives Dacar forward-secret, store-and-forward, point-to-point delivery of
Deltas to (possibly offline) nodes, alongside the public RFed broadcast. A Delta
(the §5.3 MessagePack payload) is embedded as the *content* of an LXMF message
whose title is the fixed discriminator ``dacar/sync/delta``; on receipt, only
messages with a Dacar title are fed to the shared
:class:`~dacar.delta.DeltaReceiver` (verify-on-ingest, §11.2.4). The **batch
envelope** (title ``dacar/sync/batch``, work doc #14) packs *multiple* signed
Deltas into one message's content -- pure packing, each element still
verified individually -- for chunked bootstrap and Paper Message transfer.

§11.3 reuses the very same LXMF messages in LXMF's Paper Message encoding
(high-density QR), giving a fully air-gapped, optical channel: export produces
the encrypted paper bytes; import feeds them straight back through the router.

Requires the ``lxmf`` package (``import LXMF``), installed via the optional
``transport`` extra. The pure core never imports this module (see the purity
guard in ``tests/test_transport_lxmf.py``).

Typical use (receiver)::

    router = LXMF.LXMRouter(identity=me, storagepath=...)
    router.register_delivery_callback(
        LxmfDeltaDelivery(receiver=DeltaReceiver(state, key_resolver)).handle_delivery
    )

Typical use (sender, to a known target destination)::

    delivery = LxmfDeltaDelivery(router=router)
    delivery.deliver(delta_payload, target_destination, source=src)
"""

from __future__ import annotations

from typing import List

import LXMF

from dacar import serialization
from dacar.delta import DeltaReceiver
from dacar.naming import LXMF_BATCH_TITLE, LXMF_DELIVERY_TITLE

__all__ = [
    "LxmfDeltaDelivery",
    "lxmf_message_title",
    "lxmf_message_content",
    "encode_batch",
    "decode_batch",
    "pack_chunks",
    "PAPER_CONTENT_BUDGET",
    "pack_paper_messages",
]


def lxmf_message_title(message) -> str:
    """Best-effort title of an LXMF message as text."""
    fn = getattr(message, "title_as_string", None)
    if callable(fn):
        try:
            return fn() or ""
        except Exception:
            pass
    t = getattr(message, "title", "")
    if isinstance(t, (bytes, bytearray)):
        return bytes(t).decode("utf-8", "replace")
    return t or ""


def lxmf_message_content(message) -> bytes:
    """Best-effort content of an LXMF message as bytes (the Delta payload)."""
    c = getattr(message, "content", b"")
    if isinstance(c, str):
        return c.encode("utf-8")
    if isinstance(c, (bytes, bytearray)):
        return bytes(c)
    return b""


# -- §11.2 batch envelope (work doc #14) ----------------------------------


def encode_batch(payloads) -> bytes:
    """Encode signed Delta payloads as one batch envelope (§11.2, work doc #14).

    The wire format is the msgpack array ``[payload, …]`` (each element the
    exact signed §5.3 bytes, ``bin`` on the wire) under the fixed title
    :data:`dacar.naming.LXMF_BATCH_TITLE`. Pure packing: every element keeps
    its own signature and is verified individually at ingest.
    """
    return serialization.packb([bytes(p) for p in payloads])


def decode_batch(content: bytes) -> List[bytes]:
    """Decode a batch envelope into its Delta payloads.

    Strict: the content must be a msgpack array of binary payloads. Raises
    ``ValueError`` for anything else (not msgpack, not an array, non-binary
    elements) so :meth:`LxmfDeltaDelivery.handle_delivery` can drop a malformed
    batch whole without ever crashing the transport.
    """
    try:
        decoded = serialization.unpackb(bytes(content))
    except Exception as exc:
        raise ValueError(f"batch content is not msgpack: {exc}") from exc
    if not isinstance(decoded, list) or not decoded:
        raise ValueError("batch content must be a non-empty msgpack array")
    if not all(isinstance(p, (bytes, bytearray)) for p in decoded):
        raise ValueError("batch elements must be binary payloads")
    return [bytes(p) for p in decoded]


def pack_chunks(payloads, max_bytes: int) -> List[List[bytes]]:
    """Greedily split payloads into chunks whose *encoded* batch fits ``max_bytes``.

    Each chunk is a list of payloads such that ``len(encode_batch(chunk)) <=
    max_bytes``; payloads stay in order and are never split. A single payload
    whose encoded batch exceeds ``max_bytes`` becomes a (necessarily oversized)
    singleton chunk -- the caller checks the transport limit (e.g. paper
    packing raises on ``PAPER_MDU`` overflow) and errors with context.
    """
    chunks: List[List[bytes]] = []
    current: List[bytes] = []
    for payload in payloads:
        candidate = current + [bytes(payload)]
        if current and len(encode_batch(candidate)) > max_bytes:
            chunks.append(current)
            current = [bytes(payload)]
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


#: Conservative content budget for paper chunks: ``PAPER_MDU`` minus the fixed
#: paper overhead measured against the reference LXMF (16 B destination prefix
#: + ~92 B identity encryption + ~127 B LXM msgpack framing ≈ 235 B; ratchets
#: shift it slightly, which :func:`pack_paper_messages` absorbs by halving).
#: Cross-implementation chunk *boundaries* are irrelevant -- only the batch
#: codec must interop -- so a conservative budget is safe.
PAPER_CONTENT_BUDGET = LXMF.LXMessage.PAPER_MDU - 240


def pack_paper_messages(payloads, destination, source=None, delivery=None):
    """Split payloads into packed paper messages, each within ``PAPER_MDU``.

    Greedy :func:`pack_chunks` packing under :data:`PAPER_CONTENT_BUDGET`,
    then an adaptive pass: any chunk whose packed paper message exceeds the
    paper MDU (ratchets change the encryption overhead) is halved and retried
    until every chunk fits. A lone payload that still exceeds the MDU
    propagates LXMF's ``TypeError`` -- the caller reports it with context.
    Returns the list of packed :class:`LXMF.LXMessage` objects (one per QR).
    """
    delivery = delivery if delivery is not None else LxmfDeltaDelivery()

    def build(chunk: List[bytes]) -> list:
        try:
            return [delivery.make_paper_batch_message(chunk, destination, source)]
        except TypeError:
            if len(chunk) == 1:
                raise
            mid = len(chunk) // 2
            return build(chunk[:mid]) + build(chunk[mid:])

    messages: list = []
    for chunk in pack_chunks(payloads, PAPER_CONTENT_BUDGET):
        messages.extend(build(chunk))
    return messages


class LxmfDeltaDelivery:
    """§11.2 targeted Delta delivery over LXMF; §11.3 Paper Message channel.

    Parameters
    ----------
    receiver:
        The shared :class:`DeltaReceiver` (state + key resolver). May be ``None``
        on a send-only node (then :meth:`handle_delivery` raises if called).
    router:
        Optional bound :class:`LXMF.LXMRouter` for :meth:`deliver` / :meth:`ingest_paper`.
    """

    #: Fixed title discriminator (spec §11.2). Aliases :data:`dacar.naming.LXMF_DELIVERY_TITLE`.
    TITLE = LXMF_DELIVERY_TITLE

    def __init__(self, receiver=None, router=None):
        self._receiver = receiver
        self._router = router

    # -- §11.2 send --------------------------------------------------------

    def make_message(self, delta_payload, destination, source=None, desired_method=None):
        """Build an LXMF message wrapping one §5.3 Delta payload (§11.2.2).

        The returned message is *not yet sent*; pass it to ``router.handle_outbound``
        (or call :meth:`deliver`) to queue it for the network.
        """
        return LXMF.LXMessage(
            destination,
            source,
            content=bytes(delta_payload),
            title=self.TITLE,
            desired_method=desired_method,
        )

    def deliver(self, delta_payload, destination, source=None, desired_method=None):
        """Build and queue a Delta for LXMF delivery via the bound router."""
        message = self.make_message(delta_payload, destination, source, desired_method)
        self._router.handle_outbound(message)
        return message

    def make_batch_message(self, payloads, destination, source=None, desired_method=None):
        """Build an LXMF message wrapping multiple Deltas (batch envelope, §11.2).

        Content is :func:`encode_batch` of *payloads* under the fixed title
        :data:`dacar.naming.LXMF_BATCH_TITLE`. Callers pre-chunk with
        :func:`pack_chunks` so the encoded content fits the transport limit
        (LXMF content MDU for propagated, ``PAPER_MDU`` for paper).
        """
        payloads = [bytes(p) for p in payloads]
        message = LXMF.LXMessage(
            destination,
            source,
            content=encode_batch(payloads),
            title=LXMF_BATCH_TITLE,
            desired_method=desired_method,
        )
        message.dacar_batch_payloads = payloads  # provenance for senders/tests
        return message

    def deliver_batch(self, payloads, destination, source=None, desired_method=None):
        """Build and queue a batch of Deltas via the bound router (§11.2)."""
        message = self.make_batch_message(payloads, destination, source, desired_method)
        self._router.handle_outbound(message)
        return message

    # -- §11.2 receive -----------------------------------------------------

    def handle_delivery(self, message) -> bool:
        """LXMF delivery callback: filter by title, then apply the Delta(s) (§11.2.4).

        Accepts both Dacar titles: a ``dacar/sync/delta`` message carries one
        §5.3 payload; a ``dacar/sync/batch`` message carries a msgpack array of
        them, applied element-wise. Returns ``True`` if at least one Dacar
        Delta was applied, ``False`` otherwise (wrong title, or a
        malformed/forged payload -- which :meth:`DeltaReceiver.apply_payload`
        swallows so a bad message can never crash the transport; a malformed
        *batch* is dropped whole). Non-Dacar messages are passed through
        untouched.
        """
        title = lxmf_message_title(message)
        if title not in (self.TITLE, LXMF_BATCH_TITLE):
            return False
        if self._receiver is None:
            raise RuntimeError("LxmfDeltaDelivery.handle_delivery requires a DeltaReceiver")
        if title == LXMF_BATCH_TITLE:
            try:
                payloads = decode_batch(lxmf_message_content(message))
            except ValueError:
                return False  # malformed batch: dropped whole, never crashes
            # Apply EVERY element (no any() short-circuit: a batch is not
            # satisfied by its first good delta) and report whether any applied.
            results = [self._receiver.apply_payload(p) for p in payloads]
            return any(results)
        return self._receiver.apply_payload(lxmf_message_content(message))

    # -- §11.3 Paper Messages (air-gapped / optical) ----------------------

    def make_paper_message(self, delta_payload, destination, source=None):
        """Build a §11.3 Paper Message (QR-encodable) wrapping one Delta.

        Same wrapping as :meth:`make_message` but with LXMF's ``PAPER`` delivery
        method, so :attr:`LXMessage.paper_packed` holds the encrypted bytes to
        render as a high-density QR code. Raises if the Delta exceeds
        ``LXMessage.PAPER_MDU``.
        """
        message = self.make_message(
            delta_payload, destination, source, desired_method=LXMF.LXMessage.PAPER
        )
        message.pack()  # sets message.paper_packed (destination_hash + encrypted payload)
        return message

    def make_paper_batch_message(self, payloads, destination, source=None):
        """Build a §11.3 Paper Message wrapping a chunk of Deltas (work doc #14).

        Same as :meth:`make_paper_message` but the content is the batch envelope
        (:func:`encode_batch`), so one QR can carry several Deltas (up to the
        paper content limit; pre-chunk with :func:`pack_chunks` and the
        caller-computed limit). Raises if the encoded batch exceeds the paper
        content limit.
        """
        message = self.make_batch_message(
            payloads, destination, source, desired_method=LXMF.LXMessage.PAPER
        )
        message.pack()
        return message

    @staticmethod
    def paper_bytes(message) -> bytes:
        """The encrypted Paper Message bytes ready for QR rendering (§11.3).

        Raises ``ValueError`` if *message* is not a packed Paper Message.
        """
        packed = getattr(message, "paper_packed", None)
        if not packed:
            raise ValueError("message is not a packed Paper Message (paper_packed is empty)")
        return bytes(packed)

    def ingest_paper(self, paper_bytes):
        """Feed a scanned Paper Message back through the bound router (§11.3).

        The router decrypts it (it must own the delivery Identity) and routes the
        recovered LXMF message to the registered delivery callback
        (:meth:`handle_delivery`). Returns the router's propagation result.
        """
        return self._router.lxmf_propagation(bytes(paper_bytes), is_paper_message=True)
