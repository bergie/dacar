"""Minimal canonical LXMF message wire codec.

The rfed channel envelope wraps a propagation-style LXMF message (§5.2/§5.1).
Rather than depend on the external ``lxmf`` package — whose
:class:`LXMF.LXMessage.pack()` requires a real :class:`RNS.Destination` (and
thus a running Reticulum) — this module reimplements just the wire format. It
is byte-for-byte compatible with Python LXMF's ``pack()`` /
``unpack_from_bytes()`` and with ``@reticulum/core``'s ``Message.serialize``,
so signatures and hashes cross-validate across all three.

Wire format::

    direct:   destination_hash(16) ‖ source_hash(16) ‖ signature(64) ‖ msgpack_payload
    payload:  [timestamp(float64), title(bin), content(bin), fields(map)] [, stamp(bin32)]

Signature (§5.5) is computed over ``destination_hash ‖ source_hash ‖
msgpack_payload ‖ message_hash``, where ``message_hash = SHA-256(dest ‖ src ‖
msgpack_payload)``. The optional 5th stamp element is stripped before hashing
(matching ``LXMessage.unpack_from_bytes``).

Uses :mod:`RNS` only for crypto (``full_hash`` / ``sign`` / ``validate``) and
:mod:`msgpack` for the payload, so it works without a running Reticulum.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple

import msgpack
import RNS

__all__ = ["DESTINATION_LENGTH", "SIGNATURE_LENGTH", "LxmfMessage"]

#: LXMF destination / source hash length (``TRUNCATED_HASHLENGTH // 8``).
DESTINATION_LENGTH = 16
#: Ed25519 signature length (``SIGLENGTH // 8``).
SIGNATURE_LENGTH = 64


def _to_bytes(value) -> bytes:
    """Coerce a str/bytes value to bytes (UTF-8) for bin encoding."""
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"expected str or bytes, got {type(value).__name__}")


def _pack_payload(
    timestamp: float,
    title: bytes,
    content: bytes,
    fields: Dict[str, Any],
    stamp: Optional[bytes] = None,
) -> bytes:
    """Canonical msgpack payload: float64 timestamp, bin title/content, map fields.

    ``use_single_float=False`` forces float64 (matching JS ``encodeFloat64``),
    and bytes encode as bin (``use_bin_type`` default).
    """
    payload: list = [timestamp, title, content, fields]
    if stamp is not None:
        payload.append(stamp)
    return msgpack.packb(payload, use_single_float=False)


class LxmfMessage:
    """A minimal LXMF message carrying the Dacar Delta payload.

    ``destination_hash`` / ``source_hash`` are the ``lxmf.delivery`` destination
    hashes (channel and sender respectively) — NOT bare identity hashes. For a
    channel message these are forced by :func:`dacar.rfed.blob.wrap_channel_message`
    before serialization, so placeholders are fine pre-publish.
    """

    def __init__(
        self,
        destination_hash: bytes = b"\x00" * 16,
        source_hash: bytes = b"\x00" * 16,
        content: bytes = b"",
        title: bytes = b"",
        fields: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        self.destination_hash = bytes(destination_hash)
        self.source_hash = bytes(source_hash)
        self.content = _to_bytes(content)
        self.title = _to_bytes(title)
        self.fields: Dict[str, Any] = dict(fields) if fields else {}
        self.timestamp = timestamp
        self.signature: Optional[bytes] = None
        #: message_id = SHA-256(dest ‖ src ‖ msgpack_payload).
        self.hash: Optional[bytes] = None
        self.signature_validated: bool = False
        #: Optional LXMF PoW stamp (5th payload element); rfed uses its own stamp.
        self.stamp: Optional[bytes] = None

    def serialize(self, source_identity: RNS.Identity) -> bytes:
        """Sign and serialize to the canonical LXMF wire format.

        Sets :attr:`hash` (message_id), :attr:`signature`, and returns the wire
        bytes ``dest ‖ source ‖ signature ‖ msgpack_payload``.
        """
        if self.timestamp is None:
            self.timestamp = time.time()
        packed = _pack_payload(
            self.timestamp, self.title, self.content, self.fields, stamp=None
        )
        hashed = self.destination_hash + self.source_hash + packed
        self.hash = RNS.Identity.full_hash(hashed)
        self.signature = source_identity.sign(hashed + self.hash)
        return self.destination_hash + self.source_hash + self.signature + packed

    @staticmethod
    def deserialize(
        wire: bytes, sender_pub: bytes
    ) -> "LxmfMessage":
        """Reconstruct and signature-verify an LXMF message from wire bytes.

        Parameters
        ----------
        wire:
            ``dest(16) ‖ source(16) ‖ signature(64) ‖ msgpack_payload``.
        sender_pub:
            The 64-byte sender public-key bundle (from the rfed RTID prelude),
            used to verify the Ed25519 signature.

        The hash is computed over the received ``msgpack_payload`` bytes when the
        payload has exactly 4 elements (the canonical, unambiguous path); a 5th
        stamp element is stripped and the first 4 re-packed before hashing,
        matching ``LXMF.LXMessage.unpack_from_bytes``.
        """
        if len(wire) < 2 * DESTINATION_LENGTH + SIGNATURE_LENGTH:
            raise ValueError(
                f"LXMF wire too short: {len(wire)} bytes "
                f"(need at least {2 * DESTINATION_LENGTH + SIGNATURE_LENGTH})"
            )
        dest_hash = wire[:DESTINATION_LENGTH]
        source_hash = wire[DESTINATION_LENGTH : 2 * DESTINATION_LENGTH]
        signature = wire[
            2 * DESTINATION_LENGTH : 2 * DESTINATION_LENGTH + SIGNATURE_LENGTH
        ]
        packed = wire[2 * DESTINATION_LENGTH + SIGNATURE_LENGTH :]

        unpacked = msgpack.unpackb(packed, raw=False, strict_map_key=False)
        if not isinstance(unpacked, list) or len(unpacked) < 4:
            raise ValueError("LXMF payload is not a 4+-element msgpack array")
        stamp: Optional[bytes] = None
        if len(unpacked) > 4:
            stamp = unpacked[4]
            unpacked = unpacked[:4]
            # Re-pack the 4 elements for hashing (matches LXMF unpack_from_bytes).
            packed_for_hash = msgpack.packb(unpacked, use_single_float=False)
        else:
            packed_for_hash = packed

        hashed = dest_hash + source_hash + packed_for_hash
        message_hash = RNS.Identity.full_hash(hashed)
        timestamp, title, content, fields = unpacked[:4]

        msg = LxmfMessage(
            destination_hash=dest_hash,
            source_hash=source_hash,
            content=content if isinstance(content, (bytes, bytearray)) else _to_bytes(content),
            title=title if isinstance(title, (bytes, bytearray)) else _to_bytes(title),
            fields=fields if isinstance(fields, dict) else {},
            timestamp=timestamp,
        )
        msg.signature = bytes(signature)
        msg.hash = message_hash
        msg.stamp = stamp

        sender_identity = RNS.Identity(create_keys=False)
        sender_identity.load_public_key(bytes(sender_pub))
        msg.signature_validated = sender_identity.validate(
            bytes(signature), hashed + message_hash
        )
        return msg
