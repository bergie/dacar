"""rfed channel proof-of-work stamp contract.

A rfed SEND payload ends with an optional 32-byte proof-of-work stamp bound to
the bytes it accompanies. The stamp material and value semantics are fixed by
``RFed/SPEC.md`` "PoW STAMP CONTRACT"::

    material     = channel_hash(16) ‖ inner_blob      # payload[..len-STAMP_SIZE]
    transient_id = SHA-256(material)
    workblock    = LXStamper::stamp_workblock(transient_id, STAMP_EXPAND_ROUNDS=16)
    value        = leading_zero_bits(SHA-256(workblock ‖ stamp))
    valid        = value >= stamp_cost

.. note::

   The SPEC defers to ``LXStamper::stamp_workblock``, expecting Python LXMF's
   memory-hard HKDF expansion. However the deployed ``reticulum-rust``
   ``LXStamper`` is an incompatible stub: its workblock is ``SHA-256`` iterated
   ``rounds + 1`` times over the transient id — a 32-byte value, not the
   memory-hard expansion. To interoperate with live rfed nodes (and with
   ``@reticulum/core``'s ``RFedClient``), this module mirrors that
   reticulum-rust workblock exactly. The value/stamp-valid semantics match
   Python (leading-zero-bits of ``SHA-256(workblock ‖ stamp)``).

``stamp_cost`` is owned by the ``/rfed/subscribe`` reply: a cost of ``0`` (or
``None``) means stamping is disabled and no stamp is required or appended.
"""

from __future__ import annotations

from typing import Tuple

import RNS

from dacar.rfed.constants import STAMP_EXPAND_ROUNDS, STAMP_SIZE

__all__ = [
    "STAMP_NONCE_CAP",
    "generate_channel_stamp",
    "validate_channel_stamp",
    "channel_stamp_workblock",
    "stamp_value",
]


#: Iteration cap mirroring ``reticulum-rust``'s ``LXStamper::generate_stamp``.
#: Costs used by rfed (e.g. 12) terminate far below this (~2^cost trials).
STAMP_NONCE_CAP = 1_000_000


def _leading_zero_bits(data: bytes) -> int:
    """Leading zero bits: 8 per all-zero byte, then ``lz`` of the first non-zero."""
    value = 0
    for byte in data:
        if byte == 0:
            value += 8
        else:
            value += 8 - byte.bit_length()
            break
    return value


def _u128le(nonce: int) -> bytes:
    """Encode a nonce as a 16-byte little-endian unsigned int (Rust ``u128``)."""
    return nonce.to_bytes(16, "little")


def channel_stamp_workblock(
    channel_hash: bytes, inner_blob: bytes, rounds: int = STAMP_EXPAND_ROUNDS
) -> Tuple[bytes, bytes]:
    """Compute the transient id and workblock for a channel stamp.

    ``transient_id = SHA-256(channel_hash ‖ inner_blob)``; the workblock is the
    reticulum-rust ``LXStamper`` workblock: ``SHA-256`` iterated ``rounds + 1``
    times over the transient id (a 32-byte value).
    """
    material = bytes(channel_hash) + bytes(inner_blob)
    transient_id = RNS.Identity.full_hash(material)
    workblock = RNS.Identity.full_hash(transient_id)
    for _ in range(rounds):
        workblock = RNS.Identity.full_hash(workblock)
    return transient_id, workblock


def stamp_value(workblock: bytes, stamp: bytes) -> int:
    """Leading-zero-bit value: ``leadingZeroBits(SHA-256(workblock ‖ stamp))``."""
    return _leading_zero_bits(RNS.Identity.full_hash(bytes(workblock) + bytes(stamp)))


def generate_channel_stamp(
    channel_hash: bytes, inner_blob: bytes, stamp_cost: int, rounds: int = STAMP_EXPAND_ROUNDS
) -> Tuple[bytes, int]:
    """Search for a valid 32-byte channel PoW stamp.

    Mirrors ``reticulum-rust``'s ``LXStamper::generate_stamp``: a stamp is
    ``SHA-256(workblock ‖ nonce_le16)`` for an increasing ``u128`` nonce,
    accepted once ``stamp_value(workblock, stamp) >= stamp_cost``.

    Returns ``(stamp, achieved_value)``. Raises if no stamp meets the cost
    within :data:`STAMP_NONCE_CAP` trials.
    """
    _, workblock = channel_stamp_workblock(channel_hash, inner_blob, rounds)
    for nonce in range(STAMP_NONCE_CAP + 1):
        stamp = RNS.Identity.full_hash(workblock + _u128le(nonce))
        value = stamp_value(workblock, stamp)
        if value >= stamp_cost:
            return stamp, value
    raise RuntimeError(
        f"rfed stamp generation exhausted {STAMP_NONCE_CAP} trials at cost {stamp_cost}"
    )


def validate_channel_stamp(
    channel_hash: bytes,
    inner_blob: bytes,
    stamp: bytes,
    stamp_cost: int,
    rounds: int = STAMP_EXPAND_ROUNDS,
) -> bool:
    """Validate a channel PoW stamp against a required cost."""
    if len(stamp) < STAMP_SIZE:
        return False
    _, workblock = channel_stamp_workblock(channel_hash, inner_blob, rounds)
    return stamp_value(workblock, stamp) >= stamp_cost
