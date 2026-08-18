"""rfed channel proof-of-work stamp contract.

A rfed SEND payload ends with an optional 32-byte proof-of-work stamp bound to
the bytes it accompanies. The stamp material and value semantics are fixed by
``RFed/SPEC.md`` "PoW STAMP CONTRACT"::

    material     = channel_hash(16) ‖ inner_blob      # payload[..len-STAMP_SIZE]
    transient_id = SHA-256(material)
    workblock    = LXStamper::stamp_workblock(transient_id, STAMP_EXPAND_ROUNDS=16)
    value        = leading_zero_bits(SHA-256(workblock ‖ stamp))
    valid        = value >= stamp_cost

The workblock, stamp generation, and validation semantics are the **standard
LXMF** ones — byte-compatible with Python LXMF's ``LXMF.LXStamper`` and
``@reticulum/core``'s ``lxmf/stamper.js`` — run at rfed's 16 expansion rounds.
The workblock is the memory-hard HKDF expansion: the concatenation of
``rounds`` chunks of 256 bytes each, where chunk ``n`` is
``HKDF-SHA256(ikm=transient_id, salt=SHA-256(transient_id ‖ msgpack(n)), L=256)``
(4096 bytes at rfed's 16 rounds). Stamp generation mirrors LXMF's random-trial
search; validation is value-based, so the trial strategy does not affect
interoperability.

.. note::

   An interim ``reticulum-rust`` ``LXStamper`` was an incompatible stub: its
   workblock was ``SHA-256`` iterated ``rounds + 1`` times over the transient
   id — a 32-byte value, not the memory-hard HKDF expansion — so this module
   briefly mirrored that stub to interoperate with live rfed nodes. The stub
   was fixed upstream (https://github.com/jrl290/Reticulum-rust/pull/2), and
   both ``reticulum-rust`` and ``@reticulum/core`` now use the standard LXMF
   workblock, so stamps minted by either side cross-validate with Python LXMF
   and fixed Rust nodes. Stamps generated against the old stub workblock are
   no longer valid (nor are ours on unfixed Rust nodes) — a protocol-level
   change, not an API one.

``stamp_cost`` is owned by the ``/rfed/subscribe`` reply: a cost of ``0`` (or
``None``) means stamping is disabled and no stamp is required or appended.
"""

from __future__ import annotations

import os
from typing import Tuple

import msgpack
import RNS

from dacar.rfed.constants import STAMP_EXPAND_ROUNDS, STAMP_SIZE

__all__ = [
    "stamp_workblock",
    "generate_channel_stamp",
    "validate_channel_stamp",
    "channel_stamp_workblock",
    "stamp_value",
    "stamp_valid",
]


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


def stamp_workblock(material: bytes, expand_rounds: int = STAMP_EXPAND_ROUNDS) -> bytes:
    """Build the memory-hard LXMF stamp workblock for ``material``.

    Mirrors ``LXMF.LXStamper.stamp_workblock`` byte-for-byte: the concatenation
    of ``expand_rounds`` chunks, each 256 bytes of HKDF-SHA256 keyed on
    ``material`` and salted with ``SHA-256(material ‖ msgpack(n))``. At the
    default 3000 LXMF rounds the workblock is 768 KiB — deliberately
    cache-unfriendly to limit GPU/ASIC speedup; at rfed's 16 rounds it is a
    4 KiB block. The per-round msgpack counter matches ``umsgpack.packb``
    (positive fixint below 128, then wider uint encodings).
    """
    workblock = b""
    for n in range(expand_rounds):
        workblock += RNS.Cryptography.hkdf(
            length=256,
            derive_from=material,
            salt=RNS.Identity.full_hash(material + msgpack.packb(n)),
            context=None,
        )
    return workblock


def channel_stamp_workblock(
    channel_hash: bytes, inner_blob: bytes, rounds: int = STAMP_EXPAND_ROUNDS
) -> Tuple[bytes, bytes]:
    """Compute the transient id and workblock for a channel stamp.

    ``transient_id = SHA-256(channel_hash ‖ inner_blob)``; the workblock is the
    standard LXMF memory-hard HKDF expansion of the transient id
    (:func:`stamp_workblock`) at rfed's expansion rounds.
    """
    material = bytes(channel_hash) + bytes(inner_blob)
    transient_id = RNS.Identity.full_hash(material)
    return transient_id, stamp_workblock(transient_id, rounds)


def stamp_value(workblock: bytes, stamp: bytes) -> int:
    """Leading-zero-bit value: ``leadingZeroBits(SHA-256(workblock ‖ stamp))``."""
    return _leading_zero_bits(RNS.Identity.full_hash(bytes(workblock) + bytes(stamp)))


def stamp_valid(stamp: bytes, target_cost: int, workblock: bytes) -> bool:
    """Validate a stamp against a target proof-of-work cost (LXMF semantics).

    A stamp meets ``target_cost`` when
    ``int(SHA-256(workblock ‖ stamp)) <= 1 << (256 - target_cost)`` — equivalent
    to :func:`stamp_value` ``>= target_cost``.
    """
    target = 1 << (256 - target_cost)
    result = RNS.Identity.full_hash(bytes(workblock) + bytes(stamp))
    return int.from_bytes(result, byteorder="big") <= target


def generate_channel_stamp(
    channel_hash: bytes, inner_blob: bytes, stamp_cost: int, rounds: int = STAMP_EXPAND_ROUNDS
) -> Tuple[bytes, int]:
    """Search for a valid 32-byte channel PoW stamp.

    Mirrors LXMF's ``LXStamper.generate_stamp``: random 32-byte trials over the
    standard-LXMF workblock, accepted once
    ``stamp_value(workblock, stamp) >= stamp_cost``. Expected trials are
    ``~2^stamp_cost`` (rfed costs such as 12 terminate in a few thousand).

    Returns ``(stamp, achieved_value)``.
    """
    _, workblock = channel_stamp_workblock(channel_hash, inner_blob, rounds)
    while True:
        stamp = os.urandom(STAMP_SIZE)
        if stamp_valid(stamp, stamp_cost, workblock):
            return stamp, stamp_value(workblock, stamp)


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
