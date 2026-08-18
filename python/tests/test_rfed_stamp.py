"""Smoketests for the rfed channel PoW stamp contract (:mod:`dacar.rfed.stamp`).

The rfed stamp uses the **standard LXMF** mechanism (``LXMF.LXStamper`` /
``@reticulum/core`` ``lxmf/stamper.js``) at rfed's 16 expansion rounds: a
memory-hard HKDF workblock over ``SHA-256(channel_hash ‖ inner_blob)``, with
value-based validation. These tests pin:

- the workblock byte format (fixed vector + length),
- byte-compatibility with Python LXMF's ``LXStamper`` when installed (it is an
  optional dependency, so those tests skip otherwise),
- that the legacy reticulum-rust stub workblock (iterated SHA-256) is *not*
  what we produce anymore,
- generate → validate round-trips and stamp/material binding.

Offline (no running Reticulum needed); requires the ``rns`` package.
"""

from __future__ import annotations

import unittest

import RNS

from dacar.rfed.constants import STAMP_EXPAND_ROUNDS, STAMP_SIZE
from dacar.rfed.stamp import (
    channel_stamp_workblock,
    generate_channel_stamp,
    stamp_valid,
    stamp_value,
    stamp_workblock,
    validate_channel_stamp,
)

try:  # optional: the canonical reference implementation
    from LXMF.LXStamper import stamp_workblock as lxmf_stamp_workblock

    HAS_LXMF = True
except ImportError:  # pragma: no cover - depends on environment
    HAS_LXMF = False

#: Fixed vector: channel_hash(16×0x01) ‖ inner_blob(100×0x02), 16 rounds.
CHANNEL_HASH = b"\x01" * 16
INNER_BLOB = b"\x02" * 100
TRANSIENT_ID = bytes.fromhex(
    "f93147a0368ead6529b5ea5be059382611be7f4bf9eaf5198d05d2820a7e110a"
)
#: SHA-256 over the full 4096-byte workblock (derived with Python LXMF 1.1.0).
WORKBLOCK_SHA256 = "2dedaf184fff0dc27edf5f53ecf4eff6509e9a4954564e1e7e2d4026c4cc7790"


class ChannelStampWorkblockTest(unittest.TestCase):
    """The workblock is the standard LXMF memory-hard HKDF expansion."""

    def test_workblock_matches_fixed_lxmf_vector(self) -> None:
        """The full 4096-byte workblock is pinned by its SHA-256 (LXMF-derived)."""
        _, workblock = channel_stamp_workblock(CHANNEL_HASH, INNER_BLOB)
        self.assertEqual(
            RNS.Identity.full_hash(workblock).hex(),
            WORKBLOCK_SHA256,
            "workblock does not match the fixed LXMF-derived vector",
        )

    def test_transient_id_and_size(self) -> None:
        transient_id, workblock = channel_stamp_workblock(CHANNEL_HASH, INNER_BLOB)
        self.assertEqual(transient_id, TRANSIENT_ID)
        # 16 rounds × 256-byte HKDF chunks = 4096 bytes (not the 32-byte stub).
        self.assertEqual(len(workblock), STAMP_EXPAND_ROUNDS * 256)

    def test_workblock_is_not_the_legacy_rust_stub(self) -> None:
        """The old reticulum-rust stub iterated SHA-256 (32 bytes); we must not.

        Fixed upstream in https://github.com/jrl290/Reticulum-rust/pull/2 —
        rfed stamping is now the standard LXMF mechanism.
        """
        _, workblock = channel_stamp_workblock(CHANNEL_HASH, INNER_BLOB)
        stub = RNS.Identity.full_hash(TRANSIENT_ID)
        for _ in range(STAMP_EXPAND_ROUNDS):
            stub = RNS.Identity.full_hash(stub)
        self.assertNotEqual(workblock, stub)
        self.assertNotEqual(workblock[:32], stub)

    @unittest.skipUnless(HAS_LXMF, "lxmf package not installed")
    def test_byte_identical_to_lxmf_stamper(self) -> None:
        """rfed workblock == ``LXMF.LXStamper.stamp_workblock`` at 16 rounds."""
        for rounds in (0, 1, 16, 128, 300):
            material = RNS.Identity.full_hash(CHANNEL_HASH + INNER_BLOB)
            self.assertEqual(
                stamp_workblock(material, rounds),
                lxmf_stamp_workblock(material, rounds),
                f"workblock diverges from LXMF at {rounds} rounds",
            )


class GenerateValidateStampTest(unittest.TestCase):
    """generate → validate round-trips and binding (random-trial search)."""

    def test_generate_validates_at_cost(self) -> None:
        for cost in (1, 4, 8):
            with self.subTest(cost=cost):
                stamp, value = generate_channel_stamp(
                    CHANNEL_HASH, INNER_BLOB, cost
                )
                self.assertEqual(len(stamp), STAMP_SIZE)
                self.assertGreaterEqual(value, cost)
                self.assertTrue(
                    validate_channel_stamp(CHANNEL_HASH, INNER_BLOB, stamp, cost)
                )

    def test_stamp_is_bound_to_material(self) -> None:
        stamp, _ = generate_channel_stamp(CHANNEL_HASH, INNER_BLOB, 4)
        other_blob = INNER_BLOB[:-1] + b"\x03"
        self.assertFalse(validate_channel_stamp(CHANNEL_HASH, other_blob, stamp, 4))

    def test_validate_rejects_junk(self) -> None:
        self.assertFalse(
            validate_channel_stamp(CHANNEL_HASH, INNER_BLOB, b"\xff" * 32, 8)
        )
        self.assertFalse(
            validate_channel_stamp(CHANNEL_HASH, INNER_BLOB, b"\xff" * 8, 1),
            "short stamps must be rejected",
        )

    def test_stamp_value_and_valid_match_lxmf_semantics(self) -> None:
        workblock = stamp_workblock(TRANSIENT_ID, STAMP_EXPAND_ROUNDS)
        stamp = RNS.Identity.full_hash(workblock + b"nonce")
        value = stamp_value(workblock, stamp)
        self.assertEqual(stamp_valid(stamp, value, workblock), True)
        self.assertEqual(stamp_valid(stamp, value + 1, workblock), False)


if __name__ == "__main__":
    unittest.main()
