"""Smoketests for Hybrid Logical Clocks (§5.1)."""

from __future__ import annotations

import unittest

from dacar.hlc import (
    LOGICAL_MASK,
    MAX_HLC,
    MAX_PHYSICAL,
    Clock,
    pack,
    physical_now_ms,
    unpack,
)


class HLCFormatTest(unittest.TestCase):
    def test_pack_unpack_roundtrip(self) -> None:
        ms, logical = physical_now_ms(), 1234
        hlc = pack(ms, logical)
        self.assertEqual(unpack(hlc), (ms, logical))

    def test_layout_is_48_plus_16(self) -> None:
        # Logical bits live in the low 16; physical in the high 48.
        hlc = pack(0, 1)
        self.assertEqual(hlc, 1)
        hlc2 = pack(1, 0)
        self.assertEqual(hlc2 >> 16, 1)

    def test_extremes(self) -> None:
        self.assertEqual(pack(0, 0), 0)
        self.assertEqual(pack(MAX_PHYSICAL, LOGICAL_MASK), MAX_HLC)
        self.assertEqual(unpack(MAX_HLC), (MAX_PHYSICAL, LOGICAL_MASK))

    def test_out_of_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            pack(MAX_PHYSICAL + 1, 0)
        with self.assertRaises(ValueError):
            pack(0, LOGICAL_MASK + 1)
        with self.assertRaises(ValueError):
            unpack(-1)


class ClockTest(unittest.TestCase):
    def test_monotonic(self) -> None:
        clock = Clock()
        prev = 0
        for _ in range(1000):
            value = clock.now()
            self.assertGreater(value, prev)
            prev = value

    def test_observe_preserves_happens_before(self) -> None:
        clock = Clock()
        a = clock.now()
        # A remote HLC strictly newer than anything local bumps the logical
        # counter so the next local event is causally after the remote one.
        remote = a + 5_000
        b = clock.observe(remote)
        self.assertGreater(b, remote)
        self.assertGreater(clock.now(), b)


if __name__ == "__main__":
    unittest.main()
