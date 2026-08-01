"""Smoketests for Threshold Groups / N-of-M Issuers (§4.1)."""

from __future__ import annotations

import hashlib
import unittest

from dacar.namespace import HASH_SIZE
from dacar.threshold import ThresholdGroup, group_id

M1 = bytes(range(HASH_SIZE))
M2 = bytes(range(1, HASH_SIZE + 1))
M3 = bytes(range(2, HASH_SIZE + 2))


def _expected_group_id(members, threshold: int) -> bytes:
    blob = b"".join(sorted(members)) + threshold.to_bytes(8, "big")
    return hashlib.sha256(blob).digest()[:HASH_SIZE]


class GroupIdTest(unittest.TestCase):
    def test_sha256_sorted_members_plus_n_truncated(self) -> None:
        self.assertEqual(group_id([M1, M2, M3], 2), _expected_group_id([M1, M2, M3], 2))
        self.assertEqual(len(group_id([M1, M2, M3], 2)), HASH_SIZE)

    def test_order_invariant(self) -> None:
        self.assertEqual(group_id([M1, M2, M3], 2), group_id([M3, M2, M1], 2))

    def test_threshold_changes_id(self) -> None:
        self.assertNotEqual(group_id([M1, M2, M3], 1), group_id([M1, M2, M3], 2))

    def test_membership_changes_id(self) -> None:
        self.assertNotEqual(group_id([M1, M2], 1), group_id([M1, M3], 1))

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            group_id([M1], 1)  # M < 2
        with self.assertRaises(ValueError):
            group_id([M1, M2], 0)  # N < 1
        with self.assertRaises(ValueError):
            group_id([M1, M2], 2)  # N >= M
        with self.assertRaises(ValueError):
            group_id([b"short", M2], 1)


class ThresholdGroupTest(unittest.TestCase):
    def test_members_stored_sorted(self) -> None:
        g = ThresholdGroup((M3, M1, M2), 2)
        self.assertEqual(g.members, tuple(sorted((M1, M2, M3))))

    def test_group_id_matches_helper(self) -> None:
        g = ThresholdGroup((M1, M2, M3), 2)
        self.assertEqual(g.group_id, group_id([M1, M2, M3], 2))
        self.assertEqual(g.size, 3)

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            ThresholdGroup((M1,), 1)


if __name__ == "__main__":
    unittest.main()
