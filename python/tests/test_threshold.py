"""Smoketests for Threshold Groups / N-of-M Issuers (§4.1)."""

from __future__ import annotations

import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar.namespace import HASH_SIZE
from dacar.operation import Action, Operation, Tuple
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
            group_id([M1, M2], 3)  # N > M
        with self.assertRaises(ValueError):
            group_id([b"short", M2], 1)

    def test_unanimous_n_equals_m_is_allowed(self) -> None:
        # N == M (unanimous consent) is a legitimate config the spec permits.
        self.assertEqual(group_id([M1, M2], 2), _expected_group_id([M1, M2], 2))
        self.assertEqual(len(group_id([M1, M2], 2)), HASH_SIZE)
        # and it is distinct from N == M - 1
        self.assertNotEqual(group_id([M1, M2], 2), group_id([M1, M2], 1))


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


class UnanimousConsentTest(unittest.TestCase):
    """N == M (all members must sign) is a legitimate config the spec permits."""

    def test_group_id_accepted_at_n_equals_m(self) -> None:
        g = ThresholdGroup((M1, M2, M3), 3)
        self.assertEqual(g.size, 3)
        self.assertEqual(g.group_id, group_id([M1, M2, M3], 3))

    def test_unanimous_signature_verifies(self) -> None:
        # Three members, threshold 3: all three must sign, and it verifies.
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes_raw() for k in keys]
        members = [
            hashlib.sha256(pubs[i]).digest()[:HASH_SIZE] for i in range(3)
        ]
        gid = group_id(members, 3)
        t = Tuple(
            relation_hash=bytes(range(HASH_SIZE)),
            object_hashes=(bytes(range(HASH_SIZE)),),
            wildcard=False,
            grantee=bytes(range(HASH_SIZE)),
            issuer=gid,
        )
        op = Operation(tuple=t, action=Action.GRANT, hlc=1).sign(*keys)
        self.assertTrue(op.verify_threshold(pubs, 3))
        # Dropping one signature (only 2 of 3) must NOT verify.
        short = Operation(
            tuple=t, action=Action.GRANT, hlc=1
        ).sign(keys[0], keys[1])
        self.assertFalse(short.verify_threshold(pubs, 3))


if __name__ == "__main__":
    unittest.main()
