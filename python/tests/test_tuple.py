"""Smoketests for the hashed Tuple and its canonical hash (§3.1, §6.1)."""

from __future__ import annotations

import hashlib
import unittest

from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.tuple import MAX_SEGMENTS, Tuple

SALT = bytes(range(SALT_SIZE))
HASHER = NamespaceHasher(SALT)
ISSUER = bytes(range(HASH_SIZE))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))


def _relation(name: str) -> bytes:
    return HASHER.hash_relation(name)


def _object(name: str):
    return HASHER.hash_object(name)


class FromPlaintextTest(unittest.TestCase):
    def test_hashes_labels_with_the_salt(self) -> None:
        t = Tuple.from_plaintext(
            object_id="sensor:wind", relation="calibrate",
            grantee=GRANTEE, issuer=ISSUER, hasher=HASHER,
        )
        self.assertEqual(t.relation_hash, _relation("calibrate"))
        self.assertEqual(t.object_hashes, _object("sensor:wind")[0])
        self.assertFalse(t.wildcard)

    def test_wildcard_flag_preserved(self) -> None:
        t = Tuple.from_plaintext(
            object_id="sensor:*", relation="admin",
            grantee=GRANTEE, issuer=ISSUER, hasher=HASHER,
        )
        self.assertTrue(t.wildcard)
        self.assertEqual(t.object_hashes, _object("sensor:*")[0])


class HashLayoutTest(unittest.TestCase):
    def test_preimage_excludes_action_and_hlc(self) -> None:
        # §6.1: Issuer + Grantee + RelationHash + Wildcard + SegCount + Hashes
        t = Tuple.from_plaintext(
            object_id="sensor:wind", relation="calibrate",
            grantee=GRANTEE, issuer=ISSUER, hasher=HASHER,
        )
        expected = (
            ISSUER + GRANTEE + _relation("calibrate")
            + bytes([0x00])  # wildcard flag
            + bytes([2])     # segment count
            + _object("sensor:wind")[0][0] + _object("sensor:wind")[0][1]
        )
        self.assertEqual(t.preimage(), expected)

    def test_hash_is_sha256_of_preimage(self) -> None:
        t = Tuple.from_plaintext(
            object_id="o", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER,
        )
        self.assertEqual(t.hash(), hashlib.sha256(t.preimage()).digest())

    def test_grant_and_revoke_share_a_hash(self) -> None:
        # §6.1: action/HLC excluded, so the same permission has one Tuple Hash.
        t = Tuple.from_plaintext(
            object_id="o", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER,
        )
        self.assertEqual(t.hash(), t.key)


class DistinctnessTest(unittest.TestCase):
    def test_per_issuer_distinctness(self) -> None:
        other = bytes(range(1, HASH_SIZE + 1))
        t1 = Tuple.from_plaintext(object_id="o", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER)
        t2 = Tuple.from_plaintext(object_id="o", relation="r", grantee=GRANTEE, issuer=other, hasher=HASHER)
        self.assertNotEqual(t1.hash(), t2.hash())

    def test_per_grantee_distinctness(self) -> None:
        other = bytes(range(2, HASH_SIZE + 2))
        t1 = Tuple.from_plaintext(object_id="o", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER)
        t2 = Tuple.from_plaintext(object_id="o", relation="r", grantee=other, issuer=ISSUER, hasher=HASHER)
        self.assertNotEqual(t1.hash(), t2.hash())

    def test_wildcard_differs_from_exact(self) -> None:
        t_exact = Tuple.from_plaintext(object_id="sensor", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER)
        t_wild = Tuple.from_plaintext(object_id="sensor:*", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER)
        self.assertNotEqual(t_exact.hash(), t_wild.hash())


class ValidationTest(unittest.TestCase):
    def test_bad_lengths_rejected(self) -> None:
        rh = _relation("r")
        with self.assertRaises(ValueError):
            Tuple(rh, (b"short",), False, GRANTEE, ISSUER)
        with self.assertRaises(ValueError):
            Tuple(b"short", (), False, GRANTEE, ISSUER)
        with self.assertRaises(ValueError):
            Tuple(rh, (), False, b"short", ISSUER)

    def test_too_many_segments_rejected(self) -> None:
        rh = _relation("r")
        seg = b"s" * HASH_SIZE
        with self.assertRaises(ValueError):
            Tuple(rh, tuple([seg] * (MAX_SEGMENTS + 1)), False, GRANTEE, ISSUER)

    def test_frozen(self) -> None:
        t = Tuple.from_plaintext(object_id="o", relation="r", grantee=GRANTEE, issuer=ISSUER, hasher=HASHER)
        with self.assertRaises(Exception):
            t.wildcard = True  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
