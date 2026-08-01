"""Smoketests for the Tuple and its canonical hash (§3.1, §6.1)."""

from __future__ import annotations

import hashlib
import unittest

from dacar.tuple import HASH_SIZE, Tuple

ISSUER = bytes(range(HASH_SIZE))  # 16 deterministic bytes
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))


class TupleTest(unittest.TestCase):
    def test_hash_matches_spec_layout(self) -> None:
        t = Tuple(object="sensor:wind", relation="calibrate", grantee=GRANTEE, issuer=ISSUER)
        relation = b"calibrate"
        expected = hashlib.sha256(
            ISSUER + GRANTEE + len(relation).to_bytes(1, "big") + relation + b"sensor:wind"
        ).digest()
        self.assertEqual(t.hash(), expected)

    def test_per_issuer_distinctness(self) -> None:
        # The same permission granted by two different issuers yields two
        # mathematically distinct tuples (§3.1).
        other_issuer = bytes(range(1, HASH_SIZE + 1))
        t1 = Tuple("o", "r", GRANTEE, ISSUER)
        t2 = Tuple("o", "r", GRANTEE, other_issuer)
        self.assertNotEqual(t1.hash(), t2.hash())

    def test_grantee_distinctness(self) -> None:
        other_grantee = bytes(range(2, HASH_SIZE + 2))
        t1 = Tuple("o", "r", GRANTEE, ISSUER)
        t2 = Tuple("o", "r", other_grantee, ISSUER)
        self.assertNotEqual(t1.hash(), t2.hash())

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            Tuple("o", "r", b"short", ISSUER)
        with self.assertRaises(ValueError):
            Tuple("o", "r", GRANTEE, b"short")
        with self.assertRaises(ValueError):
            Tuple("o", "x" * 256, GRANTEE, ISSUER)

    def test_frozen(self) -> None:
        t = Tuple("o", "r", GRANTEE, ISSUER)
        with self.assertRaises(Exception):
            t.object = "other"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
