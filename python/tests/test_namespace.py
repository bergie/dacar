"""Smoketests for Namespace Label Privacy (§3.3)."""

from __future__ import annotations

import hashlib
import hmac
import unittest

from dacar.namespace import (
    DEFAULT_SALT,
    HASH_SIZE,
    MAX_LEGACY_SALTS,
    SALT_SIZE,
    NamespaceHasher,
    covers,
    split,
)

SALT_A = bytes(range(SALT_SIZE))
SALT_B = bytes(reversed(range(SALT_SIZE)))


def _hmac16(salt: bytes, msg: str) -> bytes:
    return hmac.new(salt, msg.encode("utf-8"), hashlib.sha256).digest()[:HASH_SIZE]


class HashRelationTest(unittest.TestCase):
    def test_truncated_to_16_bytes(self) -> None:
        h = NamespaceHasher(SALT_A)
        self.assertEqual(len(h.hash_relation("admin")), HASH_SIZE)
        self.assertEqual(len(h.hash_relation("-calibrate")), HASH_SIZE)

    def test_matches_hmac_sha256_truncated(self) -> None:
        h = NamespaceHasher(SALT_A)
        self.assertEqual(h.hash_relation("calibrate"), _hmac16(SALT_A, "calibrate"))
        # Explicit denies hash the whole string including the hyphen (§3.3).
        self.assertEqual(h.hash_relation("-calibrate"), _hmac16(SALT_A, "-calibrate"))

    def test_salt_sensitivity(self) -> None:
        a, b = NamespaceHasher(SALT_A), NamespaceHasher(SALT_B)
        self.assertNotEqual(a.hash_relation("read"), b.hash_relation("read"))

    def test_default_salt_is_fail_open_nulls(self) -> None:
        self.assertEqual(NamespaceHasher().salt, DEFAULT_SALT)
        self.assertEqual(DEFAULT_SALT, b"\x00" * SALT_SIZE)


class HashObjectTest(unittest.TestCase):
    def test_segments_hashed_individually(self) -> None:
        h = NamespaceHasher(SALT_A)
        hashes, wildcard = h.hash_object("sensor:wind")
        self.assertFalse(wildcard)
        self.assertEqual(hashes, (_hmac16(SALT_A, "sensor"), _hmac16(SALT_A, "wind")))

    def test_terminal_wildcard_is_stripped(self) -> None:
        h = NamespaceHasher(SALT_A)
        hashes, wildcard = h.hash_object("sensor:*")
        self.assertTrue(wildcard)
        self.assertEqual(hashes, (_hmac16(SALT_A, "sensor"),))

    def test_root_wildcard(self) -> None:
        h = NamespaceHasher(SALT_A)
        hashes, wildcard = h.hash_object("*")
        self.assertTrue(wildcard)
        self.assertEqual(hashes, ())


class IdTagTest(unittest.TestCase):
    def test_identifies_the_salt(self) -> None:
        self.assertEqual(NamespaceHasher(SALT_A).id_tag, NamespaceHasher(SALT_A).id_tag)
        self.assertNotEqual(NamespaceHasher(SALT_A).id_tag, NamespaceHasher(SALT_B).id_tag)
        self.assertEqual(len(NamespaceHasher(SALT_A).id_tag), HASH_SIZE)

    def test_legacy_cap_constant(self) -> None:
        self.assertEqual(MAX_LEGACY_SALTS, 2)


class CoversTest(unittest.TestCase):
    def test_exact_match(self) -> None:
        req = (b"a" * 16, b"b" * 16)
        self.assertTrue(covers(req, False, req))
        self.assertFalse(covers((b"a" * 16,), False, req))  # shorter, no wildcard

    def test_wildcard_prefix(self) -> None:
        req = (b"a" * 16, b"b" * 16, b"c" * 16)
        self.assertTrue(covers((b"a" * 16,), True, req))  # sensor:* covers sensor:wind:north
        self.assertTrue(covers((), True, req))  # root wildcard covers all
        self.assertFalse(covers((b"z" * 16,), True, req))  # prefix mismatch

    def test_wildcard_not_longer_than_request(self) -> None:
        req = (b"a" * 16,)
        self.assertFalse(covers((b"a" * 16, b"b" * 16), True, req))


class ValidationTest(unittest.TestCase):
    def test_salt_must_be_32_bytes(self) -> None:
        with self.assertRaises(ValueError):
            NamespaceHasher(b"short")

    def test_split(self) -> None:
        self.assertEqual(split("a:b:c"), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
