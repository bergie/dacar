"""Smoketests for node configuration (§4, §10)."""

from __future__ import annotations

import unittest

from dacar.config import Config
from dacar.namespace import DEFAULT_SALT, MAX_LEGACY_SALTS, SALT_SIZE, NamespaceHasher
from dacar.threshold import ThresholdGroup
from dacar.tuple import HASH_SIZE

ROOT = bytes(range(HASH_SIZE))
SALT_A = bytes(range(SALT_SIZE))
SALT_B = bytes(reversed(range(SALT_SIZE)))
SALT_C = bytes([3] * SALT_SIZE)
SALT_D = bytes([4] * SALT_SIZE)


class AnchorsTest(unittest.TestCase):
    def test_requires_at_least_one_anchor(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset())

    def test_anchor_length_validated(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({b"short"}))

    def test_is_root_anchor(self) -> None:
        other = bytes(range(1, HASH_SIZE + 1))
        cfg = Config(root_trust_anchors=frozenset({ROOT, other}))
        self.assertTrue(cfg.is_root_anchor(ROOT))
        self.assertTrue(cfg.is_root_anchor(other))
        self.assertFalse(cfg.is_root_anchor(bytes(HASH_SIZE)))

    def test_authoritative_identity_validated(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({ROOT}), authoritative_identity=b"short")


class SaltsTest(unittest.TestCase):
    def test_default_salt_is_fail_open(self) -> None:
        cfg = Config(root_trust_anchors=frozenset({ROOT}))
        self.assertEqual(cfg.primary_salt, DEFAULT_SALT)
        self.assertEqual(cfg.hashers, [NamespaceHasher(DEFAULT_SALT)])

    def test_primary_and_legacy_hashers_ordered(self) -> None:
        cfg = Config(
            root_trust_anchors=frozenset({ROOT}),
            primary_salt=SALT_A,
            legacy_salts=(SALT_B, SALT_C),
        )
        self.assertEqual([h.salt for h in cfg.hashers], [SALT_A, SALT_B, SALT_C])

    def test_legacy_cap_enforced(self) -> None:
        with self.assertRaises(ValueError):
            Config(
                root_trust_anchors=frozenset({ROOT}),
                primary_salt=SALT_A,
                legacy_salts=(SALT_B, SALT_C, SALT_D),  # 3 > MAX_LEGACY_SALTS
            )

    def test_salt_length_validated(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({ROOT}), primary_salt=b"short")
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({ROOT}), legacy_salts=(b"short",))


class ThresholdGroupsTest(unittest.TestCase):
    def test_group_for_lookup(self) -> None:
        m1, m2 = bytes(range(HASH_SIZE)), bytes(range(1, HASH_SIZE + 1))
        group = ThresholdGroup((m1, m2), 1)
        cfg = Config(root_trust_anchors=frozenset({group.group_id}), threshold_groups=(group,))
        self.assertIs(cfg.group_for(group.group_id), group)
        self.assertIsNone(cfg.group_for(bytes(HASH_SIZE)))
        # A threshold group can be a root anchor.
        self.assertTrue(cfg.is_root_anchor(group.group_id))


class HorizonTest(unittest.TestCase):
    def test_default_horizon(self) -> None:
        cfg = Config(root_trust_anchors=frozenset({ROOT}))
        self.assertEqual(cfg.deletion_horizon_days, 180)

    def test_horizon_validated(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({ROOT}), deletion_horizon_days=0)


if __name__ == "__main__":
    unittest.main()
