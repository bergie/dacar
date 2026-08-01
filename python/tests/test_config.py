"""Smoketests for node configuration (§4)."""

from __future__ import annotations

import unittest

from dacar.config import Config
from dacar.tuple import HASH_SIZE

ROOT = bytes(range(HASH_SIZE))


class ConfigTest(unittest.TestCase):
    def test_requires_at_least_one_anchor(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset())

    def test_anchor_length_validated(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({b"short"}))

    def test_authoritative_identity_optional(self) -> None:
        cfg = Config(root_trust_anchors=frozenset({ROOT}))
        self.assertIsNone(cfg.authoritative_identity)
        self.assertTrue(cfg.is_root_anchor(ROOT))

    def test_authoritative_identity_validated(self) -> None:
        with self.assertRaises(ValueError):
            Config(root_trust_anchors=frozenset({ROOT}), authoritative_identity=b"short")

    def test_multiple_anchors(self) -> None:
        other = bytes(range(1, HASH_SIZE + 1))
        cfg = Config(root_trust_anchors=frozenset({ROOT, other}))
        self.assertTrue(cfg.is_root_anchor(ROOT))
        self.assertTrue(cfg.is_root_anchor(other))


if __name__ == "__main__":
    unittest.main()
