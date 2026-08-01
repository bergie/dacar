"""Smoketests for namespace matching (§3.3)."""

from __future__ import annotations

import unittest

from dacar.namespace import match, permutations


class MatchTest(unittest.TestCase):
    def test_exact(self) -> None:
        self.assertTrue(match("sensor:wind", "sensor:wind"))
        self.assertFalse(match("sensor:wind", "sensor:rain"))

    def test_terminal_wildcard(self) -> None:
        self.assertTrue(match("sensor:*", "sensor:wind"))
        self.assertTrue(match("sensor:*", "sensor:wind:north"))
        self.assertFalse(match("sensor:*", "actuator:pump"))

    def test_root_wildcard(self) -> None:
        self.assertTrue(match("*", "anything"))
        self.assertTrue(match("*", "a:b:c:d"))

    def test_prefix_mismatch(self) -> None:
        self.assertFalse(match("sensor:wind:*", "actuator:wind:north"))

    def test_tuple_shorter_than_request(self) -> None:
        # A non-wildcard tuple must be exactly as long as the request.
        self.assertFalse(match("sensor:wind", "sensor:wind:north"))


class PermutationsTest(unittest.TestCase):
    def test_segments(self) -> None:
        self.assertEqual(
            set(permutations("sensor:wind:north")),
            {"sensor:wind:north", "sensor:wind:*", "sensor:*", "*"},
        )

    def test_single_segment(self) -> None:
        self.assertEqual(set(permutations("sensor")), {"sensor", "*"})

    def test_patterns_always_cover_request(self) -> None:
        # Every generated pattern that is legal (terminal wildcard) must, per
        # the match algorithm, cover the original request object.
        for obj in ("sensor:wind:north", "a", "a:b:c:d:e"):
            for pattern in permutations(obj):
                self.assertTrue(match(pattern, obj), f"{pattern!r} should cover {obj!r}")


if __name__ == "__main__":
    unittest.main()
