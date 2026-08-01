"""Smoketests for the evaluation engine (§7)."""

from __future__ import annotations

import unittest

from dacar.config import Config
from dacar.crdt import StateVector
from dacar.engine import Engine
from dacar.hlc import Clock
from dacar.operation import Action, Operation
from dacar.tuple import HASH_SIZE, Tuple

ROOT = bytes(range(HASH_SIZE))              # Root Trust Anchor
ADMIN1 = bytes(range(1, HASH_SIZE + 1))     # A delegated administrator
ADMIN2 = bytes(range(2, HASH_SIZE + 2))     # Another administrator
BOB = bytes(range(3, HASH_SIZE + 3))        # A grantee
ALICE = bytes(range(4, HASH_SIZE + 4))      # Another grantee


class _Fixture:
    """A fresh engine + state + monotonic clock wired to a single root anchor."""

    def __init__(self, *, max_depth: int = 10, max_visited: int = 50) -> None:
        self.state = StateVector()
        self.clock = Clock()
        self.engine = Engine(
            Config(root_trust_anchors=frozenset({ROOT})),
            self.state,
            max_depth=max_depth,
            max_visited=max_visited,
        )

    def grant(self, obj: str, rel: str, grantee: bytes, issuer: bytes) -> None:
        self.state.apply(
            Operation(
                tuple=Tuple(obj, rel, grantee, issuer),
                action=Action.GRANT,
                hlc=self.clock.now(),
            )
        )


class ResolutionTest(unittest.TestCase):
    def test_default_deny(self) -> None:
        f = _Fixture()
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_root_anchor_direct_grant(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "calibrate", BOB, ROOT)
        self.assertTrue(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_wrong_grantee_denied(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "calibrate", BOB, ROOT)
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", ALICE))

    def test_wrong_relation_denied(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "read", BOB, ROOT)
        self.assertFalse(f.engine.evaluate("sensor:wind", "write", BOB))


class DelegationTest(unittest.TestCase):
    def test_delegated_admin_chain(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "admin", ADMIN1, ROOT)        # ADMIN1 becomes admin
        f.grant("sensor:wind", "calibrate", BOB, ADMIN1)     # ADMIN1 delegates to BOB
        self.assertTrue(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_undelegated_issuer_denied(self) -> None:
        # ADMIN1 grants BOB but has no admin backing -> invalid -> denied.
        f = _Fixture()
        f.grant("sensor:wind", "calibrate", BOB, ADMIN1)
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_wildcard_admin_cascades(self) -> None:
        # admin on sensor:* authorizes delegating sensor:wind:north (§3.2).
        f = _Fixture()
        f.grant("sensor:*", "admin", ADMIN1, ROOT)
        f.grant("sensor:wind:north", "calibrate", BOB, ADMIN1)
        self.assertTrue(f.engine.evaluate("sensor:wind:north", "calibrate", BOB))

    def test_exact_admin_does_not_cascade(self) -> None:
        # admin on sensor:wind does NOT authorize delegating sensor:wind:north.
        f = _Fixture()
        f.grant("sensor:wind", "admin", ADMIN1, ROOT)
        f.grant("sensor:wind:north", "calibrate", BOB, ADMIN1)
        self.assertFalse(f.engine.evaluate("sensor:wind:north", "calibrate", BOB))


class DenyTest(unittest.TestCase):
    def test_explicit_deny_overrides_allow(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "calibrate", BOB, ROOT)   # allow
        f.grant("sensor:wind", "-calibrate", BOB, ROOT)  # explicit deny (newer)
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_exact_deny_overrides_wildcard_allow(self) -> None:
        f = _Fixture()
        f.grant("sensor:*", "calibrate", BOB, ROOT)      # allow via wildcard
        f.grant("sensor:wind", "-calibrate", BOB, ROOT)  # deny exact
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))
        # ...but the wildcard still covers a sibling object.
        self.assertTrue(f.engine.evaluate("sensor:rain", "calibrate", BOB))


class SafetyBoundsTest(unittest.TestCase):
    def test_cycle_is_rejected_and_terminates(self) -> None:
        # ADMIN1 and ADMIN2 delegate admin to each other, neither rooted.
        f = _Fixture()
        f.grant("o", "admin", ADMIN1, ADMIN2)
        f.grant("o", "admin", ADMIN2, ADMIN1)
        f.grant("o", "r", BOB, ADMIN1)
        self.assertFalse(f.engine.evaluate("o", "r", BOB))

    def test_depth_cap_rejects_overlong_chain(self) -> None:
        # Build a 15-hop admin chain that never reaches a root anchor.
        f = _Fixture(max_depth=10)
        ids = [bytes([i]) * HASH_SIZE for i in range(1, 17)]  # 16 non-root identities
        for child, parent in zip(ids[1:], ids[:-1]):
            f.grant("o", "admin", child, parent)
        f.grant("o", "r", BOB, ids[-1])
        self.assertFalse(f.engine.evaluate("o", "r", BOB))

    def test_valid_chain_within_depth_is_allowed(self) -> None:
        # A 3-hop chain that DOES reach the root anchor must be allowed.
        f = _Fixture(max_depth=10)
        a = bytes([10]) * HASH_SIZE
        b = bytes([20]) * HASH_SIZE
        f.grant("o", "admin", a, ROOT)
        f.grant("o", "admin", b, a)
        f.grant("o", "read", BOB, b)
        self.assertTrue(f.engine.evaluate("o", "read", BOB))


if __name__ == "__main__":
    unittest.main()
