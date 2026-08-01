"""Smoketests for the evaluation engine (§7)."""

from __future__ import annotations

import unittest

from dacar.config import Config
from dacar.crdt import StateVector
from dacar.engine import Engine
from dacar.hlc import Clock, pack
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.operation import Action, Operation
from dacar.threshold import ThresholdGroup
from dacar.tuple import Tuple

SALT = bytes(range(SALT_SIZE))
HASHER = NamespaceHasher(SALT)

ROOT = bytes(range(HASH_SIZE))
ADMIN1 = bytes(range(1, HASH_SIZE + 1))
ADMIN2 = bytes(range(2, HASH_SIZE + 2))
BOB = bytes(range(3, HASH_SIZE + 3))
ALICE = bytes(range(4, HASH_SIZE + 4))


class _Fixture:
    """A fresh engine + state + monotonic clock wired to a single root anchor."""

    def __init__(
        self,
        *,
        max_depth: int = 10,
        max_visited: int = 50,
        primary_salt: bytes = SALT,
        legacy_salts=(),
        threshold_groups=(),
    ) -> None:
        self.state = StateVector()
        self.clock = Clock()
        self.engine = Engine(
            Config(
                root_trust_anchors=frozenset({ROOT}),
                primary_salt=primary_salt,
                legacy_salts=legacy_salts,
                threshold_groups=threshold_groups,
            ),
            self.state,
            max_depth=max_depth,
            max_visited=max_visited,
        )

    def grant(self, obj: str, rel: str, grantee: bytes, issuer: bytes) -> None:
        self.state.apply(
            Operation(
                tuple=Tuple.from_plaintext(
                    object_id=obj, relation=rel, grantee=grantee, issuer=issuer, hasher=HASHER
                ),
                action=Action.GRANT,
                hlc=self.clock.now(),
            )
        )


class ResolutionTest(unittest.TestCase):
    def test_default_deny(self) -> None:
        self.assertFalse(_Fixture().engine.evaluate("sensor:wind", "calibrate", BOB))

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
        f.grant("sensor:wind", "admin", ADMIN1, ROOT)
        f.grant("sensor:wind", "calibrate", BOB, ADMIN1)
        self.assertTrue(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_undelegated_issuer_denied(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "calibrate", BOB, ADMIN1)
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_wildcard_admin_cascades(self) -> None:
        f = _Fixture()
        f.grant("sensor:*", "admin", ADMIN1, ROOT)
        f.grant("sensor:wind:north", "calibrate", BOB, ADMIN1)
        self.assertTrue(f.engine.evaluate("sensor:wind:north", "calibrate", BOB))

    def test_exact_admin_does_not_cascade(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "admin", ADMIN1, ROOT)
        f.grant("sensor:wind:north", "calibrate", BOB, ADMIN1)
        self.assertFalse(f.engine.evaluate("sensor:wind:north", "calibrate", BOB))


class DenyTest(unittest.TestCase):
    def test_explicit_deny_overrides_allow(self) -> None:
        f = _Fixture()
        f.grant("sensor:wind", "calibrate", BOB, ROOT)
        f.grant("sensor:wind", "-calibrate", BOB, ROOT)
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_exact_deny_overrides_wildcard_allow(self) -> None:
        f = _Fixture()
        f.grant("sensor:*", "calibrate", BOB, ROOT)
        f.grant("sensor:wind", "-calibrate", BOB, ROOT)
        self.assertFalse(f.engine.evaluate("sensor:wind", "calibrate", BOB))
        self.assertTrue(f.engine.evaluate("sensor:rain", "calibrate", BOB))


class SafetyBoundsTest(unittest.TestCase):
    def test_cycle_is_rejected_and_terminates(self) -> None:
        f = _Fixture()
        f.grant("o", "admin", ADMIN1, ADMIN2)
        f.grant("o", "admin", ADMIN2, ADMIN1)
        f.grant("o", "r", BOB, ADMIN1)
        self.assertFalse(f.engine.evaluate("o", "r", BOB))

    def test_depth_cap_rejects_overlong_chain(self) -> None:
        f = _Fixture(max_depth=10)
        ids = [bytes([i]) * HASH_SIZE for i in range(1, 17)]
        for child, parent in zip(ids[1:], ids[:-1]):
            f.grant("o", "admin", child, parent)
        f.grant("o", "r", BOB, ids[-1])
        self.assertFalse(f.engine.evaluate("o", "r", BOB))

    def test_valid_chain_within_depth_is_allowed(self) -> None:
        f = _Fixture(max_depth=10)
        a = bytes([10]) * HASH_SIZE
        b = bytes([20]) * HASH_SIZE
        f.grant("o", "admin", a, ROOT)
        f.grant("o", "admin", b, a)
        f.grant("o", "read", BOB, b)
        self.assertTrue(f.engine.evaluate("o", "read", BOB))


class MultiSaltTest(unittest.TestCase):
    def test_legacy_salt_tuple_still_matches(self) -> None:
        # A grant hashed under a legacy salt must still authorize when that salt
        # is configured as a Legacy Salt (§10). The grant is hashed with the
        # legacy hasher; the engine matches it via the configured legacy salt.
        legacy = bytes(reversed(range(SALT_SIZE)))
        legacy_hasher = NamespaceHasher(legacy)
        f = _Fixture(primary_salt=SALT, legacy_salts=(legacy,))
        f.state.apply(
            Operation(
                tuple=Tuple.from_plaintext(
                    object_id="sensor:wind", relation="calibrate",
                    grantee=BOB, issuer=ROOT, hasher=legacy_hasher,
                ),
                action=Action.GRANT,
                hlc=pack(1_700_000_000_000, 0),
            ),
            now_ms=1_700_000_000_000,
        )
        self.assertTrue(f.engine.evaluate("sensor:wind", "calibrate", BOB))

    def test_request_matches_under_either_primary_or_legacy(self) -> None:
        legacy = bytes(reversed(range(SALT_SIZE)))
        legacy_hasher = NamespaceHasher(legacy)
        # Primary salt in the config is SALT; legacy salt differs.
        f = _Fixture(primary_salt=SALT, legacy_salts=(legacy,))
        # Grant hashed under the LEGACY salt directly into the state.
        f.state.apply(
            Operation(
                tuple=Tuple.from_plaintext(
                    object_id="sensor:wind", relation="calibrate",
                    grantee=BOB, issuer=ROOT, hasher=legacy_hasher,
                ),
                action=Action.GRANT,
                hlc=pack(1_700_000_000_000, 0),
            ),
            now_ms=1_700_000_000_000,
        )
        self.assertTrue(f.engine.evaluate("sensor:wind", "calibrate", BOB))


class ThresholdIssuerTest(unittest.TestCase):
    def test_threshold_group_admin(self) -> None:
        # A 1-of-2 threshold group is a root anchor and may delegate.
        g = ThresholdGroup((ADMIN1, ADMIN2), 1)
        f = _Fixture(threshold_groups=(g,))
        # Re-point the root anchor set at the group for this fixture.
        f.engine.config = Config(
            root_trust_anchors=frozenset({g.group_id}),
            primary_salt=SALT,
            threshold_groups=(g,),
        )
        f.grant("sensor:wind", "calibrate", BOB, g.group_id)
        self.assertTrue(f.engine.evaluate("sensor:wind", "calibrate", BOB))


if __name__ == "__main__":
    unittest.main()
