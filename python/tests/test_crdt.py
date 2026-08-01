"""Smoketests for the LWW-Element-Set CRDT (§6)."""

from __future__ import annotations

import unittest

from dacar.crdt import StateVector
from dacar.hlc import pack
from dacar.operation import Action, Operation
from dacar.tuple import HASH_SIZE, Tuple

ISSUER = bytes(range(HASH_SIZE))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
BASE_MS = 1_700_000_000_000


def _op(
    object_id: str = "sensor:wind",
    relation: str = "calibrate",
    action: Action = Action.GRANT,
    ms: int = BASE_MS,
    logical: int = 0,
) -> Operation:
    return Operation(
        tuple=Tuple(object_id, relation, GRANTEE, ISSUER),
        action=action,
        hlc=pack(ms, logical),
    )


class ApplyTest(unittest.TestCase):
    def test_grant_activates(self) -> None:
        state = StateVector()
        self.assertTrue(state.apply(_op()))
        self.assertTrue(state.is_active(_op().tuple.hash()))

    def test_revoke_deactivates(self) -> None:
        state = StateVector()
        state.apply(_op())
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS + 1))
        self.assertFalse(state.is_active(_op().tuple.hash()))

    def test_lww_tie_remove_wins(self) -> None:
        # Equal add/remove timestamps => revoked (Remove wins, §6.2).
        state = StateVector()
        state.apply(_op(ms=BASE_MS, logical=5))
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=5))
        self.assertFalse(state.is_active(_op().tuple.hash()))

    def test_older_does_not_override_newer(self) -> None:
        state = StateVector()
        state.apply(_op(ms=BASE_MS, logical=5))
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=1))  # older revoke
        self.assertTrue(state.is_active(_op().tuple.hash()))

    def test_future_rejected(self) -> None:
        state = StateVector()
        far_future = _op(ms=BASE_MS + 365 * 24 * 3600 * 1000)  # ~1 year ahead
        self.assertFalse(state.apply(far_future, now_ms=BASE_MS))
        self.assertEqual(len(state), 0)


class MergeTest(unittest.TestCase):
    def test_merge_takes_max_per_set(self) -> None:
        a, b = StateVector(), StateVector()
        a.apply(_op(ms=BASE_MS, logical=1))
        b.apply(_op(ms=BASE_MS, logical=3))  # newer add
        a.merge(b)
        entry = a.get(_op().tuple.hash())
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.add_ts, pack(BASE_MS, 3))

    def test_merge_is_commutative(self) -> None:
        a, b = StateVector(), StateVector()
        a.apply(_op(ms=BASE_MS, logical=1))
        a.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=2))
        b.apply(_op(ms=BASE_MS, logical=3))
        # Merge both orders; final active state must match.
        x = StateVector()
        x.apply(_op(ms=BASE_MS, logical=1))
        x.merge(a)
        x.merge(b)
        y = StateVector()
        y.apply(_op(ms=BASE_MS, logical=1))
        y.merge(b)
        y.merge(a)
        self.assertEqual(x.is_active(_op().tuple.hash()), y.is_active(_op().tuple.hash()))


class SerializationTest(unittest.TestCase):
    def test_roundtrip(self) -> None:
        state = StateVector()
        state.apply(_op(object_id="sensor:wind:north", relation="read"))
        state.apply(_op(object_id="sensor:wind", relation="-write", ms=BASE_MS + 1))
        restored = StateVector.from_payload(state.to_payload())
        self.assertEqual(len(restored), len(state))
        for t in state.active_tuples():
            self.assertTrue(restored.is_active(t.hash()))


if __name__ == "__main__":
    unittest.main()
