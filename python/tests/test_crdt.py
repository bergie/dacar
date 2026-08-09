"""Smoketests for the LWW-Element-Set CRDT (§6) and GC (§9)."""

from __future__ import annotations

import unittest
import warnings

from dacar.crdt import DEFAULT_DELETION_HORIZON_DAYS, StateVector, TrustedLocalOnlyWarning
from dacar.hlc import pack, unpack
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.operation import Action, Operation
from dacar.tuple import Tuple

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
ISSUER = bytes(range(HASH_SIZE))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
BASE_MS = 1_700_000_000_000
_DAY_MS = 24 * 60 * 60 * 1000


def _op(
    object_id: str = "sensor:wind",
    relation: str = "calibrate",
    action: Action = Action.GRANT,
    ms: int = BASE_MS,
    logical: int = 0,
) -> Operation:
    return Operation(
        tuple=Tuple.from_plaintext(
            object_id=object_id, relation=relation, grantee=GRANTEE, issuer=ISSUER, hasher=HASHER
        ),
        action=action,
        hlc=pack(ms, logical),
    )


class ApplyTest(unittest.TestCase):
    def test_grant_activates(self) -> None:
        state = StateVector()
        self.assertTrue(state.apply(_op(), now_ms=BASE_MS))
        self.assertTrue(state.is_active(_op().tuple.hash()))

    def test_revoke_deactivates(self) -> None:
        state = StateVector()
        state.apply(_op(), now_ms=BASE_MS)
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS + 1), now_ms=BASE_MS + 1)
        self.assertFalse(state.is_active(_op().tuple.hash()))

    def test_lww_tie_remove_wins(self) -> None:
        state = StateVector()
        state.apply(_op(ms=BASE_MS, logical=5), now_ms=BASE_MS)
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=5), now_ms=BASE_MS)
        self.assertFalse(state.is_active(_op().tuple.hash()))

    def test_older_does_not_override_newer(self) -> None:
        state = StateVector()
        state.apply(_op(ms=BASE_MS, logical=5), now_ms=BASE_MS)
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=1), now_ms=BASE_MS)
        self.assertTrue(state.is_active(_op().tuple.hash()))


class IntakeRejectionTest(unittest.TestCase):
    def test_future_rejected(self) -> None:
        state = StateVector()
        far_future = _op(ms=BASE_MS + 365 * _DAY_MS)
        self.assertFalse(state.apply(far_future, now_ms=BASE_MS))
        self.assertEqual(len(state), 0)

    def test_intake_rejection_for_stale_delta(self) -> None:
        # §9: a Delta older than the horizon is discarded outright.
        state = StateVector(deletion_horizon_days=180)
        stale = _op(ms=BASE_MS - 181 * _DAY_MS)
        self.assertFalse(state.apply(stale, now_ms=BASE_MS))
        self.assertEqual(len(state), 0)

    def test_delta_within_horizon_accepted(self) -> None:
        state = StateVector(deletion_horizon_days=180)
        ok = _op(ms=BASE_MS - 100 * _DAY_MS)
        self.assertTrue(state.apply(ok, now_ms=BASE_MS))
        self.assertEqual(len(state), 1)


class PruneTest(unittest.TestCase):
    def test_pairwise_pruning_deletes_inactive_old_pair(self) -> None:
        state = StateVector(deletion_horizon_days=180)
        h = _op().tuple.hash()
        state.apply(_op(ms=BASE_MS, logical=1), now_ms=BASE_MS)
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=2), now_ms=BASE_MS)
        self.assertFalse(state.is_active(h))
        # Both timestamps are far older than the horizon.
        pruned = state.prune(now_ms=BASE_MS + 365 * _DAY_MS)
        self.assertEqual(pruned, 1)
        self.assertNotIn(h, state)

    def test_active_grants_are_never_pruned(self) -> None:
        state = StateVector(deletion_horizon_days=180)
        h = _op().tuple.hash()
        state.apply(_op(ms=BASE_MS), now_ms=BASE_MS)
        # Active and old, but never revoked -> must survive (§9 constraint note).
        pruned = state.prune(now_ms=BASE_MS + 365 * _DAY_MS)
        self.assertEqual(pruned, 0)
        self.assertTrue(state.is_active(h))

    def test_recent_revocation_not_pruned(self) -> None:
        state = StateVector(deletion_horizon_days=180)
        h = _op().tuple.hash()
        state.apply(_op(ms=BASE_MS), now_ms=BASE_MS)
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS + 10 * _DAY_MS), now_ms=BASE_MS + 10 * _DAY_MS)
        # Remove is within the horizon -> keep.
        pruned = state.prune(now_ms=BASE_MS + 20 * _DAY_MS)
        self.assertEqual(pruned, 0)


class MergeTest(unittest.TestCase):
    def test_merge_takes_max_per_set(self) -> None:
        a, b = StateVector(), StateVector()
        a.apply(_op(ms=BASE_MS, logical=1), now_ms=BASE_MS)
        b.apply(_op(ms=BASE_MS, logical=3), now_ms=BASE_MS)
        a.merge(b)
        entry = a.get(_op().tuple.hash())
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.add_ts, pack(BASE_MS, 3))

    def test_merge_is_commutative(self) -> None:
        a, b = StateVector(), StateVector()
        a.apply(_op(ms=BASE_MS, logical=1), now_ms=BASE_MS)
        a.apply(_op(action=Action.REVOKE, ms=BASE_MS, logical=2), now_ms=BASE_MS)
        b.apply(_op(ms=BASE_MS, logical=3), now_ms=BASE_MS)
        h = _op().tuple.hash()
        x = StateVector(); x.apply(_op(ms=BASE_MS, logical=1), now_ms=BASE_MS)
        x.merge(a); x.merge(b)
        y = StateVector(); y.apply(_op(ms=BASE_MS, logical=1), now_ms=BASE_MS)
        y.merge(b); y.merge(a)
        self.assertEqual(x.is_active(h), y.is_active(h))


class SerializationTest(unittest.TestCase):
    def test_roundtrip(self) -> None:
        state = StateVector()
        state.apply(_op(object_id="sensor:wind:north", relation="read"), now_ms=BASE_MS)
        state.apply(_op(object_id="sensor:wind", relation="-write", ms=BASE_MS + 1), now_ms=BASE_MS + 1)
        # to_payload()/from_payload() are trusted-local snapshot primitives
        # (see TrustedLocalOnlyWarning); silence the warning for this genuine
        # local round-trip.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=TrustedLocalOnlyWarning)
            restored = StateVector.from_payload(state.to_payload())
        self.assertEqual(len(restored), len(state))
        for t in state.active_tuples():
            self.assertTrue(restored.is_active(t.hash()))


class IterEntriesTest(unittest.TestCase):
    """iter_entries() exposes active AND revoked tombstones for inspection tools."""

    def test_yields_active_and_revoked_with_timestamps(self) -> None:
        state = StateVector()
        state.apply(_op(ms=BASE_MS), now_ms=BASE_MS)
        state.apply(_op(action=Action.REVOKE, ms=BASE_MS + 1), now_ms=BASE_MS + 1)
        entries = list(state.iter_entries())
        self.assertEqual(len(entries), 1)
        tup, add_ts, remove_ts = entries[0]
        self.assertEqual(tup, _op().tuple)
        self.assertIsNotNone(add_ts)
        self.assertIsNotNone(remove_ts)
        self.assertGreater(remove_ts, add_ts)

    def test_active_tuples_subset_of_iter_entries(self) -> None:
        state = StateVector()
        state.apply(_op(object_id="sensor:wind"), now_ms=BASE_MS)
        state.apply(_op(object_id="sensor:temp", ms=BASE_MS + 1), now_ms=BASE_MS + 1)
        state.apply(
            _op(object_id="sensor:temp", action=Action.REVOKE, ms=BASE_MS + 2),
            now_ms=BASE_MS + 2,
        )
        active_hashes = {t.hash() for t in state.active_tuples()}
        all_hashes = {t.hash() for (t, _a, _r) in state.iter_entries()}
        self.assertLessEqual(active_hashes, all_hashes)
        self.assertEqual(len(all_hashes), 2)
        self.assertEqual(len(active_hashes), 1)


if __name__ == "__main__":
    unittest.main()
