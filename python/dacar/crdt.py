"""The authorization state: an LWW-Element-Set CRDT (§6).

The global state maps a Tuple Hash to an HLC timestamp, split into an Add set
and a Remove set (classic LWW-Element-Set). A Tuple is *active* iff it has an
Add timestamp strictly greater than its Remove timestamp; ties resolve to
removed (Remove wins, §6.1).

Storage is bounded by **Time-Horizon Tombstone Pruning** (§9): once a tuple has
been resolved inactive *and* both its Add and Remove timestamps are older than
the deletion horizon, both entries are silently deleted. Incoming Operations
older than the horizon are rejected outright (intake rejection, §9).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from dacar import serialization
from dacar.hlc import MAX_HLC, physical_now_ms, unpack
from dacar.operation import Action, Operation
from dacar.tuple import Tuple

#: Operations more than this far in the future are rejected (§12 timestamp skew).
_MS_PER_DAY = 24 * 60 * 60 * 1000
DEFAULT_MAX_FUTURE_MS: Optional[int] = _MS_PER_DAY
#: Default deletion horizon H for Time-Horizon Tombstone Pruning (§9).
DEFAULT_DELETION_HORIZON_DAYS = 180


@dataclass
class _Entry:
    """An LWW-Element-Set entry: one Tuple with separate add/remove clocks."""

    tuple: Tuple
    add_ts: Optional[int] = None
    remove_ts: Optional[int] = None

    def active(self) -> bool:
        return self.add_ts is not None and (
            self.remove_ts is None or self.add_ts > self.remove_ts
        )


def _max(existing: Optional[int], incoming: int) -> int:
    return incoming if existing is None else max(existing, incoming)


class StateVector:
    """A replicated authorization state.

    Tuples are indexed by their canonical Tuple Hash (§6.1). Mutations arrive
    as signed Operations; merges take the maximum HLC for every known Tuple
    Hash independently in each set.
    """

    def __init__(self, deletion_horizon_days: int = DEFAULT_DELETION_HORIZON_DAYS) -> None:
        self._entries: Dict[bytes, _Entry] = {}
        self.deletion_horizon_days = deletion_horizon_days

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, tuple_hash: bytes) -> bool:
        return tuple_hash in self._entries

    @property
    def deletion_horizon_ms(self) -> int:
        return self.deletion_horizon_days * _MS_PER_DAY

    # -- single-delta application (§6.1) -------------------------------------
    def apply(
        self,
        operation: Operation,
        *,
        now_ms: Optional[int] = None,
        max_future_ms: Optional[int] = DEFAULT_MAX_FUTURE_MS,
    ) -> bool:
        """Apply one Operation (Delta) to the appropriate set.

        Returns True if applied, False if rejected. An Operation is rejected
        when it projects too far into the future (§12) or is older than the
        deletion horizon (§9 intake rejection). The Operation's signature(s)
        are assumed already verified by the caller; this method performs the
        pure CRDT update.
        """
        physical, _ = unpack(operation.hlc)
        now = now_ms if now_ms is not None else physical_now_ms()
        if max_future_ms is not None and physical > now + max_future_ms:
            return False  # §12 timestamp manipulation mitigation
        if physical < now - self.deletion_horizon_ms:
            return False  # §9 intake rejection
        entry = self._entries.get(operation.tuple.hash())
        if entry is None:
            entry = _Entry(tuple=operation.tuple)
            self._entries[operation.tuple.hash()] = entry
        if operation.action == Action.GRANT:
            entry.add_ts = _max(entry.add_ts, operation.hlc)
        else:
            entry.remove_ts = _max(entry.remove_ts, operation.hlc)
        return True

    # -- full-state merge (§6.1) --------------------------------------------
    def merge(self, other: "StateVector") -> None:
        """Merge another StateVector by taking the max HLC per set per tuple."""
        for th, other_entry in other._entries.items():
            entry = self._entries.get(th)
            if entry is None:
                entry = _Entry(tuple=other_entry.tuple)
                self._entries[th] = entry
            if other_entry.add_ts is not None:
                entry.add_ts = _max(entry.add_ts, other_entry.add_ts)
            if other_entry.remove_ts is not None:
                entry.remove_ts = _max(entry.remove_ts, other_entry.remove_ts)

    # -- garbage collection (§9) --------------------------------------------
    def prune(self, *, now_ms: Optional[int] = None) -> int:
        """Run Time-Horizon Tombstone Pruning (§9).

        Deletes *both* the Add and Remove entries for any tuple that currently
        resolves to inactive *and* whose Add and Remove timestamps are both
        older than the deletion horizon. Returns the number of tuples pruned.
        Pruning never alters the resolved access state or destroys active
        re-grants.
        """
        now = now_ms if now_ms is not None else physical_now_ms()
        cutoff = now - self.deletion_horizon_ms
        dead: List[bytes] = []
        for th, entry in self._entries.items():
            if entry.active():
                continue
            a, r = entry.add_ts, entry.remove_ts
            if a is None or r is None:
                continue
            if unpack(a)[0] < cutoff and unpack(r)[0] < cutoff:
                dead.append(th)
        for th in dead:
            del self._entries[th]
        return len(dead)

    # -- queries -------------------------------------------------------------
    def get(self, tuple_hash: bytes) -> Optional[_Entry]:
        return self._entries.get(tuple_hash)

    def is_active(self, tuple_hash: bytes) -> bool:
        entry = self._entries.get(tuple_hash)
        return entry.active() if entry is not None else False

    def active_tuples(self) -> Iterator[Tuple]:
        """Yield every currently active Tuple."""
        for entry in self._entries.values():
            if entry.active():
                yield entry.tuple

    # -- state-vector serialization (for sync) ------------------------------
    def to_payload(self) -> bytes:
        """Serialize the full state vector as a MessagePack array of entries.

        Each entry is ``[relation_hash(16), [object_hashes], wildcard_bool,
        grantee(16), issuer(16), add_ts | nil, remove_ts | nil]``. The Tuple
        Hash is recoverable from the first five fields, so it is not stored.
        """
        rows = []
        for entry in self._entries.values():
            rows.append(
                [
                    entry.tuple.relation_hash,
                    list(entry.tuple.object_hashes),
                    entry.tuple.wildcard,
                    entry.tuple.grantee,
                    entry.tuple.issuer,
                    entry.add_ts,
                    entry.remove_ts,
                ]
            )
        return serialization.packb(rows)

    @classmethod
    def from_payload(
        cls, data: bytes, deletion_horizon_days: int = DEFAULT_DELETION_HORIZON_DAYS
    ) -> "StateVector":
        """Deserialize a state vector produced by :meth:`to_payload`."""
        rows = serialization.unpackb(data)
        if not isinstance(rows, list):
            raise ValueError("state vector payload must be a MessagePack array")
        state = cls(deletion_horizon_days=deletion_horizon_days)
        for row in rows:
            if not isinstance(row, (list, tuple)) or len(row) != 7:
                raise ValueError("each state entry must be a 7-element array")
            relation_hash, object_hashes, wildcard, grantee, issuer, add_ts, remove_ts = row
            for name, blob in (
                ("relation_hash", relation_hash),
                ("grantee", grantee),
                ("issuer", issuer),
            ):
                if not isinstance(blob, (bytes, bytearray)) or len(blob) != 16:
                    raise ValueError(f"{name} must be a 16-byte binary blob")
            if not isinstance(object_hashes, (list, tuple)):
                raise ValueError("object_hashes must be an array of 16-byte blobs")
            for h in object_hashes:
                if not isinstance(h, (bytes, bytearray)) or len(h) != 16:
                    raise ValueError("each object segment hash must be 16 bytes")
            if not isinstance(wildcard, bool):
                raise ValueError("wildcard must be a bool")
            for ts in (add_ts, remove_ts):
                if ts is not None and (not isinstance(ts, int) or not 0 <= ts <= MAX_HLC):
                    raise ValueError("timestamps must be uint64 or nil")
            entry = _Entry(
                tuple=Tuple(
                    relation_hash=bytes(relation_hash),
                    object_hashes=tuple(bytes(h) for h in object_hashes),
                    wildcard=wildcard,
                    grantee=bytes(grantee),
                    issuer=bytes(issuer),
                ),
                add_ts=add_ts,
                remove_ts=remove_ts,
            )
            state._entries[entry.tuple.hash()] = entry
        return state
