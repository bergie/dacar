"""The authorization state: an LWW-Element-Set CRDT (§6).

The global state maps a Tuple Hash to an HLC timestamp, split into an Add set
and a Remove set (classic LWW-Element-Set). A Tuple is *active* iff it has an
Add timestamp strictly greater than its Remove timestamp; ties resolve to
removed (Remove wins).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, Optional

from dacar import serialization
from dacar.hlc import MAX_HLC, physical_now_ms, unpack
from dacar.operation import Action, Operation
from dacar.tuple import HASH_SIZE, Tuple

#: Operations more than this far in the future are rejected (§9 timestamp
#: manipulation mitigation).
_MS_PER_DAY = 24 * 60 * 60 * 1000
DEFAULT_MAX_FUTURE_MS: Optional[int] = _MS_PER_DAY


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

    def __init__(self) -> None:
        self._entries: Dict[bytes, _Entry] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, tuple_hash: bytes) -> bool:
        return tuple_hash in self._entries

    # -- single-delta application (§6.2) -------------------------------------
    def apply(
        self,
        operation: Operation,
        *,
        now_ms: Optional[int] = None,
        max_future_ms: Optional[int] = DEFAULT_MAX_FUTURE_MS,
    ) -> bool:
        """Apply one Operation (Delta) to the appropriate set.

        Returns True if applied, False if rejected as too far in the future
        (§9). The Operation's signature is assumed already verified by the
        caller; this method performs the pure CRDT update.
        """
        if max_future_ms is not None:
            now = now_ms if now_ms is not None else physical_now_ms()
            physical, _ = unpack(operation.hlc)
            if physical > now + max_future_ms:
                return False
        entry = self._entries.get(operation.tuple.hash())
        if entry is None:
            entry = _Entry(tuple=operation.tuple)
            self._entries[operation.tuple.hash()] = entry
        if operation.action == Action.GRANT:
            entry.add_ts = _max(entry.add_ts, operation.hlc)
        else:
            entry.remove_ts = _max(entry.remove_ts, operation.hlc)
        return True

    # -- full-state merge (§6.2) --------------------------------------------
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
        """Serialize the full state vector as a MessagePack array.

        Each entry is ``[object, relation, grantee, issuer, add_ts | nil,
        remove_ts | nil]``. Tuple identity (and thus hash) is recoverable from
        the first four fields, so the hash is not stored redundantly.
        """
        rows = []
        for entry in self._entries.values():
            rows.append(
                [
                    entry.tuple.object,
                    entry.tuple.relation,
                    entry.tuple.grantee,
                    entry.tuple.issuer,
                    entry.add_ts,
                    entry.remove_ts,
                ]
            )
        return serialization.packb(rows)

    @classmethod
    def from_payload(cls, data: bytes) -> "StateVector":
        """Deserialize a state vector produced by :meth:`to_payload`."""
        rows = serialization.unpackb(data)
        if not isinstance(rows, list):
            raise ValueError("state vector payload must be a MessagePack array")
        state = cls()
        for row in rows:
            if not isinstance(row, (list, tuple)) or len(row) != 6:
                raise ValueError("each state entry must be a 6-element array")
            obj, relation, grantee, issuer, add_ts, remove_ts = row
            if (
                not isinstance(grantee, (bytes, bytearray)) or len(grantee) != HASH_SIZE
                or not isinstance(issuer, (bytes, bytearray)) or len(issuer) != HASH_SIZE
            ):
                raise ValueError("grantee/issuer must be 16-byte binary blobs")
            for ts in (add_ts, remove_ts):
                if ts is not None and (not isinstance(ts, int) or not 0 <= ts <= MAX_HLC):
                    raise ValueError("timestamps must be uint64 or nil")
            entry = _Entry(
                tuple=Tuple(object=obj, relation=relation, grantee=bytes(grantee), issuer=bytes(issuer)),
                add_ts=add_ts,
                remove_ts=remove_ts,
            )
            state._entries[entry.tuple.hash()] = entry
        return state
