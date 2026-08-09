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

import warnings
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from dacar import serialization
from dacar.hlc import MAX_HLC, physical_now_ms, unpack
from dacar.operation import Action, Operation
from dacar.tuple import Tuple
from dacar.verifier import KeyResolver, verify_operation

#: Operations more than this far in the future are rejected (§12 timestamp skew).
_MS_PER_DAY = 24 * 60 * 60 * 1000
DEFAULT_MAX_FUTURE_MS: Optional[int] = _MS_PER_DAY
#: Default deletion horizon H for Time-Horizon Tombstone Pruning (§9).
DEFAULT_DELETION_HORIZON_DAYS = 180


class TrustedLocalOnlyWarning(UserWarning):
    """Emitted when a trusted-local-only CRDT API is exercised.

    ``StateVector.from_payload()`` / ``StateVector.merge()`` /
    ``StateVector.to_payload()`` are **snapshot/restore primitives for a node's
    own trusted state**. They carry and merge no Ed25519 signature material,
    so feeding them network bytes lets a peer forge arbitrary authorization
    state (including Root Trust Anchor grants) and silently bypass the §9
    stale-horizon and §12 future-skew intake checks that per-delta ingestion
    enforces.

    Network convergence MUST instead run each signed Operation through
    :meth:`StateVector.ingest` (single) or
    :meth:`dacar.delta.DeltaReceiver.apply_payloads` (batch). Silence this
    warning only for genuine local snapshot/restore of your own state::

        import warnings
        from dacar.crdt import TrustedLocalOnlyWarning
        warnings.filterwarnings("ignore", category=TrustedLocalOnlyWarning)
    """


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
    def ingest(
        self,
        operation: Operation,
        key_resolver: KeyResolver,
        *,
        now_ms: Optional[int] = None,
        max_future_ms: Optional[int] = DEFAULT_MAX_FUTURE_MS,
    ) -> bool:
        """Authenticate then apply a network-received Delta (§11.2.4, §5.2).

        This is the secure entry point for Operations received over any
        transport (RFed, LXMF, optical sneakernet). The Operation's Ed25519
        signature(s) MUST verify against the public key(s) resolved for its
        claimed Issuer before the pure CRDT update (:meth:`apply`) is allowed
        to mutate state. Any authentication failure -- unknown Issuer, bad
        signature, wrong threshold -- drops the Operation (returns ``False``).

        Returns ``True`` iff authenticated *and* applied. This is distinct from
        :meth:`apply`, which trusts its caller and performs no cryptography.
        """
        if not verify_operation(operation, key_resolver):
            return False
        return self.apply(operation, now_ms=now_ms, max_future_ms=max_future_ms)

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
        """Merge another StateVector by taking the max HLC per set per tuple.

        .. warning:: **Trusted-local-only — never feed network bytes.**

           ``merge()`` trusts its argument completely and performs **no**
           signature verification, so it can inject or alter authorization
           state (including Root Trust Anchor grants) for any tuple. It also
           skips the §9 stale-horizon and §12 future-skew intake checks that
           :meth:`apply`/ :meth:`ingest` enforce per-delta, so even a trusted
           source can silently reintroduce operations per-delta ingestion
           would have rejected.

           Legitimate uses are confined to a node's own trusted state:
           CRDT unit testing and restoring a snapshot previously produced by
           :meth:`to_payload` on the *same* node. For network convergence use
           :meth:`ingest` (single Delta) or
           :meth:`dacar.delta.DeltaReceiver.apply_payloads` (batch of signed
           Deltas) instead.
        """
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

    def iter_entries(self) -> "Iterator[Tuple, Optional[int], Optional[int]]":
        """Yield ``(tuple, add_ts, remove_ts)`` for *every* stored entry.

        Unlike :meth:`active_tuples`, this also exposes resolved (revoked)
        tombstones, which management/inspection tools need to list revoked
        tuples and their tombstone timestamps (e.g. ``grants --all``). Each
        item is ``(tuple, add_ts, remove_ts)`` where a ``None`` timestamp
        means that set has no entry for the tuple.
        """
        for entry in self._entries.values():
            yield entry.tuple, entry.add_ts, entry.remove_ts

    # -- state-vector serialization (for sync) ------------------------------
    def to_payload(self) -> bytes:
        """Serialize the full state vector as a MessagePack array of entries.

        .. warning:: **Trusted-local-only.** The payload is an unauthenticated
           dump of this node's CRDT and carries **no** Ed25519 signature
           material; it exists for a node to snapshot *its own* state (e.g. a
           local backup or CRDT unit test). It MUST NOT be accepted from the
           network — deserialize such bytes only via your own trusted store,
           and if it ever crosses a trust boundary use
           :meth:`dacar.delta.DeltaReceiver.apply_payloads` (a batch of signed
           §5.3 Operations) instead.

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
        """Deserialize a state vector produced by :meth:`to_payload`.

        .. warning:: **Trusted-local-only — never feed network bytes.**

           The payload carries **no** signature material, so deserializing
           attacker bytes and then :meth:`merge`-ing it lets a peer forge
           arbitrary authorization state (including Root Trust Anchor grants)
           and silently bypass the §9 stale-horizon and §12 future-skew intake
           checks. Only deserialize bytes from your own trusted store (a
           snapshot you previously produced with :meth:`to_payload` on this
           node). For network convergence use
           :meth:`dacar.delta.DeltaReceiver.apply_payloads` (a batch of signed
           §5.3 Operations) instead.

           A :class:`TrustedLocalOnlyWarning` is emitted to make this
           contract audible; filter it only for genuine local snapshot/restore.
        """
        warnings.warn(
            "StateVector.from_payload() is trusted-local-only: it performs no "
            "signature verification and must not be fed network bytes. For "
            "network convergence use DeltaReceiver.apply_payloads() instead.",
            TrustedLocalOnlyWarning,
            stacklevel=2,
        )
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
