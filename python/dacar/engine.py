"""The evaluation engine (§7).

Resolves a request ``(Object, Relation, Grantee)`` against the local CRDT
state and the recursive delegation graph, terminating at a Root Trust Anchor.

Resolution rules (§7.3):

  1. If any valid active Deny tuple exists, the request is DENIED.
  2. Else if any valid active Allow tuple exists, the request is ALLOWED.
  3. Else the request is DENIED.

"Valid" means the granting Issuer's authority traces back to a Root Trust
Anchor (directly, or recursively via the reserved ``admin`` relation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List

from dacar.config import Config
from dacar.crdt import StateVector
from dacar.namespace import permutations
from dacar.tuple import Tuple

#: Maximum delegation hops in a single evaluation path (§7.2).
DEFAULT_MAX_DEPTH = 10
#: Maximum evaluation steps (visited nodes) per request (§7.2).
DEFAULT_MAX_VISITED = 50

#: The reserved relation that confers the authority to delegate (§3.2).
ADMIN_RELATION = "admin"


class Engine:
    """Local authorization evaluator bound to a Config and a StateVector."""

    def __init__(
        self,
        config: Config,
        state: StateVector,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_visited: int = DEFAULT_MAX_VISITED,
    ) -> None:
        self.config = config
        self.state = state
        self.max_depth = max_depth
        self.max_visited = max_visited

    def evaluate(self, object_id: str, relation: str, grantee: bytes) -> bool:
        """Return True if ``(object_id, relation, grantee)`` is ALLOWED."""
        index: Dict[bytes, List[Tuple]] = {}
        for t in self.state.active_tuples():
            index.setdefault(t.grantee, []).append(t)

        memo: Dict[FrozenSet, bool] = {}
        counter = [0]

        def resolve(obj: str, rel: str, grantee_id: bytes, depth: int, visited: FrozenSet[bytes]) -> str:
            """Return ``"deny"`` / ``"allow"`` / ``"none"`` for a sub-request."""
            counter[0] += 1
            if counter[0] > self.max_visited:
                return "none"  # §7.2 total work bound
            patterns = frozenset(permutations(obj))
            deny_relation = "-" + rel
            deny_valid = False
            allow_valid = False
            for candidate in index.get(grantee_id, ()):
                if candidate.object not in patterns:
                    continue
                if candidate.relation == deny_relation:
                    if authority(candidate.issuer, obj, depth, visited):
                        deny_valid = True
                elif candidate.relation == rel:
                    if authority(candidate.issuer, obj, depth, visited):
                        allow_valid = True
            if deny_valid:
                return "deny"
            if allow_valid:
                return "allow"
            return "none"

        def authority(issuer: bytes, obj: str, depth: int, visited: FrozenSet[bytes]) -> bool:
            """Return True if ``issuer`` may delegate on ``obj``."""
            # §7.2: a Root Trust Anchor terminates the chain successfully.
            if self.config.is_root_anchor(issuer):
                return True
            key = (issuer, obj)
            cached = memo.get(key)
            if cached is not None:
                return cached
            if depth >= self.max_depth:
                return False  # §7.2 recursion depth bound
            if issuer in visited:
                return False  # §7.2 cycle detection
            # Only positive results are memoized: they are path-independent,
            # whereas a negative result may simply reflect an ancestor cycle.
            result = resolve(obj, ADMIN_RELATION, issuer, depth + 1, visited | {issuer}) == "allow"
            if result:
                memo[key] = True
            return result

        return resolve(object_id, relation, grantee, 0, frozenset()) == "allow"
