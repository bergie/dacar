"""The evaluation engine (§7).

Resolves a plaintext request ``(Object, Relation, Grantee)`` against the local
CRDT state and the recursive delegation graph, terminating at a Root Trust
Anchor.

Resolution rules (§7.3):

  1. If any valid active Deny Tuple exists, the request is **DENIED**.
  2. Else if any valid active Allow Tuple exists, the request is **ALLOWED**.
  3. Else the request is **DENIED**.

"Valid" means the granting Issuer's authority traces back to a Root Trust
Anchor (directly, or recursively via the reserved ``admin`` relation).

Namespace Label Privacy (§3.3) means the engine never compares plaintext
labels: it hashes the request with every configured salt (Primary + Legacy,
§10.2) and matches the resulting byte arrays against the hashed Tuples in the
state. The total-work bound (§7.2) is enforced *per request across all salt
tracks simultaneously* (§10.2).

The core resolver also accepts pre-hashed hypotheses (:meth:`evaluate_hashes`),
which the Strict Consistency Challenge server (§8) uses to evaluate a request
that arrives already hashed, without ever recovering plaintext.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Sequence, Tuple as _Tuple

from dacar.config import Config
from dacar.crdt import StateVector
from dacar.namespace import NamespaceHasher, covers
from dacar.tuple import Tuple

#: Maximum delegation hops in a single evaluation path (§7.2).
DEFAULT_MAX_DEPTH = 10
#: Maximum evaluation steps (visited nodes) per request (§7.2).
DEFAULT_MAX_VISITED = 50

#: The reserved relation that confers the authority to delegate (§3.2).
ADMIN_RELATION = "admin"

#: A per-salt hypothesis: (hasher, object_hashes, allow_rel_hash, deny_rel_hash).
Hypothesis = _Tuple[NamespaceHasher, _Tuple[bytes, ...], bytes, bytes]


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
        """Return True if ``(object_id, relation, grantee)`` is ALLOWED.

        Hashes the plaintext request with every configured salt (§7.1, §10.2)
        and delegates to :meth:`evaluate_hashes`.
        """
        hypotheses: List[Hypothesis] = []
        for hasher in self.config.hashers:
            obj_hashes, _wildcard = hasher.hash_object(object_id)
            hypotheses.append(
                (
                    hasher,
                    obj_hashes,
                    hasher.hash_relation(relation),
                    hasher.hash_relation("-" + relation),
                )
            )
        return self.evaluate_hashes(grantee, hypotheses)

    def evaluate_hashes(self, grantee: bytes, hypotheses: Sequence[Hypothesis]) -> bool:
        """Evaluate pre-hashed per-salt hypotheses (§7.3, §10.2).

        ``hypotheses`` is one ``(hasher, object_hashes, allow_rel_hash,
        deny_rel_hash)`` per salt. The total-work bound is shared across all
        hypotheses. Returns True iff resolution yields ALLOW.
        """
        # Index active tuples by grantee for this request.
        index: Dict[bytes, List[Tuple]] = defaultdict(list)
        for t in self.state.active_tuples():
            index[t.grantee].append(t)

        # Memo of positive authority results, keyed by (issuer, object identity
        # across salts). Only positives are cached (path-independent).
        memo: Dict[_Tuple[bytes, _Tuple[_Tuple[bytes, bytes], ...]], bool] = {}
        counter = [0]
        config = self.config
        max_depth = self.max_depth
        max_visited = self.max_visited

        def object_key(hyps: Sequence[Hypothesis]) -> _Tuple[_Tuple[bytes, bytes], ...]:
            return tuple((h.id_tag, oh) for (h, oh, _a, _d) in hyps)

        def authority(
            issuer: bytes, hyps: Sequence[Hypothesis], depth: int, visited: FrozenSet[bytes]
        ) -> bool:
            """Return True if ``issuer`` may delegate on the hypothesized object."""
            if config.is_root_anchor(issuer):  # §7.2 terminal trust anchor
                return True
            key = (issuer, object_key(hyps))
            cached = memo.get(key)
            if cached is not None:
                return cached
            if depth >= max_depth:  # §7.2 recursion depth bound
                return False
            if issuer in visited:  # §7.2 cycle detection
                return False
            admin_hyps: List[Hypothesis] = [
                (h, oh, h.hash_relation(ADMIN_RELATION), h.hash_relation("-" + ADMIN_RELATION))
                for (h, oh, _a, _d) in hyps
            ]
            result = (
                _resolve(admin_hyps, issuer, depth + 1, visited | {issuer}) == "allow"
            )
            if result:
                memo[key] = True
            return result

        def _resolve(
            hyps: Sequence[Hypothesis],
            grantee_id: bytes,
            depth: int,
            visited: FrozenSet[bytes],
        ) -> str:
            """Return ``"deny"`` / ``"allow"`` / ``"none"`` for hashed hypotheses."""
            counter[0] += 1
            if counter[0] > max_visited:  # §7.2 / §10.2 shared total-work bound
                return "none"
            deny_valid = False
            allow_valid = False
            for candidate in index.get(grantee_id, ()):
                for (_hasher, obj_hashes, allow_rh, deny_rh) in hyps:
                    if candidate.relation_hash == deny_rh:
                        if covers(candidate.object_hashes, candidate.wildcard, obj_hashes):
                            if authority(candidate.issuer, hyps, depth, visited):
                                deny_valid = True
                    elif candidate.relation_hash == allow_rh:
                        if covers(candidate.object_hashes, candidate.wildcard, obj_hashes):
                            if authority(candidate.issuer, hyps, depth, visited):
                                allow_valid = True
            if deny_valid:
                return "deny"
            if allow_valid:
                return "allow"
            return "none"

        return _resolve(tuple(hypotheses), grantee, 0, frozenset()) == "allow"
