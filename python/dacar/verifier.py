"""Verify-on-ingest: authenticating network Deltas by Ed25519 signature.

The CRDT update itself (:meth:`dacar.crdt.StateVector.apply`) is a *pure*
mutation that trusts its caller; it deliberately performs no cryptography so
the layering stays simple and the hot path stays fast. Network-received Deltas
instead enter the state through :meth:`StateVector.ingest`, which **must**
authenticate each Operation against the claimed Issuer's public key(s) before it
is allowed to mutate state (spec §11.2.4: *"The signature remains the sole
source of authorization authenticity"*).

This module bridges an Issuer hash to the public-key material needed to verify
it:

* :class:`IssuerKeyset` -- M public keys + a threshold (1 for a single identity,
  N for a Threshold Group, §4.1).
* :class:`KeyResolver`  -- ``issuer_hash(16) -> IssuerKeyset | None``.
* :class:`Keyring`      -- a dict-backed resolver for offline / test use.
* :func:`verify_operation` -- resolve + verify, returning a plain bool.

Authentication is *not* authorization. Verifying a signature proves the
Operation was genuinely issued by the claimed Issuer; whether that Issuer is
itself authorized (i.e. its authority traces to a Root Trust Anchor) is resolved
later by the Evaluation Engine (§7) against the converged CRDT state. Because
Deltas arrive out of order over an eventually-consistent mesh, full authority
chains often cannot be checked at ingest time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple as _Tuple

from dacar.operation import Operation

#: Resolves a 16-byte Issuer hash to its verification keyset, or ``None`` when
#: the Issuer is unknown (the Operation is then rejected as unverifiable).
KeyResolver = Callable[[bytes], "Optional[IssuerKeyset]"]

#: Ed25519 public keys are 32 raw bytes.
_PUBLIC_KEY_SIZE = 32


@dataclass(frozen=True)
class IssuerKeyset:
    """Public-key material needed to verify an Operation from one Issuer.

    A single-identity Issuer has ``threshold == 1`` and one member key; a
    Threshold Group Issuer (§4.1) has ``threshold == N`` and ``M >= N`` member
    keys. Either form is consumed directly by
    :meth:`Operation.verify_threshold`.
    """

    #: One public key (single identity) or M public keys (group), as raw
    #: 32-byte Ed25519 public keys.
    member_public_keys: _Tuple[bytes, ...]
    #: Consensus threshold N (1 for a single identity).
    threshold: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.threshold, int) or self.threshold < 1:
            raise ValueError("threshold must be a positive integer")
        keys = []
        for k in self.member_public_keys:
            if not isinstance(k, (bytes, bytearray)) or len(k) != _PUBLIC_KEY_SIZE:
                raise ValueError(
                    f"Ed25519 public keys are {_PUBLIC_KEY_SIZE} raw bytes, got {k!r}"
                )
            keys.append(bytes(k))
        if len(keys) < self.threshold:
            raise ValueError("need at least `threshold` member public keys")
        object.__setattr__(self, "member_public_keys", tuple(keys))

    @classmethod
    def single(cls, public_key: Any) -> "IssuerKeyset":
        """Keyset for a single-identity Issuer (threshold 1)."""
        return cls((public_key,), 1)

    @classmethod
    def group(cls, member_public_keys: Sequence[Any], threshold: int) -> "IssuerKeyset":
        """Keyset for an N-of-M Threshold Group Issuer (§4.1)."""
        return cls(tuple(member_public_keys), threshold)


class Keyring:
    """A dict-backed :data:`KeyResolver` for offline and test use.

    Production nodes will typically back this with RNS Identity resolution
    (querying the network for the public key behind a 16-byte Identity hash);
    this in-memory implementation is sufficient for single-node reference
    deployments, air-gapped sneakernet, and the test suite.
    """

    def __init__(self, mapping: "Optional[Mapping[bytes, IssuerKeyset]]" = None) -> None:
        self._map: "dict[bytes, IssuerKeyset]" = {}
        if mapping:
            for k, v in mapping.items():
                self.register(bytes(k), v)

    def register(self, issuer_hash: bytes, keyset: IssuerKeyset) -> "Keyring":
        """Map a 16-byte Issuer hash to its :class:`IssuerKeyset`."""
        self._map[bytes(issuer_hash)] = keyset
        return self

    def register_single(self, issuer_hash: bytes, public_key: Any) -> "Keyring":
        return self.register(issuer_hash, IssuerKeyset.single(public_key))

    def register_group(
        self, group_id: bytes, member_public_keys: Sequence[Any], threshold: int
    ) -> "Keyring":
        return self.register(group_id, IssuerKeyset.group(member_public_keys, threshold))

    def resolve(self, issuer_hash: bytes) -> "Optional[IssuerKeyset]":
        return self._map.get(bytes(issuer_hash))

    def __call__(self, issuer_hash: bytes) -> "Optional[IssuerKeyset]":
        # Make a Keyring directly usable as a KeyResolver callable.
        return self.resolve(issuer_hash)


def verify_operation(operation: Operation, resolver: KeyResolver) -> bool:
    """Authenticate one Operation against its claimed Issuer (§5.2, §11.2.4).

    Returns ``True`` iff the Issuer hash is known to ``resolver`` *and* the
    Operation carries a valid threshold signature from the resolved keyset. An
    unknown Issuer or any cryptographic failure yields ``False`` -- the
    Operation MUST be dropped rather than merged.
    """
    keyset = resolver(bytes(operation.issuer))
    if keyset is None:
        return False
    return operation.verify_keyset(keyset)
