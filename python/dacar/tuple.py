"""The authorization Tuple and its canonical hash (Dacar spec §3.1, §6.1).

A Tuple asserts that a specific Grantee holds a specific Relation over a
specific Object, as authorized by a specific Issuer::

    (Object, Relation, Grantee, Issuer)

To guarantee cross-language CRDT convergence the Tuple Hash is SHA-256 over a
packed binary pre-image::

    [16-byte Issuer] + [16-byte Grantee] + [1-byte Relation Length]
                    + [Relation (UTF-8)] + [Object (UTF-8)]
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

HASH_SIZE = 16  #: Length of an RNS.Identity hash, in bytes.
RELATION_MAX_LEN = 0xFF  #: Relations are length-prefixed by a single byte.


@dataclass(frozen=True)
class Tuple:
    """A single authorization relationship."""

    object: str
    relation: str
    grantee: bytes  #: 16-byte RNS.Identity hash of the permission holder.
    issuer: bytes  #: 16-byte RNS.Identity hash of the signing administrator.

    def __post_init__(self) -> None:
        rel_len = len(self.relation.encode("utf-8"))
        if len(self.grantee) != HASH_SIZE:
            raise ValueError(f"grantee must be {HASH_SIZE} bytes, got {len(self.grantee)}")
        if len(self.issuer) != HASH_SIZE:
            raise ValueError(f"issuer must be {HASH_SIZE} bytes, got {len(self.issuer)}")
        if rel_len > RELATION_MAX_LEN:
            raise ValueError(f"relation too long ({rel_len} > {RELATION_MAX_LEN} bytes)")

    def preimage(self) -> bytes:
        """Return the canonical binary pre-image over which the hash is taken."""
        relation = self.relation.encode("utf-8")
        return (
            self.issuer
            + self.grantee
            + len(relation).to_bytes(1, "big")
            + relation
            + self.object.encode("utf-8")
        )

    def hash(self) -> bytes:
        """Return the 32-byte SHA-256 Tuple Hash."""
        return hashlib.sha256(self.preimage()).digest()
