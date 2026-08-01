"""The authorization Tuple and its canonical hash (Dacar spec §3.1, §6.1).

A Tuple asserts that a Grantee holds a Relation over an Object, authorized by
an Issuer::

    (Object, Relation, Grantee, Issuer)

Because two different administrators granting identical permissions produce two
distinct Tuples, the Issuer is incorporated into the tuple identity (§3.1).

For Namespace Label Privacy (§3.3), the Relation and Object are stored *only*
as their 16-byte salted hashes. The **Tuple Hash** (§6.1) is SHA-256 over::

    [16-byte Issuer] + [16-byte Grantee] + [16-byte Relation Hash]
    + [1-byte Wildcard Flag] + [1-byte Segment Count] + [Object Hashes]

The Action byte and HLC timestamp are deliberately excluded, so a Grant and its
Revoke for the same permission resolve to the *same* Tuple Hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple as _Tuple

from dacar.namespace import HASH_SIZE, NamespaceHasher

#: Maximum number of Object segments (the Segment Count field is one byte).
MAX_SEGMENTS = 0xFF


@dataclass(frozen=True)
class Tuple:
    """A single hashed authorization relationship."""

    #: 16-byte HMAC-SHA256 hash of the relation string.
    relation_hash: bytes
    #: Tuple of 16-byte HMAC-SHA256 hashes, one per non-wildcard Object segment.
    object_hashes: _Tuple[bytes, ...]
    #: True iff the Object terminated in the suffix wildcard ``*`` (§3.3).
    wildcard: bool
    #: 16-byte RNS.Identity hash of the permission holder (always a single identity).
    grantee: bytes
    #: 16-byte RNS.Identity hash of the issuer, or a Threshold Group ID (§4.1).
    issuer: bytes

    def __post_init__(self) -> None:
        for name, value in (
            ("relation_hash", self.relation_hash),
            ("grantee", self.grantee),
            ("issuer", self.issuer),
        ):
            if not isinstance(value, (bytes, bytearray)) or len(value) != HASH_SIZE:
                raise ValueError(f"{name} must be {HASH_SIZE} bytes, got {value!r}")
        if len(self.object_hashes) > MAX_SEGMENTS:
            raise ValueError(
                f"too many object segments ({len(self.object_hashes)} > {MAX_SEGMENTS})"
            )
        normalized_hashes: _Tuple[bytes, ...] = tuple(
            self._check_segment(h) for h in self.object_hashes
        )
        object.__setattr__(self, "relation_hash", bytes(self.relation_hash))
        object.__setattr__(self, "grantee", bytes(self.grantee))
        object.__setattr__(self, "issuer", bytes(self.issuer))
        object.__setattr__(self, "object_hashes", normalized_hashes)

    @staticmethod
    def _check_segment(h) -> bytes:
        if not isinstance(h, (bytes, bytearray)) or len(h) != HASH_SIZE:
            raise ValueError(f"object segment hash must be {HASH_SIZE} bytes, got {h!r}")
        return bytes(h)

    @classmethod
    def from_plaintext(
        cls,
        *,
        object_id: str,
        relation: str,
        grantee: bytes,
        issuer: bytes,
        hasher: NamespaceHasher,
    ) -> "Tuple":
        """Build a Tuple by hashing plaintext labels with ``hasher`` (§3.3)."""
        relation_hash = hasher.hash_relation(relation)
        object_hashes, wildcard = hasher.hash_object(object_id)
        return cls(relation_hash, object_hashes, wildcard, grantee, issuer)

    def preimage(self) -> bytes:
        """Return the canonical §6.1 binary pre-image (excludes Action + HLC)."""
        out = bytearray()
        out += self.issuer
        out += self.grantee
        out += self.relation_hash
        out.append(0x01 if self.wildcard else 0x00)
        out.append(len(self.object_hashes))
        for h in self.object_hashes:
            out += h
        return bytes(out)

    def hash(self) -> bytes:
        """Return the 32-byte SHA-256 Tuple Hash (the CRDT map key)."""
        return hashlib.sha256(self.preimage()).digest()

    @property
    def key(self) -> bytes:
        """Alias for :meth:`hash` (the stable CRDT identity)."""
        return self.hash()

    def equals(self, other: "Tuple") -> bool:
        """Structural equality with another Tuple."""
        return (
            self.relation_hash == other.relation_hash
            and self.object_hashes == other.object_hashes
            and self.wildcard == other.wildcard
            and self.grantee == other.grantee
            and self.issuer == other.issuer
        )
