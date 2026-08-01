"""Node configuration: trust anchors and authoritative identity (§4).

Every Dacar node is bootstrapped out-of-band with one or more Root Trust
Anchors. A node that supports Strict Consistency (§8) is additionally
configured with exactly one Authoritative Identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional

from dacar.tuple import HASH_SIZE


@dataclass(frozen=True)
class Config:
    """Static trust configuration for a Dacar service node."""

    #: One or more 16-byte RNS.Identity hashes that act as terminal authority.
    root_trust_anchors: FrozenSet[bytes]
    #: Exactly one identity that signs Freshness Receipts (§8), or None when
    #: the node does not participate in Strict Consistency as a client.
    authoritative_identity: Optional[bytes] = None

    def __post_init__(self) -> None:
        if not self.root_trust_anchors:
            raise ValueError("at least one Root Trust Anchor is required (§4.1)")
        for anchor in self.root_trust_anchors:
            if not isinstance(anchor, (bytes, bytearray)) or len(anchor) != HASH_SIZE:
                raise ValueError(f"trust anchor must be {HASH_SIZE} bytes, got {anchor!r}")
        if self.authoritative_identity is not None:
            if (
                not isinstance(self.authoritative_identity, (bytes, bytearray))
                or len(self.authoritative_identity) != HASH_SIZE
            ):
                raise ValueError(
                    f"authoritative identity must be {HASH_SIZE} bytes"
                )
        # Normalize to immutable bytes so Config is safely hashable/frozen.
        object.__setattr__(
            self, "root_trust_anchors", frozenset(bytes(a) for a in self.root_trust_anchors)
        )
        if self.authoritative_identity is not None:
            object.__setattr__(self, "authoritative_identity", bytes(self.authoritative_identity))

    def is_root_anchor(self, identity_hash: bytes) -> bool:
        """Return True if ``identity_hash`` is a configured Root Trust Anchor."""
        return identity_hash in self.root_trust_anchors
