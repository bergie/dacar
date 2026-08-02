"""Node configuration: trust anchors, salts, and thresholds (§4, §10).

Every Dacar node is bootstrapped out-of-band with one or more Root Trust
Anchors (single identities or Threshold Groups), a Privacy Salt (plus up to two
Legacy Salts for rotation, §10), and optionally an Authoritative Identity for
Strict Consistency (§8).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple as _Tuple

from dacar.namespace import (
    DEFAULT_SALT,
    HASH_SIZE,
    MAX_LEGACY_SALTS,
    SALT_SIZE,
    NamespaceHasher,
)
from dacar.threshold import ThresholdGroup

#: Default deletion horizon H (days), see §9.
DEFAULT_DELETION_HORIZON_DAYS = 180


class NullPrivacySaltWarning(UserWarning):
    """Emitted when a node starts with the fail-open default Privacy Salt.

    The unset default is 32 null bytes (§3.3), which makes every label hash
    trivially dictionary-attackable — labels leak over public transports.
    Production deployments MUST set a strong random Primary Salt. This warning
    turns the spec's §3.3 caution into an audible, executed check at node
    startup (Config construction). Silence it only for deliberate test/demo
    use::

        import warnings
        from dacar.config import NullPrivacySaltWarning
        warnings.filterwarnings("ignore", category=NullPrivacySaltWarning)
    """


@dataclass(frozen=True)
class Config:
    """Static trust + privacy configuration for a Dacar service node."""

    #: One or more 16-byte hashes that act as terminal authority. Each is an
    #: RNS.Identity hash (single anchor) or a Threshold Group ID (§4.1).
    root_trust_anchors: FrozenSet[bytes]
    #: The Primary Privacy Salt (32 bytes). Defaults to fail-open nulls (§3.3).
    primary_salt: bytes = DEFAULT_SALT
    #: Ordered Legacy Salts for rotation; at most ``MAX_LEGACY_SALTS`` (§10.2).
    legacy_salts: _Tuple[bytes, ...] = ()
    #: Threshold Groups the node knows about (for Issuer verification, §4.1).
    threshold_groups: _Tuple[ThresholdGroup, ...] = ()
    #: Exactly one identity that signs Freshness Receipts (§8), or None.
    authoritative_identity: Optional[bytes] = None
    #: Deletion horizon H in days for tombstone pruning (§9).
    deletion_horizon_days: int = DEFAULT_DELETION_HORIZON_DAYS

    def __post_init__(self) -> None:
        if not self.root_trust_anchors:
            raise ValueError("at least one Root Trust Anchor is required (§4.1)")
        anchors = set()
        for anchor in self.root_trust_anchors:
            if not isinstance(anchor, (bytes, bytearray)) or len(anchor) != HASH_SIZE:
                raise ValueError(f"trust anchor must be {HASH_SIZE} bytes, got {anchor!r}")
            anchors.add(bytes(anchor))
        object.__setattr__(self, "root_trust_anchors", frozenset(anchors))

        if not isinstance(self.primary_salt, (bytes, bytearray)) or len(self.primary_salt) != SALT_SIZE:
            raise ValueError(f"primary_salt must be {SALT_SIZE} bytes")
        object.__setattr__(self, "primary_salt", bytes(self.primary_salt))

        if len(self.legacy_salts) > MAX_LEGACY_SALTS:
            raise ValueError(
                f"at most {MAX_LEGACY_SALTS} Legacy Salts are allowed (§10.2), "
                f"got {len(self.legacy_salts)}"
            )
        normalized_legacy = []
        for salt in self.legacy_salts:
            if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
                raise ValueError(f"each legacy salt must be {SALT_SIZE} bytes")
            normalized_legacy.append(bytes(salt))
        object.__setattr__(self, "legacy_salts", tuple(normalized_legacy))

        object.__setattr__(self, "threshold_groups", tuple(self.threshold_groups))

        if self.authoritative_identity is not None:
            if (
                not isinstance(self.authoritative_identity, (bytes, bytearray))
                or len(self.authoritative_identity) != HASH_SIZE
            ):
                raise ValueError(f"authoritative identity must be {HASH_SIZE} bytes")
            object.__setattr__(self, "authoritative_identity", bytes(self.authoritative_identity))

        if self.deletion_horizon_days < 1:
            raise ValueError("deletion_horizon_days must be >= 1")

        # §3.3 fail-open guard: only warn once the Config is fully valid, so a
        # misconfiguration that already raises is not also noisily warned about.
        # stacklevel=3 reaches the user's `Config(...)` call site (the
        # dataclass-synthesized __init__ sits at stacklevel 2).
        if self.primary_salt == DEFAULT_SALT:
            warnings.warn(
                "Config started with the default null Privacy Salt: label hashes "
                "are fail-open (trivially dictionary-attackable, §3.3). Set a "
                "strong random primary_salt for any real deployment.",
                NullPrivacySaltWarning,
                stacklevel=3,
            )

    # -- salts (§3.3, §10) --------------------------------------------------
    @property
    def primary_hasher(self) -> NamespaceHasher:
        return NamespaceHasher(self.primary_salt)

    @property
    def legacy_hashers(self) -> _Tuple[NamespaceHasher, ...]:
        return tuple(NamespaceHasher(s) for s in self.legacy_salts)

    @property
    def hashers(self) -> List[NamespaceHasher]:
        """All configured hashers: Primary first, then Legacy in order (§10.2)."""
        return [self.primary_hasher, *self.legacy_hashers]

    # -- anchors & groups (§4) ----------------------------------------------
    def is_root_anchor(self, identity_hash: bytes) -> bool:
        """Return True if ``identity_hash`` is a configured Root Trust Anchor."""
        return bytes(identity_hash) in self.root_trust_anchors

    def group_for(self, group_id: bytes) -> Optional[ThresholdGroup]:
        """Return the Threshold Group with the given Group ID, or None (§4.1)."""
        gid = bytes(group_id)
        for group in self.threshold_groups:
            if group.group_id == gid:
                return group
        return None
