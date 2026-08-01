"""Threshold Trust Anchors: N-of-M identity groups (Dacar spec §4.1).

A Threshold Group is a composite authority requiring consensus: an Operation
issued *by* the group MUST carry exactly ``N`` valid signatures from ``N``
distinct members of the ``M``-member set (§5.2).

The **Group ID** is the SHA-256 hash of the alphabetically sorted member hashes
concatenated with the threshold ``N``, truncated to the first 16 bytes (§4.1).
The Group ID is itself a 16-byte value usable wherever an Issuer hash is
expected.

> **Scope (§4.1):** in v1.0, Threshold Groups MAY ONLY act as Issuers. A
> Grantee MUST be a single identity; granting permissions *to* a group is not
> supported.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple as _Tuple

from dacar.namespace import HASH_SIZE

#: The threshold ``N`` is folded into the Group ID as an 8-byte big-endian int.
_THRESHOLD_BYTES = 8


def group_id(members: Iterable[bytes], threshold: int) -> bytes:
    """Compute the 16-byte Group ID for a member set and threshold (§4.1).

    Members are the 16-byte identity hashes, sorted ascending by their raw byte
    value (equivalent to hex-alphabetical order). The threshold ``N`` is
    appended as an 8-byte big-endian unsigned integer, then SHA-256 of the whole
    blob is truncated to 16 bytes.
    """
    member_hashes = sorted(bytes(m) for m in members)
    if len(member_hashes) < 2:
        raise ValueError("a threshold group needs at least 2 members (M)")
    for m in member_hashes:
        if len(m) != HASH_SIZE:
            raise ValueError(f"member hash must be {HASH_SIZE} bytes, got {m!r}")
    if not 1 <= threshold < len(member_hashes):
        raise ValueError(
            f"threshold must satisfy 1 <= N < M (got N={threshold}, M={len(member_hashes)})"
        )
    blob = b"".join(member_hashes) + int(threshold).to_bytes(_THRESHOLD_BYTES, "big")
    import hashlib

    return hashlib.sha256(blob).digest()[:HASH_SIZE]


@dataclass(frozen=True)
class ThresholdGroup:
    """An N-of-M identity group that acts as a composite Issuer."""

    #: M member identity hashes (16 bytes each). Stored sorted ascending.
    members: _Tuple[bytes, ...]
    #: The consensus threshold N.
    threshold: int

    def __post_init__(self) -> None:
        normalized = tuple(sorted(bytes(m) for m in self.members))
        # Validate via group_id (raises on bad inputs / bad threshold).
        group_id(normalized, self.threshold)
        object.__setattr__(self, "members", normalized)

    @property
    def group_id(self) -> bytes:
        """The 16-byte Group ID (usable as an Issuer hash)."""
        return group_id(self.members, self.threshold)

    @property
    def size(self) -> int:
        """The number of members ``M``."""
        return len(self.members)
