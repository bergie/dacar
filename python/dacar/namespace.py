"""Namespace Label Privacy (Dacar spec §3.3).

To prevent label disclosure over public transports, Dacar never transmits or
stores Object or Relation strings in plaintext. Every string label is hashed
with **HMAC-SHA256**, keyed with the node's Privacy Salt, and strictly
truncated to the first 16 bytes.

Objects are split by ``:`` into segments, and each segment is hashed
individually. The terminal suffix wildcard ``*`` is stripped *before* hashing
and carried instead as a boolean flag on the Tuple (§3.3).

> **WARNING (§3.3):** an unset Privacy Salt defaults to 32 null bytes, which is
> *fail-open on privacy* — the hashes become trivially dictionary-attackable.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Tuple as _Tuple

DELIMITER = ":"
WILDCARD = "*"

#: Privacy Salts are 32 bytes of cryptographically secure random data.
SALT_SIZE = 32
#: All label hashes (and RNS.Identity hashes) are 16 bytes.
HASH_SIZE = 16
#: The fail-open default salt when none is configured (§3.3 WARNING).
DEFAULT_SALT = b"\x00" * SALT_SIZE
#: Maximum number of concurrently-configured Legacy Salts (§10.2).
MAX_LEGACY_SALTS = 2

#: Domain-separation tag used to derive a salt's identifying ``id_tag`` (§8.3).
_SALT_ID_TAG = b"dacar.salt.id"


def _hmac16(salt: bytes, message: bytes) -> bytes:
    """HMAC-SHA256(salt, message) truncated to 16 bytes (§3.3 hashing primitive)."""
    return hmac.new(salt, message, hashlib.sha256).digest()[:HASH_SIZE]


def split(object_id: str) -> List[str]:
    """Split an object string into its colon-delimited segments."""
    return object_id.split(DELIMITER)


def _parse_object(object_id: str) -> _Tuple[List[str], bool]:
    """Return ``(segments, wildcard)`` for an object string.

    The terminal ``*`` is stripped and reported via the wildcard flag:

      * ``"*"``        -> ``([], True)``            (root wildcard)
      * ``"sensor:*"`` -> ``(["sensor"], True)``
      * ``"sensor:wind"`` -> ``(["sensor", "wind"], False)``

    A non-terminal ``*`` is treated as a literal segment.
    """
    if object_id == WILDCARD:
        return ([], True)
    segments = split(object_id)
    wildcard = False
    if segments and segments[-1] == WILDCARD:
        wildcard = True
        segments = segments[:-1]
    return (segments, wildcard)


@dataclass(frozen=True)
class NamespaceHasher:
    """Hashes plaintext labels into the 16-byte forms stored in Tuples.

    All methods use HMAC-SHA256 keyed with the configured Privacy Salt,
    truncated to 16 bytes (§3.3). A single hasher is bound to exactly one salt.
    """

    salt: bytes = DEFAULT_SALT

    def __post_init__(self) -> None:
        if not isinstance(self.salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes")
        if len(self.salt) != SALT_SIZE:
            raise ValueError(f"salt must be {SALT_SIZE} bytes, got {len(self.salt)}")
        object.__setattr__(self, "salt", bytes(self.salt))

    def hash_relation(self, relation: str) -> bytes:
        """Hash a whole relation string (§3.3). Explicit denies include ``-``."""
        return _hmac16(self.salt, relation.encode("utf-8"))

    def hash_object(self, object_id: str) -> _Tuple[_Tuple[bytes, ...], bool]:
        """Return ``(segment_hashes, wildcard)`` for an object string (§3.3)."""
        segments, wildcard = _parse_object(object_id)
        hashes = tuple(_hmac16(self.salt, seg.encode("utf-8")) for seg in segments)
        return (hashes, wildcard)

    @property
    def id_tag(self) -> bytes:
        """A 16-byte tag identifying this salt (§8.3 ``salt_id_tag``).

        Derived as ``HMAC-SHA256(salt, b"dacar.salt.id")`` truncated to 16 bytes,
        so an Authority can match a hypothesized request to the salt that
        produced it without ever exchanging the salt itself.
        """
        return _hmac16(self.salt, _SALT_ID_TAG)


def covers(
    tuple_hashes,
    wildcard: bool,
    request_hashes,
) -> bool:
    """Does a Tuple's hashed Object cover a request's exact hashed Object? (§3.3)

    A match succeeds if the Tuple is wildcarded and its hashes are a *prefix* of
    the request hashes, or if the two hash arrays are identical. Request hashes
    are always exact (a request never carries its own wildcard).
    """
    req = tuple(request_hashes)
    if wildcard:
        tup = tuple(tuple_hashes)
        if len(tup) > len(req):
            return False
        return tup == req[: len(tup)]
    return tuple(tuple_hashes) == req
