"""Signed authorization Operations / Deltas (Dacar spec §5.2, §5.3).

An Operation is a cryptographically signed instruction to Grant (Add) or
Revoke (Remove) a specific Tuple. Operations are the unit of CRDT mutation and
transport.

For Threshold Group issuers (§4.1), an Operation carries exactly ``N``
signatures from ``N`` distinct members of the ``M``-set.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Any, List, Sequence, Tuple as _Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from dacar import serialization
from dacar.hlc import MAX_HLC
from dacar.tuple import Tuple

#: Ed25519 signatures are always 64 bytes.
SIGNATURE_SIZE = 64
#: HLC timestamps travel as 64-bit big-endian unsigned integers.
HLC_BYTES = 8


class Action(IntEnum):
    """The effect of an Operation on the CRDT."""

    REVOKE = 0x00  #: Remove the Tuple from the Add set.
    GRANT = 0x01  #: Add the Tuple to the Add set.


def _as_public_key(public_key: Any) -> Ed25519PublicKey:
    """Coerce several public-key representations into an Ed25519PublicKey."""
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if isinstance(public_key, (bytes, bytearray, memoryview)):
        return Ed25519PublicKey.from_public_bytes(bytes(public_key))
    raise TypeError(f"unsupported public key type: {type(public_key)!r}")


@dataclass(frozen=True)
class Operation:
    """A signed Grant or Revoke of a Tuple at a given HLC.

    Single-identity issuers carry exactly one signature; Threshold Group
    issuers carry exactly ``N`` signatures from distinct members (§5.2).
    """

    tuple: Tuple
    action: Action
    hlc: int
    signatures: _Tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            raise TypeError(f"action must be an Action, got {type(self.action)!r}")
        if not 0 <= self.hlc <= MAX_HLC:
            raise ValueError(f"hlc must fit in 64 bits, got {self.hlc}")
        sigs = []
        for sig in self.signatures:
            if not isinstance(sig, (bytes, bytearray)) or len(sig) != SIGNATURE_SIZE:
                raise ValueError(
                    f"each signature must be {SIGNATURE_SIZE} bytes, got {sig!r}"
                )
            sigs.append(bytes(sig))
        object.__setattr__(self, "signatures", tuple(sigs))

    # -- accessors delegating to the embedded Tuple --------------------------
    @property
    def issuer(self) -> bytes:
        return self.tuple.issuer

    @property
    def grantee(self) -> bytes:
        return self.tuple.grantee

    @property
    def relation_hash(self) -> bytes:
        return self.tuple.relation_hash

    @property
    def object_hashes(self) -> _Tuple[bytes, ...]:
        return self.tuple.object_hashes

    @property
    def wildcard(self) -> bool:
        return self.tuple.wildcard

    # -- cryptography (§5.2) -------------------------------------------------
    def preimage(self) -> bytes:
        """Return the signature pre-image per the §5.2 binary layout.

        ``issuer(16) + grantee(16) + action(1) + hlc(8) + relation_hash(16)
        + wildcard(1) + segment_count(1) + object_hashes(S*16)``.
        """
        out = bytearray()
        out += self.tuple.issuer
        out += self.tuple.grantee
        out.append(int(self.action))
        out += self.hlc.to_bytes(HLC_BYTES, "big")
        out += self.tuple.relation_hash
        out.append(0x01 if self.tuple.wildcard else 0x00)
        out.append(len(self.tuple.object_hashes))
        for h in self.tuple.object_hashes:
            out += h
        return bytes(out)

    def sign(self, *private_keys: Ed25519PrivateKey) -> "Operation":
        """Return a copy signed with one or more Ed25519 private keys.

        Each key produces one signature, in argument order. Pass a single key
        for a single-identity issuer, or ``N`` member keys for a Threshold
        Group issuer (§5.2).
        """
        if not private_keys:
            raise ValueError("at least one signing key is required")
        preimage = self.preimage()
        signatures = tuple(k.sign(preimage) for k in private_keys)
        return replace(self, signatures=signatures)

    def verify(self, public_key: Any) -> bool:
        """Verify a single-identity Operation against one public key (§5.2)."""
        if len(self.signatures) != 1:
            return False
        return self.verify_threshold([public_key], 1)

    def verify_threshold(
        self, member_public_keys: Sequence[Any], threshold: int
    ) -> bool:
        """Verify a Threshold Group Operation (§5.2, §4.1).

        Requires exactly ``threshold`` signatures, each valid against a
        *distinct* member public key of the ``M``-set. Duplicate signatures or
        signatures that verify against the same public key more than once are
        rejected.
        """
        if threshold < 1 or len(self.signatures) != threshold:
            return False
        if len(member_public_keys) < threshold:
            return False
        keys = [_as_public_key(k) for k in member_public_keys]
        preimage = self.preimage()
        used: set[bytes] = set()
        for sig in self.signatures:
            matched: bytes | None = None
            for key in keys:
                key_bytes = key.public_bytes_raw()
                if key_bytes in used:
                    continue
                try:
                    key.verify(sig, preimage)
                    matched = key_bytes
                    break
                except InvalidSignature:
                    continue
            if matched is None:
                return False
            used.add(matched)
        return len(used) == threshold

    def verify_keyset(self, keyset: Any) -> bool:
        """Verify against a resolved :class:`~dacar.verifier.IssuerKeyset`.

        This is the bridge used by verify-on-ingest (§11.2.4): a resolver maps
        the Operation's 16-byte Issuer hash to a keyset, and this confirms the
        threshold signature against it.
        """
        return self.verify_threshold(keyset.member_public_keys, keyset.threshold)

    # -- transport (§5.3) ---------------------------------------------------
    def to_payload(self) -> bytes:
        """Serialize to the 8-element MessagePack transport array (§5.3).

        ``[issuer(16), grantee(16), action, hlc, relation_hash(16),
        [segment_hashes], wildcard_bool, [sig_1, ..., sig_N]]``.
        """
        if not self.signatures:
            raise ValueError("Operation must be signed before payload serialization")
        return serialization.packb(
            [
                self.tuple.issuer,
                self.tuple.grantee,
                int(self.action),
                self.hlc,
                self.tuple.relation_hash,
                list(self.tuple.object_hashes),
                self.tuple.wildcard,
                list(self.signatures),
            ]
        )

    @classmethod
    def from_payload(cls, data: bytes) -> "Operation":
        """Deserialize an 8-element MessagePack transport array (§5.3)."""
        fields = serialization.unpackb(data)
        if not isinstance(fields, (list, tuple)) or len(fields) != 8:
            raise ValueError("payload must be an 8-element MessagePack array")
        issuer, grantee, action, hlc, relation_hash, object_hashes, wildcard, signatures = fields
        for name, blob in (("issuer", issuer), ("grantee", grantee), ("relation_hash", relation_hash)):
            if not isinstance(blob, (bytes, bytearray)) or len(blob) != 16:
                raise ValueError(f"{name} must be a 16-byte binary blob")
        if action not in (int(Action.GRANT), int(Action.REVOKE)):
            raise ValueError(f"unknown action byte {action!r}")
        if not isinstance(hlc, int) or not 0 <= hlc <= MAX_HLC:
            raise ValueError("hlc must be a uint64 integer")
        if not isinstance(object_hashes, (list, tuple)):
            raise ValueError("object_hashes must be an array of 16-byte blobs")
        for h in object_hashes:
            if not isinstance(h, (bytes, bytearray)) or len(h) != 16:
                raise ValueError("each object segment hash must be 16 bytes")
        if not isinstance(wildcard, bool):
            raise ValueError("wildcard must be a bool")
        if not isinstance(signatures, (list, tuple)) or not signatures:
            raise ValueError("signatures must be a non-empty array of 64-byte blobs")
        for sig in signatures:
            if not isinstance(sig, (bytes, bytearray)) or len(sig) != SIGNATURE_SIZE:
                raise ValueError("each signature must be a 64-byte binary blob")
        return cls(
            tuple=Tuple(
                relation_hash=bytes(relation_hash),
                object_hashes=tuple(bytes(h) for h in object_hashes),
                wildcard=wildcard,
                grantee=bytes(grantee),
                issuer=bytes(issuer),
            ),
            action=Action(action),
            hlc=hlc,
            signatures=tuple(bytes(sig) for sig in signatures),
        )
