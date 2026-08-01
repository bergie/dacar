"""Signed authorization Operations / Deltas (Dacar spec §5.2, §5.3).

An Operation is a cryptographically signed instruction to Grant (Add) or
Revoke (Remove) a specific Tuple. Operations are the unit of CRDT mutation
and transport.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from dacar import serialization
from dacar.hlc import MAX_HLC
from dacar.tuple import HASH_SIZE, RELATION_MAX_LEN, Tuple

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
    """A signed Grant or Revoke of a Tuple at a given HLC."""

    tuple: Tuple
    action: Action
    hlc: int
    signature: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            raise TypeError(f"action must be an Action, got {type(self.action)!r}")
        if not 0 <= self.hlc <= MAX_HLC:
            raise ValueError(f"hlc must fit in 64 bits, got {self.hlc}")
        if self.signature and len(self.signature) != SIGNATURE_SIZE:
            raise ValueError(
                f"signature must be {SIGNATURE_SIZE} bytes, got {len(self.signature)}"
            )

    # -- accessors delegating to the embedded Tuple --------------------------
    @property
    def object(self) -> str:
        return self.tuple.object

    @property
    def relation(self) -> str:
        return self.tuple.relation

    @property
    def grantee(self) -> bytes:
        return self.tuple.grantee

    @property
    def issuer(self) -> bytes:
        return self.tuple.issuer

    # -- cryptography (§5.2) -------------------------------------------------
    def preimage(self) -> bytes:
        """Return the signature pre-image per the §5.2 binary layout."""
        relation = self.relation.encode("utf-8")
        return (
            self.issuer
            + self.grantee
            + bytes([int(self.action)])
            + self.hlc.to_bytes(HLC_BYTES, "big")
            + len(relation).to_bytes(1, "big")
            + relation
            + self.object.encode("utf-8")
        )

    def sign(self, private_key: Ed25519PrivateKey) -> "Operation":
        """Return a copy of this Operation signed with ``private_key``."""
        signature = private_key.sign(self.preimage())
        return replace(self, signature=signature)

    def verify(self, public_key: Any) -> bool:
        """Return True if ``signature`` is valid for ``public_key``."""
        if len(self.signature) != SIGNATURE_SIZE:
            return False
        try:
            _as_public_key(public_key).verify(self.signature, self.preimage())
            return True
        except InvalidSignature:
            return False

    # -- transport (§5.3) ---------------------------------------------------
    def to_payload(self) -> bytes:
        """Serialize to the 7-element MessagePack transport array."""
        if len(self.signature) != SIGNATURE_SIZE:
            raise ValueError("Operation must be signed before payload serialization")
        return serialization.packb(
            [
                self.issuer,
                self.grantee,
                int(self.action),
                self.hlc,
                self.relation,
                self.object,
                self.signature,
            ]
        )

    @classmethod
    def from_payload(cls, data: bytes) -> "Operation":
        """Deserialize a 7-element MessagePack transport array."""
        fields = serialization.unpackb(data)
        if not isinstance(fields, (list, tuple)) or len(fields) != 7:
            raise ValueError("payload must be a 7-element MessagePack array")
        issuer, grantee, action, hlc, relation, obj, signature = fields
        if not isinstance(issuer, (bytes, bytearray)) or len(issuer) != HASH_SIZE:
            raise ValueError("issuer must be a 16-byte binary blob")
        if not isinstance(grantee, (bytes, bytearray)) or len(grantee) != HASH_SIZE:
            raise ValueError("grantee must be a 16-byte binary blob")
        if action not in (int(Action.GRANT), int(Action.REVOKE)):
            raise ValueError(f"unknown action byte {action!r}")
        if not isinstance(hlc, int) or not 0 <= hlc <= MAX_HLC:
            raise ValueError("hlc must be a uint64 integer")
        if not isinstance(relation, str):
            raise ValueError("relation must be a string")
        if not isinstance(obj, str):
            raise ValueError("object must be a string")
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_SIZE:
            raise ValueError("signature must be a 64-byte binary blob")
        return cls(
            tuple=Tuple(object=obj, relation=relation, grantee=bytes(grantee), issuer=bytes(issuer)),
            action=Action(action),
            hlc=hlc,
            signature=bytes(signature),
        )
