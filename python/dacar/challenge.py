"""Strict Consistency Challenge / Freshness Receipts (§8).

For destructive operations, eventual consistency is dangerous. A node performs
a local pre-check, then challenges a configured Authoritative Identity over an
RNS link for a signed Freshness Receipt evaluated against the server's
absolute-latest CRDT state.

The RNS transport itself is abstracted behind a ``transport`` callable
(``challenge_payload -> receipt_payload | None``) so the cryptographic and
verdict logic is fully testable without a live network. A transport that
returns ``None`` or raises is treated as a partition -> immediately DENIED.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from dacar import serialization
from dacar.config import Config
from dacar.crdt import StateVector
from dacar.engine import Engine
from dacar.hlc import MAX_HLC, Clock
from dacar.tuple import HASH_SIZE

#: Cryptographically secure challenge nonces are 32 bytes.
NONCE_SIZE = 32
#: The receipt signature covers the three fields preceding it (41 bytes).
_RECEIPT_PREIMAGE_LEN = 1 + 8 + NONCE_SIZE


class Verdict(IntEnum):
    """The binary verdict carried by a Freshness Receipt."""

    DENY = 0x00
    ALLOW = 0x01


def _as_public_key(public_key: Any) -> Ed25519PublicKey:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if isinstance(public_key, (bytes, bytearray, memoryview)):
        return Ed25519PublicKey.from_public_bytes(bytes(public_key))
    raise TypeError(f"unsupported public key type: {type(public_key)!r}")


@dataclass(frozen=True)
class Challenge:
    """The complete evaluation context sent to the Authoritative Identity."""

    object: str
    relation: str
    grantee: bytes  #: 16-byte RNS.Identity hash.
    nonce: bytes  #: 32-byte locally generated nonce.

    def __post_init__(self) -> None:
        if len(self.grantee) != HASH_SIZE:
            raise ValueError(f"grantee must be {HASH_SIZE} bytes")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")

    @classmethod
    def generate(
        cls, object_id: str, relation: str, grantee: bytes, *, nonce: Optional[bytes] = None
    ) -> "Challenge":
        """Build a Challenge with a fresh (or supplied) cryptographically secure nonce."""
        return cls(object_id, relation, grantee, nonce if nonce is not None else os.urandom(NONCE_SIZE))

    def to_payload(self) -> bytes:
        """Serialize as ``[object, relation, grantee(16), nonce(32)]``."""
        return serialization.packb([self.object, self.relation, self.grantee, self.nonce])

    @classmethod
    def from_payload(cls, data: bytes) -> "Challenge":
        fields = serialization.unpackb(data)
        if not isinstance(fields, (list, tuple)) or len(fields) != 4:
            raise ValueError("challenge payload must be a 4-element MessagePack array")
        obj, relation, grantee, nonce = fields
        if not isinstance(obj, str) or not isinstance(relation, str):
            raise ValueError("object/relation must be strings")
        if not isinstance(grantee, (bytes, bytearray)) or len(grantee) != HASH_SIZE:
            raise ValueError("grantee must be a 16-byte binary blob")
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_SIZE:
            raise ValueError("nonce must be a 32-byte binary blob")
        return cls(obj, relation, bytes(grantee), bytes(nonce))


@dataclass(frozen=True)
class Receipt:
    """The Authoritative Identity's signed verdict."""

    verdict: Verdict
    server_hlc: int
    nonce: bytes
    signature: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            raise TypeError("verdict must be a Verdict")
        if not 0 <= self.server_hlc <= MAX_HLC:
            raise ValueError("server_hlc must fit in 64 bits")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        if self.signature and len(self.signature) != 64:
            raise ValueError("signature must be 64 bytes")

    def preimage(self) -> bytes:
        """The unpadded concatenation of the fields preceding the signature."""
        return (
            bytes([int(self.verdict)])
            + self.server_hlc.to_bytes(8, "big")
            + self.nonce
        )

    def sign(self, private_key: Ed25519PrivateKey) -> "Receipt":
        return replace(self, signature=private_key.sign(self.preimage()))

    def verify(self, public_key: Any) -> bool:
        if len(self.signature) != 64:
            return False
        try:
            _as_public_key(public_key).verify(self.signature, self.preimage())
            return True
        except InvalidSignature:
            return False

    def to_payload(self) -> bytes:
        if len(self.signature) != 64:
            raise ValueError("Receipt must be signed before payload serialization")
        return serialization.packb(
            [int(self.verdict), self.server_hlc, self.nonce, self.signature]
        )

    @classmethod
    def from_payload(cls, data: bytes) -> "Receipt":
        fields = serialization.unpackb(data)
        if not isinstance(fields, (list, tuple)) or len(fields) != 4:
            raise ValueError("receipt payload must be a 4-element MessagePack array")
        verdict, server_hlc, nonce, signature = fields
        if verdict not in (int(Verdict.ALLOW), int(Verdict.DENY)):
            raise ValueError(f"unknown verdict byte {verdict!r}")
        if not isinstance(server_hlc, int) or not 0 <= server_hlc <= MAX_HLC:
            raise ValueError("server_hlc must be a uint64 integer")
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_SIZE:
            raise ValueError("nonce must be a 32-byte binary blob")
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            raise ValueError("signature must be a 64-byte binary blob")
        return cls(Verdict(verdict), server_hlc, bytes(nonce), bytes(signature))


#: Transport callable type: challenge payload -> receipt payload (or None).
Transport = Callable[[bytes], Optional[bytes]]


class AuthoritativeServer:
    """The Authoritative Identity: evaluates requests and signs Freshness Receipts."""

    def __init__(
        self,
        config: Config,
        state: StateVector,
        private_key: Ed25519PrivateKey,
        *,
        clock: Optional[Clock] = None,
    ) -> None:
        self._engine = Engine(config, state)
        self._state = state
        self._private_key = private_key
        self._clock = clock if clock is not None else Clock()

    def handle(self, challenge_payload: bytes) -> bytes:
        """Evaluate a Challenge and return a signed Receipt payload."""
        challenge = Challenge.from_payload(challenge_payload)
        allowed = self._engine.evaluate(challenge.object, challenge.relation, challenge.grantee)
        verdict = Verdict.ALLOW if allowed else Verdict.DENY
        receipt = Receipt(verdict, self._clock.now(), challenge.nonce).sign(self._private_key)
        # NOTE (§8.4): when the server's DENY is due to upstream revocations not
        # yet known to the client, the server SHOULD also ship the revoked
        # tuples so the client can update its local CRDT. The wire format for
        # that is not defined by spec 1.0-RC3; applications extend the Receipt
        # payload to carry it.
        return receipt.to_payload()


class ChallengeClient:
    """The requesting node: performs the local pre-check and challenge exchange."""

    def __init__(
        self,
        config: Config,
        state: StateVector,
        authoritative_public_key: Any,
        transport: Transport,
    ) -> None:
        if config.authoritative_identity is None:
            raise ValueError("Strict Consistency requires an Authoritative Identity (§4.1)")
        self._engine = Engine(config, state)
        self._state = state
        self._public_key = _as_public_key(authoritative_public_key)
        self._transport = transport

    def authorize(self, object_id: str, relation: str, grantee: bytes) -> bool:
        """Run the full §8 flow. Returns True only on a verified server ALLOW."""
        # §8.1 Local pre-check: denied locally -> fail immediately.
        if not self._engine.evaluate(object_id, relation, grantee):
            return False
        # §8.2 Challenge.
        challenge = Challenge.generate(object_id, relation, grantee)
        try:
            receipt_payload = self._transport(challenge.to_payload())
        except Exception:
            return False  # §8.5 partition penalty
        if receipt_payload is None:
            return False  # §8.5 partition penalty
        receipt = Receipt.from_payload(receipt_payload)
        # §8.4 Verify the nonce matches exactly and the signature is valid.
        if receipt.nonce != challenge.nonce or not receipt.verify(self._public_key):
            return False  # invalid sig / nonce == treated as timeout -> DENY
        return receipt.verdict == Verdict.ALLOW
