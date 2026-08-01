"""Strict Consistency Challenge / Freshness Receipts (§8).

For destructive operations, eventual consistency is dangerous. A node performs
a local pre-check, then challenges a configured Authoritative Identity over an
RNS link (App Name ``dacar``, Aspects ``auth``, ``v1``) for a signed verdict
evaluated against the server's absolute-latest CRDT state.

To preserve Namespace Label Privacy (§3.3), the Challenge payload carries only
*hashed* hypotheses — never plaintext. The client hashes the request across its
Primary Salt and all Legacy Salts (§10); the server matches each by its
``salt_id_tag`` and evaluates directly in hash space.

Canonical challenge wire format (concrete resolution of §8.3)::

    [ nonce(32),
      [ [ salt_id_tag(16), grantee_hash(16), allow_relation_hash(16),
          deny_relation_hash(16), wildcard_bool, [object_segment_hashes] ],
        ... ] ]

Each entry is fully self-contained for one salt and carries *both* the allow and
deny relation hashes so the Authority can apply the deny-beats-allow rule
(§7.3) without recovering plaintext.

The RNS transport is abstracted behind a ``transport`` callable
(``challenge_payload -> receipt_payload | None``), so the cryptographic and
verdict logic is fully testable without a live network. A transport that returns
``None`` or raises is a partition -> immediately DENIED (§8).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any, Callable, List, Optional, Sequence, Tuple as _Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from dacar import serialization
from dacar.config import Config
from dacar.crdt import StateVector
from dacar.engine import Engine, Hypothesis
from dacar.hlc import MAX_HLC, Clock
from dacar.namespace import HASH_SIZE, NamespaceHasher

#: Cryptographically secure challenge nonces are 32 bytes.
NONCE_SIZE = 32


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


def _expect_blob(value: Any, length: int, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != length:
        raise ValueError(f"{name} must be a {length}-byte binary blob")
    return bytes(value)


@dataclass(frozen=True)
class Challenge:
    """The complete evaluation context sent to the Authoritative Identity.

    Plaintext is held only on the client; :meth:`to_payload` emits hashed
    hypotheses across the supplied salts.
    """

    object: str
    relation: str
    grantee: bytes  #: 16-byte RNS.Identity hash.
    nonce: bytes  #: 32-byte locally generated nonce.
    hashers: _Tuple[NamespaceHasher, ...]  #: salts to hypothesize over.

    def __post_init__(self) -> None:
        if len(self.grantee) != HASH_SIZE:
            raise ValueError(f"grantee must be {HASH_SIZE} bytes")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        if not self.hashers:
            raise ValueError("at least one salt hasher is required")
        object.__setattr__(self, "grantee", bytes(self.grantee))
        object.__setattr__(self, "nonce", bytes(self.nonce))
        object.__setattr__(self, "hashers", tuple(self.hashers))

    @classmethod
    def generate(
        cls,
        object_id: str,
        relation: str,
        grantee: bytes,
        hashers: Sequence[NamespaceHasher],
        *,
        nonce: Optional[bytes] = None,
    ) -> "Challenge":
        """Build a Challenge with a fresh (or supplied) cryptographically secure nonce."""
        return cls(
            object_id,
            relation,
            grantee,
            nonce if nonce is not None else os.urandom(NONCE_SIZE),
            tuple(hashers),
        )

    def to_payload(self) -> bytes:
        """Serialize the hashed multi-salt challenge (§8.3)."""
        entries = []
        for hasher in self.hashers:
            obj_hashes, _wildcard = hasher.hash_object(self.object)
            entries.append(
                [
                    hasher.id_tag,
                    self.grantee,
                    hasher.hash_relation(self.relation),
                    hasher.hash_relation("-" + self.relation),
                    False,  # requests are exact; tuples may still be wildcarded
                    list(obj_hashes),
                ]
            )
        return serialization.packb([self.nonce, entries])

    @classmethod
    def from_payload(cls, data: bytes) -> "_ChallengeDecoded":
        """Decode a challenge payload into ``(nonce, grantee, hypotheses)``.

        Plaintext is intentionally unrecoverable; the caller (the Authority)
        receives per-salt hashed hypotheses directly. ``hypotheses`` is a list of
        ``(object_hashes, allow_relation_hash, deny_relation_hash)`` plus the
        ``salt_id_tag`` needed to bind each to a configured salt.
        """
        fields = serialization.unpackb(data)
        if not isinstance(fields, (list, tuple)) or len(fields) != 2:
            raise ValueError("challenge payload must be a 2-element MessagePack array")
        nonce, entries = fields
        nonce = _expect_blob(nonce, NONCE_SIZE, "nonce")
        if not isinstance(entries, (list, tuple)):
            raise ValueError("challenge entries must be an array")
        decoded: List[_DecodedEntry] = []
        grantee: Optional[bytes] = None
        for entry in entries:
            if not isinstance(entry, (list, tuple)) or len(entry) != 6:
                raise ValueError("each challenge entry must be a 6-element array")
            salt_id_tag, grantee_hash, allow_rh, deny_rh, wildcard, obj_hashes = entry
            salt_id_tag = _expect_blob(salt_id_tag, HASH_SIZE, "salt_id_tag")
            grantee_hash = _expect_blob(grantee_hash, HASH_SIZE, "grantee_hash")
            allow_rh = _expect_blob(allow_rh, HASH_SIZE, "allow_relation_hash")
            deny_rh = _expect_blob(deny_rh, HASH_SIZE, "deny_relation_hash")
            if not isinstance(wildcard, bool):
                raise ValueError("wildcard must be a bool")
            if not isinstance(obj_hashes, (list, tuple)):
                raise ValueError("object_segment_hashes must be an array")
            obj_hashes = tuple(_expect_blob(h, HASH_SIZE, "object segment hash") for h in obj_hashes)
            if grantee is None:
                grantee = grantee_hash
            elif grantee != grantee_hash:
                raise ValueError("all challenge entries must share one grantee")
            decoded.append(
                _DecodedEntry(salt_id_tag, grantee_hash, allow_rh, deny_rh, wildcard, obj_hashes)
            )
        if grantee is None:
            raise ValueError("challenge must carry at least one entry")
        return _ChallengeDecoded(nonce, grantee, decoded)


@dataclass(frozen=True)
class _ChallengeDecoded:
    """Decoded challenge: nonce, grantee, and per-salt hashed entries."""

    nonce: bytes
    grantee: bytes
    entries: _Tuple[_DecodedEntry, ...]


@dataclass(frozen=True)
class _DecodedEntry:
    salt_id_tag: bytes
    grantee_hash: bytes
    allow_relation_hash: bytes
    deny_relation_hash: bytes
    wildcard: bool
    object_hashes: _Tuple[bytes, ...]


@dataclass(frozen=True)
class Receipt:
    """The Authoritative Identity's signed verdict (§8.5)."""

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
        return bytes([int(self.verdict)]) + self.server_hlc.to_bytes(8, "big") + self.nonce

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
        return serialization.packb([int(self.verdict), self.server_hlc, self.nonce, self.signature])

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
        return cls(
            Verdict(verdict),
            server_hlc,
            _expect_blob(nonce, NONCE_SIZE, "nonce"),
            _expect_blob(signature, 64, "signature"),
        )


#: Transport callable type: challenge payload -> receipt payload (or None).
Transport = Callable[[bytes], Optional[bytes]]


def _build_hypotheses(
    config: Config, decoded: _ChallengeDecoded
) -> List[Hypothesis]:
    """Bind each decoded entry to a configured salt via its salt_id_tag (§8.4)."""
    by_tag = {h.id_tag: h for h in config.hashers}
    hyps: List[Hypothesis] = []
    for entry in decoded.entries:
        hasher = by_tag.get(entry.salt_id_tag)
        if hasher is None:
            continue  # unknown salt -> hypothesis unusable, skip
        hyps.append(
            (hasher, entry.object_hashes, entry.allow_relation_hash, entry.deny_relation_hash)
        )
    return hyps


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
        self._config = config
        self._private_key = private_key
        self._clock = clock if clock is not None else Clock()

    def handle(self, challenge_payload: bytes) -> bytes:
        """Evaluate a hashed Challenge and return a signed Receipt payload (§8.4)."""
        decoded = Challenge.from_payload(challenge_payload)
        hypotheses = _build_hypotheses(self._config, decoded)
        if hypotheses:
            allowed = self._engine.evaluate_hashes(decoded.grantee, hypotheses)
        else:
            allowed = False  # no recognizable salt -> cannot prove allowance
        verdict = Verdict.ALLOW if allowed else Verdict.DENY
        receipt = Receipt(verdict, self._clock.now(), decoded.nonce).sign(self._private_key)
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
            raise ValueError("Strict Consistency requires an Authoritative Identity (§8)")
        self._engine = Engine(config, state)
        self._state = state
        self._config = config
        self._public_key = _as_public_key(authoritative_public_key)
        self._transport = transport

    def authorize(self, object_id: str, relation: str, grantee: bytes) -> bool:
        """Run the full §8 flow. Returns True only on a verified server ALLOW."""
        # §8.1 Local pre-check: denied locally -> fail immediately.
        if not self._engine.evaluate(object_id, relation, grantee):
            return False
        # §8.2/§8.3 Challenge across Primary + Legacy salts.
        challenge = Challenge.generate(
            object_id, relation, grantee, self._config.hashers
        )
        try:
            receipt_payload = self._transport(challenge.to_payload())
        except Exception:
            return False  # partition penalty (§8)
        if receipt_payload is None:
            return False  # partition penalty (§8)
        receipt = Receipt.from_payload(receipt_payload)
        # §8.5 Verify the nonce matches exactly and the signature is valid.
        if receipt.nonce != challenge.nonce or not receipt.verify(self._public_key):
            return False  # invalid sig / nonce -> treated as DENY
        return receipt.verdict == Verdict.ALLOW
