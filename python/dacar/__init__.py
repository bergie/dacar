"""Dacar: Decentralized Access Control for Reticulum.

Python implementation of Dacar, a Decentralized Access Control system for
Reticulum: a tuple-based, offline-first authorization policy plane built on an
LWW-Element-Set CRDT, designed for delay-tolerant mesh networks.

Object and relation labels are stored only as salted HMAC-SHA256 hashes
(§3.3 Namespace Label Privacy), Threshold Groups may act as N-of-M Issuers
(§4.1), and the state is bounded by Time-Horizon Tombstone Pruning (§9).
"""

from dacar.hlc import Clock, MAX_HLC, MAX_LOGICAL, MAX_PHYSICAL, pack, unpack
from dacar.namespace import (
    DEFAULT_SALT,
    HASH_SIZE,
    MAX_LEGACY_SALTS,
    SALT_SIZE,
    DELIMITER,
    WILDCARD,
    NamespaceHasher,
    covers,
    split,
)
from dacar.tuple import MAX_SEGMENTS, Tuple
from dacar.threshold import ThresholdGroup, group_id
from dacar.operation import HLC_BYTES, SIGNATURE_SIZE, Action, Operation
from dacar.verifier import IssuerKeyset, KeyResolver, Keyring, verify_operation
from dacar.config import Config, DEFAULT_DELETION_HORIZON_DAYS
from dacar.crdt import StateVector
from dacar.engine import ADMIN_RELATION, DEFAULT_MAX_DEPTH, DEFAULT_MAX_VISITED, Engine
from dacar.challenge import (
    NONCE_SIZE,
    AuthoritativeServer,
    Challenge,
    ChallengeClient,
    Receipt,
    Transport,
    Verdict,
)

__all__ = [
    # HLC (§5.1)
    "Clock",
    "MAX_HLC",
    "MAX_LOGICAL",
    "MAX_PHYSICAL",
    "pack",
    "unpack",
    # Namespace Label Privacy (§3.3)
    "DEFAULT_SALT",
    "HASH_SIZE",
    "MAX_LEGACY_SALTS",
    "SALT_SIZE",
    "DELIMITER",
    "WILDCARD",
    "NamespaceHasher",
    "covers",
    "split",
    # Tuple (§3.1, §6.1)
    "MAX_SEGMENTS",
    "Tuple",
    # Threshold Groups (§4.1)
    "ThresholdGroup",
    "group_id",
    # Operations (§5.2, §5.3)
    "HLC_BYTES",
    "SIGNATURE_SIZE",
    "Action",
    "Operation",
    # Verify-on-ingest (§11.2.4)
    "IssuerKeyset",
    "KeyResolver",
    "Keyring",
    "verify_operation",
    # Config (§4, §10) + state (§6)
    "Config",
    "DEFAULT_DELETION_HORIZON_DAYS",
    "StateVector",
    # Engine (§7)
    "ADMIN_RELATION",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_VISITED",
    "Engine",
    # Challenge (§8)
    "NONCE_SIZE",
    "AuthoritativeServer",
    "Challenge",
    "ChallengeClient",
    "Receipt",
    "Transport",
    "Verdict",
]

__version__ = "1.0.0rc7"
__spec_version__ = "1.0-RC7"
