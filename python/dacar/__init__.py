"""Dacar: Decentralized Access Control for Reticulum.

A reference Python implementation of the Dacar 1.0-RC3 specification: a
tuple-based, offline-first authorization policy plane built on an
LWW-Element-Set CRDT, designed for delay-tolerant mesh networks.
"""

from dacar.hlc import Clock, MAX_HLC, MAX_LOGICAL, MAX_PHYSICAL, pack, unpack
from dacar.namespace import match, permutations
from dacar.tuple import Tuple
from dacar.operation import Action, Operation
from dacar.config import Config
from dacar.crdt import StateVector
from dacar.engine import ADMIN_RELATION, Engine
from dacar.challenge import (
    Challenge,
    ChallengeClient,
    AuthoritativeServer,
    Receipt,
    Transport,
    Verdict,
)

__all__ = [
    "Clock",
    "MAX_HLC",
    "MAX_LOGICAL",
    "MAX_PHYSICAL",
    "pack",
    "unpack",
    "match",
    "permutations",
    "Tuple",
    "Action",
    "Operation",
    "Config",
    "StateVector",
    "ADMIN_RELATION",
    "Engine",
    "Challenge",
    "ChallengeClient",
    "AuthoritativeServer",
    "Receipt",
    "Transport",
    "Verdict",
]

__version__ = "1.0.0rc3"
__spec_version__ = "1.0-RC3"
