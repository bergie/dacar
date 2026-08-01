# Dacar — Python reference implementation

A Python implementation of the [Dacar 1.0-RC3](../README.md) specification:
decentralized, offline-first access control for Reticulum mesh networks.

Dacar is a tuple-based authorization system (inspired by Google Zanzibar) built
on an LWW-Element-Set CRDT. Each node evaluates permissions locally against a
replicated, eventually-consistent authorization state, with delegation chains
that terminate at configured Root Trust Anchors.

## Dependencies

| Need              | Choice                                   | Why                                            |
| ----------------- | ---------------------------------------- | ---------------------------------------------- |
| Ed25519 (§5.2)    | [`cryptography`](https://cryptography.io) | Same backend RNS (Reticulum) selects when present |
| SHA-256 (§6.1)    | stdlib `hashlib`                         | In the standard library                        |
| MessagePack (§5.3)| `msgpack`                                | Spec-listed dependency                         |

## Install

```bash
cd python
pip install -e .
```

## Layout

```
dacar/
  hlc.py          §5.1  Hybrid Logical Clocks (64-bit packed, big-endian)
  namespace.py    §3.3  segment-aware namespace matching + wildcard permutations
  tuple.py        §3.1, §6.1  authorization Tuple + SHA-256 Tuple Hash
  operation.py    §5.2, §5.3  signed Operation, pre-image, transport payload
  serialization.py       MessagePack helpers
  crdt.py         §6    LWW-Element-Set state, apply, merge (Remove wins ties)
  config.py       §4    Root Trust Anchors + Authoritative Identity
  engine.py       §7    recursive delegation evaluation, bounds, memoization
  challenge.py    §8    Strict Consistency Challenge / Freshness Receipts
tests/            unittest smoketests for every module
```

## Quick start

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dacar import (
    Action, Clock, Config, Engine, Operation, StateVector, Tuple,
)

HASH = b"\x01" * 16  # a 16-byte RNS.Identity hash
ROOT = b"\x00" * 16  # your Root Trust Anchor

state = StateVector()
clock = Clock()

# Bootstrap: the root anchor grants Alice the "read" relation on "sensor:wind".
state.apply(
    Operation(
        tuple=Tuple("sensor:wind", "read", HASH, ROOT),
        action=Action.GRANT,
        hlc=clock.now(),
    ).sign(Ed25519PrivateKey.generate())  # in practice, ROOT's private key
)

engine = Engine(Config(root_trust_anchors=frozenset({ROOT})), state)
assert engine.evaluate("sensor:wind", "read", HASH) is True
```

## Tests

Pure stdlib `unittest` (no `pytest` dependency):

```bash
cd python
python -m unittest discover -s tests -v
```
