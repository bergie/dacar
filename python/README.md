# Dacar — Python reference implementation

A Python implementation of the [Dacar 1.0-RC6](../README.md) specification:
decentralized, offline-first access control for Reticulum mesh networks.

Dacar is a tuple-based authorization system (inspired by Google Zanzibar) built
on an LWW-Element-Set CRDT. Each node evaluates permissions locally against a
replicated, eventually-consistent authorization state, with delegation chains
that terminate at configured Root Trust Anchors.

## Dependencies

| Need              | Choice                                   | Why                                            |
| ----------------- | ---------------------------------------- | ---------------------------------------------- |
| Ed25519 (§5.2)    | [`cryptography`](https://cryptography.io) | Same backend RNS (Reticulum) selects when present |
| SHA-256 / HMAC (§3.3, §6.1) | stdlib `hashlib` / `hmac`   | In the standard library                        |
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
  namespace.py    §3.3  Namespace Label Privacy: salted HMAC-SHA256 hashing,
                        object segmenting, wildcard flag, hashed-object matching
  tuple.py        §3.1, §6.1  hashed authorization Tuple + SHA-256 Tuple Hash
  threshold.py    §4.1  N-of-M Threshold Groups + 16-byte Group ID
  operation.py    §5.2, §5.3  signed Operation (single + multi-sig), pre-image,
                        MessagePack transport payload
  serialization.py       MessagePack helpers
  crdt.py         §6, §9  LWW-Element-Set state, merge (Remove wins ties),
                        Time-Horizon Tombstone Pruning, intake rejection
  config.py       §4, §10  Root Trust Anchors, Privacy Salts (Primary + Legacy),
                        Authoritative Identity, deletion horizon
  engine.py       §7    recursive delegation evaluation, hashed hypotheses,
                        multi-salt shared work bound
  challenge.py    §8    Strict Consistency Challenge (hashed, multi-salt) +
                        signed Freshness Receipts
tests/            unittest smoketests for every module
```

## Quick start

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dacar import (
    Action, Clock, Config, Engine, NamespaceHasher,
    Operation, StateVector, Tuple,
)

HASH = b"\x01" * 16  # a 16-byte RNS.Identity hash
ROOT = b"\x00" * 16  # your Root Trust Anchor

hasher = NamespaceHasher()  # default salt is FAIL-OPEN; supply a real 32-byte salt!
state = StateVector()
clock = Clock()

# Bootstrap: the root anchor grants Alice the "read" relation on "sensor:wind".
state.apply(
    Operation(
        tuple=Tuple.from_plaintext(
            object_id="sensor:wind", relation="read",
            grantee=HASH, issuer=ROOT, hasher=hasher,
        ),
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
