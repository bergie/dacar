# Dacar — Python reference implementation

A Python implementation of the [Dacar 1.0-RC7](../README.md) specification:
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
pip install -e .            # pure core: cryptography + msgpack only
pip install -e ".[transport]"  # + the §8/§11 RNS & LXMF transport adapters
```

The pure core has **no RNS dependency**. `import dacar` never pulls in the
`dacar.transport` subpackage (the `rns`/`lxmf` packages); those adapters are
opt-in via the `transport` extra.

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
                        Time-Horizon Tombstone Pruning, intake rejection,
                        verify-then-apply ingest() entry point
  config.py       §4, §10  Root Trust Anchors, Privacy Salts (Primary + Legacy),
                        Authoritative Identity, deletion horizon
  engine.py       §7    recursive delegation evaluation, hashed hypotheses,
                        multi-salt shared work bound
  challenge.py    §8    Strict Consistency Challenge (hashed, multi-salt) +
                        signed Freshness Receipts
  verifier.py     §5.2, §11.2.4  verify-on-ingest: IssuerKeyset, KeyResolver,
                        Keyring, verify_operation()
  delta.py        §11.2.4  DeltaReceiver — transport-agnostic receive boundary
                        (decode → verify → apply)
  naming.py       §8, §11  RNS naming constants (fixed discriminators +
                        configurable RFed topic)
  transport/      §8, §11.2, §11.3  optional RNS/LXMF adapters (`transport` extra):
    rns_challenge.py  §8 Challenge over an RNS Link (server endpoint + client transport)
    rns_identity.py   §3.1, §11.2.4  RnsIdentityResolver (recall → verify key)
    lxmf_sync.py      §11.2/§11.3 targeted LXMF Delta delivery + Paper Messages
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

## Verify-on-ingest & identity resolution

Every Delta received over the network (RFed, LXMF, or a scanned Paper Message)
flows through one seam — `DeltaReceiver.apply_payload` — which decodes the
§5.3 payload, **authenticates it by Ed25519 signature before it may mutate
state** (§11.2.4), and only then merges it. A `KeyResolver` maps an Operation's
16-byte Issuer Hash to the public key(s) needed to check that signature:

- **`Keyring`** — a dict-backed resolver for offline / air-gapped / test use; you
  register each Issuer hash → keyset out of band.
- **`RnsIdentityResolver`** (`dacar[transport]`) — resolves a single-identity
  Issuer by **recalling the `RNS.Identity` behind its hash from the network's
  announce store**, with no out-of-band key exchange. Threshold Groups (composite
  IDs RNS cannot recall) and any out-of-band identities fall through to an
  optional inner resolver — RNS is consulted first, then the fallback.

```python
import RNS
from dacar import DeltaReceiver, Keyring, Operation, StateVector
from dacar.transport import RnsIdentityResolver

issuer = RNS.Identity()                  # the Issuer's RNS identity
state = StateVector()
resolver = RnsIdentityResolver(fallback=Keyring())  # + registered groups
rx = DeltaReceiver(state, resolver)

op = Operation(...).sign(issuer.sig_prv) # op.issuer is issuer.hash
rx.apply_payload(op.to_payload())        # recall issuer.hash → verify → merge
```

> **The Issuer Hash must be the canonical RNS identity hash.** RNS defines an
> identity hash as `SHA-256(P)[:16]` where `P` is the 64-byte public key
> (`X25519_pub ‖ Ed25519_pub`) — *not* a hash of the Ed25519 signing key alone.
> Only that hash is recallable, so a single-identity Issuer Hash MUST be
> `RNS.Identity().hash`; any other value cannot be authenticated and is dropped.
> (Threshold Group IDs are exempt — they are resolved by explicit keyset
> registration, not recall.) The quick-start example above uses a placeholder
> 16-byte hash purely to demonstrate the API; real deployments use RNS identity
> hashes for Issuer and Grantee.

## Tests

Pure stdlib `unittest` (no `pytest` dependency):

```bash
cd python
python -m unittest discover -s tests -v
```
