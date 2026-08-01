# `@reticulum/dacar` — JavaScript implementation

A JavaScript implementation of the [Dacar 1.0-RC6](../README.md) specification:
decentralized, offline-first access control for Reticulum mesh networks.

Dacar is a tuple-based authorization system (inspired by Google Zanzibar) built
on an LWW-Element-Set CRDT. Each node evaluates permissions locally against a
replicated, eventually-consistent authorization state, with delegation chains
that terminate at configured Root Trust Anchors.

This is a modern ES-module package with JSDoc type annotations that runs on
**browsers, Node.js, Deno, and Bun** with no build step.

## Dependencies

| Need | Choice | Why |
| ---- | ------ | --- |
| Ed25519 sign/verify (§5.2) | `@reticulum/core` `Identity` (Web Crypto) | The canonical Reticulum JS stack |
| HMAC-SHA256 / SHA-256 (§3.3, §6.1) | Web Crypto `crypto.subtle` | Standard, runtime-portable |
| MessagePack (§5.3) | `@reticulum/core` `MsgPack` | Reuses the canonical stack's encoder |

`@reticulum/core` is the only dependency.

> **Note on MessagePack + 64-bit HLCs:** a packed HLC (`physical_ms << 16`)
> exceeds `Number.MAX_SAFE_INTEGER`, so it is represented as a `bigint`. The HLC
> is always encoded as a `bigint` (uint64) and normalized with `BigInt()` on
> decode, so it round-trips losslessly.

## Install

```bash
cd javascript
npm install
```

## Layout

```
src/
  hlc.js          §5.1  Hybrid Logical Clocks (bigint, 64-bit packed, big-endian)
  namespace.js    §3.3  Namespace Label Privacy: salted HMAC-SHA256 hashing,
                        object segmenting, wildcard flag, hashed-object matching
  tuple.js        §3.1, §6.1  hashed authorization Tuple + SHA-256 Tuple Hash
  threshold.js    §4.1  N-of-M Threshold Groups + 16-byte Group ID
  operation.js    §5.2, §5.3  signed Operation (single + multi-sig), pre-image,
                        MessagePack transport payload
  crdt.js         §6, §9  LWW-Element-Set state, merge (Remove wins ties),
                        Time-Horizon Tombstone Pruning, intake rejection
  config.js       §4, §10  Root Trust Anchors, Privacy Salts (Primary + Legacy),
                        Authoritative Identity, deletion horizon
  engine.js       §7    recursive delegation evaluation, hashed hypotheses,
                        multi-salt shared work bound
  challenge.js    §8    Strict Consistency Challenge (hashed, multi-salt) +
                        signed Freshness Receipts
  index.js              public API
test/             node:test smoketests for every module
scripts/test.sh   cross-runtime runner (node / deno / bun)
```

## Quick start

```js
import {
  Action,
  Clock,
  Config,
  Engine,
  NamespaceHasher,
  Operation,
  StateVector,
  Tuple,
} from "@reticulum/dacar";
import { Identity } from "@reticulum/core";

const anchor = await Identity.generate();          // your Root Trust Anchor
const ROOT = anchor.identityHash;                   // 16-byte hash

const hasher = new NamespaceHasher(); // default salt is FAIL-OPEN; supply a real 32-byte salt!
const state = new StateVector();
const clock = new Clock();

// Bootstrap: the root anchor grants "read" on "sensor:wind".
const op = await new Operation({
  tuple: await Tuple.fromPlaintext({
    objectId: "sensor:wind", relation: "read", grantee: ROOT, issuer: ROOT, hasher,
  }),
  action: Action.GRANT,
  hlc: clock.now(),
}).sign(anchor);
state.apply(op);

const engine = new Engine(new Config({ rootTrustAnchors: [ROOT] }), state);
console.log(await engine.evaluate("sensor:wind", "read", ROOT)); // true
```

## Tests

Tests use [`node:test`](https://nodejs.org/api/test.html) and run under every
installed runtime (node, deno, bun). The runner fails if **none** is installed:

```bash
npm test            # runs under each installed runtime
npm run test:node   # node only
npm run test:deno   # deno only
npm run test:bun    # bun only
```

## Publishing

Published to both registries as **`@reticulum/dacar`**:

```bash
# JSR
cd javascript && deno publish

# npm
cd javascript && npm publish
```
