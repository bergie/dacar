# `@reticulum/dacar` — JavaScript implementation

A JavaScript implementation of the [Dacar 1.0-RC3](../README.md) specification:
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
| Ed25519 sign/verify (§5.2) | `@reticulum/core` `Identity` (Web Crypto) | The canonical Reticulum JS stack; Web Crypto is native everywhere |
| Identity hashing (16-byte) | `@reticulum/core` `Identity.identityHash` | `TRUNCATED_HASHLENGTH = 128` matches the spec exactly |
| MessagePack (§5.3) | `@reticulum/core` `MsgPack` (`MicroMsgPack`) | Reuses the canonical stack's encoder |
| SHA-256 (§6.1) | Web Crypto `crypto.subtle.digest` | Standard, runtime-portable |

`@reticulum/core` is the only dependency.

> **Note on MessagePack + 64-bit HLCs:** a packed HLC (`physical_ms << 16`)
> exceeds `Number.MAX_SAFE_INTEGER`, so it is represented as a `bigint`. This
> implementation requires `@reticulum/core`'s `MicroMsgPack` with BigInt support
> (uint64 encode + lossless decode), which is contributed upstream.

## Install

```bash
cd javascript
npm install
```

> During development the `@reticulum/core` dependency points at a local
> `file:` checkout (the patched source). For release, set it to the published
> version, e.g. `"@reticulum/core": "^0.5.1"`.

## Layout

```
src/
  hlc.js        §5.1  Hybrid Logical Clocks (bigint, 64-bit packed, big-endian)
  namespace.js  §3.3  segment-aware matching + suffix-wildcard permutations
  tuple.js      §3.1, §6.1  authorization Tuple + SHA-256 Tuple Hash
  operation.js  §5.2, §5.3  signed Operation, pre-image, transport payload
  crdt.js       §6    LWW-Element-Set state, apply, merge (Remove wins ties)
  config.js     §4    Root Trust Anchors + Authoritative Identity
  engine.js     §7    recursive delegation evaluation, bounds, memoization
  challenge.js  §8    Strict Consistency Challenge / Freshness Receipts
  index.js            public API
test/           node:test smoketests for every module
scripts/test.sh cross-runtime runner (node / deno / bun)
```

## Quick start

```js
import {
  Action,
  Clock,
  Config,
  Engine,
  Operation,
  StateVector,
  Tuple,
} from "@reticulum/dacar";
import { Identity } from "@reticulum/core";

const anchor = await Identity.generate();          // your Root Trust Anchor
const ROOT = anchor.identityHash;                   // 16-byte hash

const state = new StateVector();
const clock = new Clock();

// Bootstrap: the root anchor grants "read" on "sensor:wind".
const op = await new Operation({
  tuple: new Tuple({ object: "sensor:wind", relation: "read", grantee: ROOT, issuer: ROOT }),
  action: Action.GRANT,
  hlc: clock.now(),
}).sign(anchor);
state.apply(op);

const engine = new Engine(new Config({ rootTrustAnchors: [ROOT] }), state);
console.log(engine.evaluate("sensor:wind", "read", ROOT)); // true
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

Set the released `@reticulum/core` version in `package.json` before publishing.
