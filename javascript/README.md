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

`@reticulum/core` is the only dependency (for both the core and the optional
transport adapters — which additionally use its `Destination`, `Link`,
`LXMRouter`, and `RFedClient`).

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
  verifier.js     §5.2, §11.2.4  verify-on-ingest: IssuerKeyset, KeyResolver,
                        Keyring, verifyOperation()
  delta.js        §11.2.4  DeltaReceiver — transport-agnostic receive boundary
                        (decode → verify → apply)
  naming.js       §8, §11  RNS naming constants (fixed discriminators +
                        configurable RFed topic)
  index.js              public API
  transport/      §8, §11.2, §11.3  optional RNS/RFed/LXMF adapters (opt-in):
    rnsIdentity.js   §3.1, §11.2.4  RnsIdentityResolver (recall → verify key)
    rnsChallenge.js  §8  Challenge over an RNS Link (server endpoint +
                        client transport + establishLink)
    lxmfSync.js      §11.2/§11.3  targeted LXMF Delta delivery + Paper Messages
    rfedSync.js      §11.1  RFed many-to-many convergence
    index.js               transport barrel
test/             node:test smoketests for every module (incl. transport-*)
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

## Transport layer

The pure core has no transport: it is wired to the Reticulum transports by the
optional `@reticulum/dacar/transport` subpath. Importing the core
(`@reticulum/dacar`) never pulls it in, and every adapter depends only on
`@reticulum/core` (already a core dependency), so it adds **no new dependency**.

Every transport funnels received bytes through the same verify-on-ingest seam
(`DeltaReceiver.applyPayload()`, §11.2.4): a Delta is decoded, authenticated by
Ed25519 signature, and only then merged — regardless of whether it arrived over
RFed, LXMF, or a scanned QR code.

```js
import {
  RnsIdentityResolver,
  LxmfDeltaDelivery,
  RfedDeltaSync,
  RnsChallengeServer,
  RnsLinkTransport,
  establishLink,
} from "@reticulum/dacar/transport";
```

| Adapter | Spec | Role |
| ------- | ---- | ---- |
| `RnsIdentityResolver` | §3.1, §11.2.4 | Resolves a single-identity Issuer hash to its 64-byte public key via `Destination.recall` (the announce store); Threshold Groups & out-of-band identities fall through to an optional fallback resolver. Usable directly as a `KeyResolver`. |
| `LxmfDeltaDelivery` | §11.2, §11.3 | Targeted, forward-secret Delta delivery over LXMF (store-and-forward to offline nodes), plus LXMF Paper Message export/import for air-gapped/optical (QR) transport. |
| `RfedDeltaSync` | §11.1 | Many-to-many CRDT convergence via RFed (`RFedClient`): publish + receive signed Deltas on a shared, deployment-overridable channel, routed through verify-on-ingest — never the unauthenticated `merge()`. |
| `RnsChallengeServer` / `RnsLinkTransport` / `establishLink` | §8 | The Strict Consistency Challenge over a real RNS Link: an authoritative endpoint answering `dacar.auth.v1` requests, and the client-side `Transport` callable (+ helper to open a Link) for `ChallengeClient`. |

> **The Issuer Hash must be the canonical RNS identity hash.** RNS defines an
> identity hash as `SHA-256(P)[:16]` where `P` is the 64-byte public key
> (`X25519_pub ‖ Ed25519_pub`). `RnsIdentityResolver` recalls exactly that hash;
> any other value cannot be authenticated and is dropped. (Threshold Group IDs
> are exempt — they are resolved by explicit keyset registration, not recall.)

### RFed convergence

```js
import { RFedClient } from "@reticulum/core";
import { DeltaReceiver, StateVector } from "@reticulum/dacar";
import { RfedDeltaSync } from "@reticulum/dacar/transport";

const client = new RFedClient({ identity, rns });
const sync = new RfedDeltaSync({
  receiver: new DeltaReceiver(state, resolver),
  client,
  // topic: "dacar.policy.v1",  // deployment-overridable default
});
await sync.subscribe(nodeHash);          // cache the channel's stamp cost
await sync.listen();                     // receive live fanout Deltas
await sync.publish(deltaPayload, nodeHash);
```

### Strict Consistency Challenge

```js
import { ChallengeClient } from "@reticulum/dacar";
import { RnsChallengeServer, RnsLinkTransport, establishLink } from "@reticulum/dacar/transport";

// Server side: expose the Authoritative Identity on dacar.auth.v1.
await RnsChallengeServer.create({ identity: authority, server, rns });

// Client side: open a Link and challenge it (partition → DENY).
const dest = await Destination.OUT("dacar.auth.v1", DestType.SINGLE, authority, rns);
const link = await establishLink(dest);
const client = new ChallengeClient(config, state, authorityPublicKey, new RnsLinkTransport(link));
await client.authorize("sensor:wind", "calibrate", granteeHash);
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
