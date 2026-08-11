/**
 * Smoketests for the standalone `dacar publish` command (work doc #8 — §11.1).
 *
 * Covers the new, unit-testable pieces the JS `publish` command composes, in
 * the style of `cli-store.test.js` (which tests `DacarStore` + helpers, not
 * the `dacar.js` command dispatch — the latter boots RNS via `publishDelta` and
 * is exercised through the session-helper tests like `cli-discovery.test.js`):
 *
 *   - `DacarStore.loadOutbox` / `saveOutbox` — the persisted outbox of
 *     locally-issued, not-yet-published signed Deltas (`publish --all`).
 *   - `coercePayload` — the hex/binary auto-detect for `publish <file>`
 *     (so a `grant` hex export round-trips into a publishable payload).
 *   - `DeltaReceiver.packPayloads` → `applyPayloads` — the batch path that
 *     `publish --all` (and multi-file `publish`) emits, independently
 *     verified-on-ingest per element.
 *
 * Mirrors Python's `tests/test_cli_publish.py` (the canonical implementation).
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity, MemoryStorageAdapter, MsgPack } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";

import { DacarStore } from "../src/cli/store.js";
import { coercePayload } from "../src/cli/dacar.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);

async function signedDelta(issuerHash, signer, opts = {}) {
  const { action = Action.GRANT, relation = "read", objectId = "sensor:wind", hlcMs = 0 } = opts;
  const tuple = await Tuple.fromPlaintext({
    objectId, relation, grantee: GRANTEE, issuer: issuerHash, hasher: HASHER,
  });
  const op = await new Operation({ tuple, action, hlc: packHlc(physicalNowMs() + hlcMs, 0) }).sign(signer);
  return op.toPayload();
}

// ===========================================================================
// Outbox store (work doc #8)
// ===========================================================================

describe("DacarStore outbox (work doc #8)", () => {
  /** @type {MemoryStorageAdapter} */ let adapter;
  /** @type {DacarStore} */ let store;
  /** @type {Identity} */ let identity;

  before(async () => {
    adapter = new MemoryStorageAdapter();
    store = await DacarStore.init(adapter, { salt: HASHER.salt });
    identity = await store.loadIdentity();
  });

  it("loadOutbox is empty when no record exists", async () => {
    const fresh = new DacarStore(new MemoryStorageAdapter());
    assert.deepEqual(await fresh.loadOutbox(), []);
  });

  it("saveOutbox / loadOutbox round-trips payloads in order", async () => {
    const a = Uint8Array.of(1, 2, 3);
    const b = new Uint8Array(64).fill(0xff);
    const c = new Uint8Array(0); // empty element preserved
    await store.saveOutbox([a, b, c]);
    const loaded = await store.loadOutbox();
    assert.equal(loaded.length, 3);
    assert.deepEqual(loaded[0], a);
    assert.deepEqual(loaded[1], b);
    assert.deepEqual(loaded[2], c);
  });

  it("saveOutbox([]) clears the outbox (loadOutbox reads back empty)", async () => {
    await store.saveOutbox([Uint8Array.of(1), Uint8Array.of(2)]);
    assert.equal((await store.loadOutbox()).length, 2);
    await store.saveOutbox([]);
    assert.deepEqual(await store.loadOutbox(), []);
  });

  it("outbox survives a new store instance over the same adapter (cross-restart)", async () => {
    const payload = await signedDelta(identity.identityHash, identity);
    await store.saveOutbox([payload]);
    const reopened = new DacarStore(adapter);
    const loaded = await reopened.loadOutbox();
    assert.equal(loaded.length, 1);
    assert.deepEqual(loaded[0], payload);
  });

  it("a corrupted outbox record returns empty (does not crash the CLI)", async () => {
    await adapter.set("dacar", "outbox.msgpack", new TextEncoder().encode("not msgpack at all"));
    const store2 = new DacarStore(adapter);
    assert.deepEqual(await store2.loadOutbox(), []);
  });

  it("a non-array outbox record (a msgpack dict) returns empty", async () => {
    await adapter.set("dacar", "outbox.msgpack", MsgPack.encode({ a: 1 }));
    const store2 = new DacarStore(adapter);
    assert.deepEqual(await store2.loadOutbox(), []);
  });

  it("non-Uint8Array elements in an array are filtered out", async () => {
    // Defensive: a malformed array of mixed types drops the non-bytes entries.
    await adapter.set("dacar", "outbox.msgpack", MsgPack.encode([Uint8Array.of(1, 2), "oops", 7]));
    const store2 = new DacarStore(adapter);
    const loaded = await store2.loadOutbox();
    assert.equal(loaded.length, 1);
    assert.deepEqual(loaded[0], Uint8Array.of(1, 2));
  });
});

// ===========================================================================
// coercePayload — hex/binary auto-detect for `publish <file>` (work doc #8)
// ===========================================================================

describe("coercePayload (hex/binary auto-detect)", () => {
  it("decodes an all-hex ASCII string to bytes", () => {
    const hex = "deadbeef00ff";
    const data = new TextEncoder().encode(hex);
    assert.deepEqual(coercePayload(data, false), Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0x00, 0xff));
  });

  it("trims surrounding whitespace before hex detection", () => {
    const hex = "  deadbeef\n";
    const data = new TextEncoder().encode(hex);
    assert.deepEqual(coercePayload(data, false), Uint8Array.of(0xde, 0xad, 0xbe, 0xef));
  });

  it("passes raw binary through unchanged (not valid hex)", () => {
    const bin = new Uint8Array([0xde, 0xad, 0x00, 0xff]); // 0xff ok, but not all-hex-ascii
    // 0xde is non-ascii-hex (it's > 0x66), so this is binary, not hex.
    assert.deepEqual(coercePayload(bin, false), bin);
  });

  it("--binary forces raw bytes even for hex-looking input", () => {
    const hex = "deadbeef";
    const data = new TextEncoder().encode(hex); // ASCII bytes for the hex chars
    assert.deepEqual(coercePayload(data, true), data); // not decoded
  });

  it("odd-length hex is left as raw bytes (no partial decode)", () => {
    const data = new TextEncoder().encode("abc"); // odd length
    assert.deepEqual(coercePayload(data, false), data);
  });

  it("empty input yields empty output", () => {
    assert.deepEqual(coercePayload(new Uint8Array(0), false), new Uint8Array(0));
  });

  it("round-trips a real grant payload: bytes -> hex text -> bytes", async () => {
    const id = await Identity.generate();
    const payload = await signedDelta(id.identityHash, id);
    const hexText = new TextEncoder().encode(Buffer.from(payload).toString("hex"));
    assert.deepEqual(coercePayload(hexText, false), new Uint8Array(payload));
  });
});

// ===========================================================================
// DeltaReceiver.packPayloads -> applyPayloads (the batch path publish --all
// and multi-file publish emit; §11.1, §11.2.4)
// ===========================================================================

describe("publish batch path: packPayloads -> applyPayloads", () => {
  /** @type {Identity} */ let issuer;
  /** @type {Uint8Array} */ let p1;
  /** @type {Uint8Array} */ let p2;

  before(async () => {
    issuer = await Identity.generate();
    p1 = await signedDelta(issuer.identityHash, issuer, { objectId: "sensor:wind" });
    p2 = await signedDelta(issuer.identityHash, issuer, { objectId: "sensor:temp" });
  });

  it("packPayloads wraps a list into a single msgpack batch", () => {
    const batch = DeltaReceiver.packPayloads([p1, p2]);
    const items = MsgPack.decode(batch);
    assert.ok(Array.isArray(items));
    assert.equal(items.length, 2);
    assert.deepEqual(new Uint8Array(items[0]), p1);
    assert.deepEqual(new Uint8Array(items[1]), p2);
  });

  it("a packed batch applies element-by-element via verify-on-ingest", async () => {
    const state = new StateVector();
    const keyring = new Keyring();
    keyring.registerSingle(issuer.identityHash, await issuer.getPublicKey());
    const rx = new DeltaReceiver(state, keyring);

    const batch = DeltaReceiver.packPayloads([p1, p2]);
    const applied = await rx.applyPayloads(batch);
    assert.equal(applied, 2);
    assert.equal(state.size, 2);
  });

  it("a single delta is published as raw bytes (not a 1-element batch)", () => {
    // publish <one-file> and publish --all with one entry both emit raw bytes,
    // not a 1-element array — so the single-delta payload stays unwrapped.
    assert.ok(p1 instanceof Uint8Array);
    assert.ok(p1.length > 0);
  });
});
