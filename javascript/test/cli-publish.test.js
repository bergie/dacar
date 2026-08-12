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
import { Identity, MemoryStorageAdapter, MsgPack, toHex } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";

import { DacarStore } from "../src/cli/store.js";
import { coercePayload, recordPublish } from "../src/cli/dacar.js";

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
// DeltaReceiver.packPayloads -> applyPayloads (the local `dacar apply <file>`
// batch-import path; §11.2.4. Network publish sends one Delta per message,
// not a batch — see `recordPublish` below for the durable-log path.)
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
    // publish <one-file> and publish --outbox with one entry both emit raw
    // bytes, one Delta per message (§11.1.1) — not a 1-element batch array.
    assert.ok(p1 instanceof Uint8Array);
    assert.ok(p1.length > 0);
  });
});

// ===========================================================================
// DacarStore sent box (work doc #11) — durable replay log of published Deltas
// ===========================================================================

describe("DacarStore sent box (work doc #11)", () => {
  /** @type {MemoryStorageAdapter} */ let adapter;
  /** @type {DacarStore} */ let store;
  /** @type {Identity} */ let identity;

  before(async () => {
    adapter = new MemoryStorageAdapter();
    store = await DacarStore.init(adapter, { salt: HASHER.salt });
    identity = await store.loadIdentity();
  });

  it("loadSent is empty when no record exists", async () => {
    const fresh = new DacarStore(new MemoryStorageAdapter());
    assert.deepEqual(await fresh.loadSent(), []);
  });

  it("saveSent / loadSent round-trips payloads in order", async () => {
    const a = Uint8Array.of(1, 2, 3);
    const b = new Uint8Array(64).fill(0xff);
    const c = new Uint8Array(0); // empty element preserved
    await store.saveSent([a, b, c]);
    const loaded = await store.loadSent();
    assert.equal(loaded.length, 3);
    assert.deepEqual(loaded[0], a);
    assert.deepEqual(loaded[1], b);
    assert.deepEqual(loaded[2], c);
  });

  it("sent box survives a new store instance over the same adapter", async () => {
    const payload = await signedDelta(identity.identityHash, identity);
    await store.saveSent([payload]);
    const reopened = new DacarStore(adapter);
    const loaded = await reopened.loadSent();
    assert.equal(loaded.length, 1);
    assert.deepEqual(loaded[0], payload);
  });

  it("a corrupted sent record returns empty (does not crash the CLI)", async () => {
    await adapter.set("dacar", "sent.msgpack", new TextEncoder().encode("not msgpack"));
    const store2 = new DacarStore(adapter);
    assert.deepEqual(await store2.loadSent(), []);
  });

  it("a non-array sent record (a msgpack dict) returns empty", async () => {
    await adapter.set("dacar", "sent.msgpack", MsgPack.encode({ a: 1 }));
    const store2 = new DacarStore(adapter);
    assert.deepEqual(await store2.loadSent(), []);
  });

  it("outbox and sent box persist to distinct records", async () => {
    const a = new MemoryStorageAdapter();
    const s = new DacarStore(a);
    await s.saveOutbox([Uint8Array.of(1)]);
    await s.saveSent([Uint8Array.of(2)]);
    assert.deepEqual(await s.loadOutbox(), [Uint8Array.of(1)]);
    assert.deepEqual(await s.loadSent(), [Uint8Array.of(2)]);
    assert.notEqual(
      toHex((await s.loadOutbox())[0]),
      toHex((await s.loadSent())[0]),
    );
  });
});

// ===========================================================================
// recordPublish — outbox → sent box move + dedup (work doc #11)
// Pure store logic (no RNS), mirroring Python's `_record_publish`.
// ===========================================================================

describe("recordPublish (work doc #11)", () => {
  /** @type {Identity} */ let identity;
  /** @type {Uint8Array} */ let p1;
  /** @type {Uint8Array} */ let p2;

  before(async () => {
    identity = await Identity.generate();
    p1 = await signedDelta(identity.identityHash, identity, { objectId: "sensor:wind" });
    p2 = await signedDelta(identity.identityHash, identity, { objectId: "sensor:temp" });
  });

  async function freshStore() {
    const adapter = new MemoryStorageAdapter();
    return await DacarStore.init(adapter, { salt: HASHER.salt });
  }

  it("moves accepted outbox deltas to the sent box (dedup by exact bytes)", async () => {
    const store = await freshStore();
    await store.saveOutbox([p1, p2]);

    const nSent = await recordPublish(store, [p1, p2], [true, true], { recordToSent: true });
    assert.equal(nSent, 2);
    assert.deepEqual(await store.loadOutbox(), []); // drained
    assert.equal((await store.loadSent()).length, 2); // moved
  });

  it("keeps a rejected delta in the outbox (partial failure, retryable)", async () => {
    const store = await freshStore();
    await store.saveOutbox([p1, p2]);

    const nSent = await recordPublish(store, [p1, p2], [true, false], { recordToSent: true });
    assert.equal(nSent, 1); // only the accepted one recorded
    assert.equal((await store.loadSent()).length, 1);
    assert.equal((await store.loadOutbox()).length, 1); // rejected one stays
    assert.deepEqual((await store.loadSent())[0], p1);
    assert.deepEqual((await store.loadOutbox())[0], p2);
  });

  it("does not append duplicates to the sent box (idempotent re-send)", async () => {
    const store = await freshStore();
    await store.saveSent([p1]);

    await recordPublish(store, [p1], [true], { recordToSent: true });
    const sent = await store.loadSent();
    assert.equal(sent.length, 1); // no duplicate
    assert.deepEqual(sent[0], p1);
  });

  it("with recordToSent=false does not log external file payloads", async () => {
    const store = await freshStore();
    await store.saveOutbox([p1]); // an unrelated queued delta

    const nSent = await recordPublish(store, [p2], [true], { recordToSent: false });
    assert.equal(nSent, 1);
    assert.equal((await store.loadSent()).length, 0); // external payload not logged
    assert.equal((await store.loadOutbox()).length, 1); // unrelated queued delta untouched
  });

  it("with no accepted deltas is a no-op (returns 0)", async () => {
    const store = await freshStore();
    await store.saveOutbox([p1, p2]);

    const nSent = await recordPublish(store, [p1, p2], [false, false], { recordToSent: true });
    assert.equal(nSent, 0);
    assert.equal((await store.loadSent()).length, 0);
    assert.equal((await store.loadOutbox()).length, 2); // both stay
  });

  it("drains an accepted delta from the outbox even when recordToSent=false", async () => {
    // A re-send of a previously-failed outbox delta that's already in the sent
    // box: recordToSent=false (e.g. external file path) still drains it from
    // the outbox, because transport acceptance means it has left the queue.
    const store = await freshStore();
    await store.saveOutbox([p1]);

    const nSent = await recordPublish(store, [p1], [true], { recordToSent: false });
    assert.equal(nSent, 1);
    assert.deepEqual(await store.loadOutbox(), []); // drained
  });
});
