import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity, MemoryStorageAdapter, toHex } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { RFED_TOPIC } from "../src/naming.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";

import { DacarStore, AliasRegistry, SELF_ALIAS } from "../src/cli/store.js";

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

describe("DacarStore round-trip (doc #6)", () => {
  /** @type {MemoryStorageAdapter} */ let adapter;
  /** @type {DacarStore} */ let store;
  /** @type {Identity} */ let identity;

  before(async () => {
    adapter = new MemoryStorageAdapter();
    store = await DacarStore.init(adapter, { salt: HASHER.salt });
    identity = await store.loadIdentity();
    assert.ok(identity, "init created an identity");
  });

  it("init writes config with own identity as the root anchor", async () => {
    const raw = await store.loadConfig();
    assert.equal(raw.anchors.length, 1);
    assert.deepEqual(raw.anchors[0], identity.identityHash);
    assert.equal(raw.rfedTopic, RFED_TOPIC);
    assert.equal(raw.rfedNode, null);
  });

  it("init writes the self alias", async () => {
    const aliases = await store.loadAliases();
    assert.deepEqual(aliases.resolve(SELF_ALIAS), identity.identityHash);
  });

  it("config round-trips and survives a new store instance", async () => {
    const raw = await store.loadConfig();
    raw.rfedTopic = "myorg.policy.v1";
    raw.rfedNode = new Uint8Array(16).fill(0xab);
    await store.saveConfig(raw);

    const store2 = new DacarStore(adapter);
    const raw2 = await store2.loadConfig();
    assert.equal(raw2.rfedTopic, "myorg.policy.v1");
    assert.deepEqual(raw2.rfedNode, new Uint8Array(16).fill(0xab));
    assert.deepEqual(raw2.primarySalt, raw.primarySalt);
  });

  it("loadConfigValidated returns a Config with primaryHasher", async () => {
    console.debug('=== about to call loadConfigValidated ===');
    const config = await store.loadConfigValidated();
    console.debug('loaded config rootTrustAnchors:', config.rootTrustAnchors);
    console.debug('loaded config rootTrustAnchors type:', typeof config.rootTrustAnchors);
    console.debug('rootTrustAnchors.length:', config.rootTrustAnchors?.length);
    console.debug('loaded config primaryHasher:', config.primaryHasher ? 'ok' : 'missing');
    assert.equal([...config.rootTrustAnchors].length, 1);
    console.debug('rootTrustAnchors.length assertion passed');
    assert.ok(config.primaryHasher);
    console.debug('primaryHasher assertion passed');
    assert.equal(config.deletionHorizonDays, 180);
    console.debug('deletionHorizonDays assertion passed');
  });

  it("clock round-trips and persists lastMs/logical", async () => {
    const clock = await store.loadClock();
    console.debug('clock before now:', clock.lastMs, clock.logical);
    const ts = clock.now();
    console.debug('clock after now:', clock.lastMs, clock.logical);
    await store.saveClock(clock);

    const clock2 = await store.loadClock();
    console.debug('clock2 after reload:', clock2.lastMs, clock2.logical);
    assert.ok(clock2.lastMs > 0, "lastMs persisted");
  });

  it("state (CRDT) round-trips through toPayload/fromPayload", async () => {
    const config = await store.loadConfigValidated();
    const state = await store.loadState(config);
    const payload = await signedDelta(identity.identityHash, identity);
    const keyring = new Keyring();
    keyring.registerSingle(identity.identityHash, await identity.getPublicKey());
    const rx = new DeltaReceiver(state, keyring);
    const applied = await rx.applyPayload(payload);
    assert.ok(applied, "delta applied");
    await store.saveState(state);

    const state2 = await store.loadState(config);
    let count = 0;
    for (const t of state2.activeTuples()) count++;
    assert.equal(count, 1);
  });

  it("ledger round-trips a plaintext record", async () => {
    const ledger = await store.loadLedger();
    ledger.set("deadbeef", { object: "sensor:wind", relation: "read", wildcard: false, firstSeen: 1234567 });
    await store.saveLedger(ledger);

    const ledger2 = await store.loadLedger();
    assert.equal(ledger2.get("deadbeef").relation, "read");
  });

  it("identities cache round-trips a registered issuer (doc #5 parity)", async () => {
    const other = await Identity.generate();
    const keyring = new Keyring();
    keyring.registerSingle(other.identityHash, await other.getPublicKey());
    await store.saveKeyring(keyring);

    const store2 = new DacarStore(adapter);
    const keyring2 = await store2.loadKeyring();
    assert.ok(keyring2.has(other.identityHash), "issuer persisted across instances");
  });

  it("keyringForVerify includes the own identity on top of cache", async () => {
    const keyring = await store.keyringForVerify();
    assert.ok(keyring.has(identity.identityHash), "own identity registered");
  });

  it("rejects a forged identities cache entry (bad pub key length)", async () => {
    const bad = await store.loadKeyring();
    // Manually write a malformed record through the adapter.
    const { MsgPack } = await import("@reticulum/core");
    const forged = MsgPack.encode({ ["00".repeat(16)]: new Uint8Array(10) });
    await adapter.set("dacar", "identities", forged);
    const keyring = await store.loadKeyring();
    assert.equal(keyring.size, 0, "malformed entry dropped, not trusted");
  });
});

describe("AliasRegistry", () => {
  it("add is idempotent and keeps first name as primary", () => {
    const h = new Uint8Array(16).fill(1);
    const aliases = new AliasRegistry();
    aliases.add("alice", h);
    aliases.add("alice", h); // idempotent
    aliases.add("node-a", h, "primary laptop");
    assert.deepEqual(aliases.resolve("alice"), h);
    assert.deepEqual(aliases.resolve("node-a"), h);
    assert.equal(aliases.primaryName(h), "alice");
    assert.equal(aliases.namesFor(h).length, 2);
  });

  it("setSelf moves the self alias between identities", () => {
    const a = new Uint8Array(16).fill(1);
    const b = new Uint8Array(16).fill(2);
    const aliases = new AliasRegistry();
    aliases.add(SELF_ALIAS, a);
    aliases.setSelf(b);
    assert.deepEqual(aliases.resolve(SELF_ALIAS), b);
    // old identity still has no alias (self was its only name)
    assert.equal(aliases.primaryName(a), null);
  });

  it("round-trips through encode/decode", () => {
    const h = new Uint8Array(16).fill(3);
    const aliases = new AliasRegistry();
    aliases.add("relay", h, "roof node");
    const bytes = aliases.encode();
    const decoded = AliasRegistry.decode(bytes);
    assert.deepEqual(decoded.resolve("relay"), h);
    assert.equal(decoded.entries[0].note, "roof node");
  });
});
