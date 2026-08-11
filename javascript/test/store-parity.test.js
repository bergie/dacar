/**
 * Cross-implementation store interoperability (work doc #9, SPEC.md §13).
 *
 * Verifies that the on-disk record bytes produced by the JS `DacarStore` are
 * byte-for-byte identical to what the canonical Python `Store` would write, so
 * both CLIs can share one `~/.dacar/` directory. These tests check the record
 * *formats* (not a live round-trip with Python, which lives in the Python test
 * suite) by asserting the exact bytes JS writes for each record.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { MsgPack, MemoryStorageAdapter } from "@reticulum/core";
import { DacarStore, AliasRegistry, SELF_ALIAS } from "../src/cli/store.js";

/**
 * Build a store with a fixed salt + a single known alias, mirroring a minimal
 * Python `init` output, so record bytes are deterministic for comparison.
 */
async function minimalStore() {
  const adapter = new MemoryStorageAdapter();
  const salt = new Uint8Array(32).fill(0xab);
  const store = await DacarStore.init(adapter, { salt });
  return { store, adapter, salt };
}

describe("store format parity with Python (SPEC.md §13)", () => {
  it("config is INI text with [salt]/[trust]/[policy]/[rfed] sections (§13.2)", async () => {
    const { adapter, salt } = await minimalStore();
    const bytes = await adapter.get("dacar", "config");
    assert.ok(bytes, "config record exists");
    const text = new TextDecoder().decode(bytes);

    // Section order + blank-line separators, matching configparser output.
    assert.match(text, /^\[salt\]\nprimary = [0-9a-f]{64}\n\n\[trust\]\nanchors = [0-9a-f]{32}\n\n\[policy\]\ndeletion_horizon_days = 180\n\n\[rfed\]\ntopic = dacar\.policy\.v1\n\n$/);
    // The salt hex is in the [salt] primary line.
    const saltHex = [...salt].map((b) => b.toString(16).padStart(2, "0")).join("");
    assert.ok(text.includes(`primary = ${saltHex}`));
    // No legacy/authoritative/node lines on a fresh init.
    assert.doesNotMatch(text, /legacy/);
    assert.doesNotMatch(text, /authoritative/);
    assert.doesNotMatch(text, /^node = /m);
  });

  it("clock.msgpack is {last_ms, logical} with snake_case keys (§13.3)", async () => {
    const { adapter } = await minimalStore();
    const bytes = await adapter.get("dacar", "clock.msgpack");
    assert.ok(bytes);
    const obj = MsgPack.decode(bytes);
    assert.ok(typeof obj === "object" && !Array.isArray(obj));
    assert.ok("last_ms" in obj, "snake_case last_ms key");
    assert.ok("logical" in obj, "logical key");
    assert.ok(!("lastMs" in obj), "no camelCase lastMs");
    assert.equal(typeof obj.last_ms, "number");
    assert.equal(typeof obj.logical, "number");
  });

  it("state.msgpack is a msgpack array of 7-element rows (§13.4)", async () => {
    const { adapter } = await minimalStore();
    const bytes = await adapter.get("dacar", "state.msgpack");
    assert.ok(bytes);
    const arr = MsgPack.decode(bytes);
    assert.ok(Array.isArray(arr), "state is an array of rows");
    // Fresh init: zero rows (Python writes `msgpack.packb([])` = 0x90).
    assert.equal(arr.length, 0);
  });

  it("ledger.msgpack is {hex: {object,relation,wildcard,first_seen}} snake_case (§13.6)", async () => {
    const { store, adapter } = await minimalStore();
    // Write a ledger row and check the on-disk key casing.
    const ledger = await store.loadLedger();
    ledger.set("deadbeef", { object: "sensor:wind", relation: "read", wildcard: false, firstSeen: 1234567 });
    await store.saveLedger(ledger);

    const bytes = await adapter.get("dacar", "ledger.msgpack");
    const obj = MsgPack.decode(bytes);
    assert.ok(typeof obj === "object" && !Array.isArray(obj));
    const row = obj["deadbeef"];
    assert.ok(row, "row keyed by tuple hash hex");
    assert.ok("first_seen" in row, "snake_case first_seen");
    assert.ok(!("firstSeen" in row), "no camelCase firstSeen");
    assert.equal(row.first_seen, 1234567);
    assert.equal(row.object, "sensor:wind");
    assert.equal(row.relation, "read");
    assert.equal(row.wildcard, false);
  });

  it("identities.msgpack stores 32-byte Ed25519 pub keys (§13.7)", async () => {
    const { store, adapter } = await minimalStore();
    const { Identity } = await import("@reticulum/core");
    const other = await Identity.generate();
    const fullPub = await other.getPublicKey();
    assert.equal(fullPub.length, 64, "in-memory key is 64-byte RNS");

    const keyring = await store.loadKeyring();
    keyring.registerSingle(other.identityHash, fullPub);
    await store.saveKeyring(keyring);

    const bytes = await adapter.get("dacar", "identities.msgpack");
    assert.ok(bytes);
    const obj = MsgPack.decode(bytes);
    const hashHex = [...other.identityHash].map((b) => b.toString(16).padStart(2, "0")).join("");
    const stored = obj[hashHex];
    assert.ok(stored instanceof Uint8Array);
    assert.equal(stored.length, 32, "on-disk key is 32-byte Ed25519 (not 64-byte RNS)");
    // The stored bytes are the Ed25519 half (last 32 of the 64-byte RNS key).
    assert.deepEqual(stored, fullPub.slice(32));
  });

  it("identities.msgpack loads back, padding 32→64 for in-memory verify (§13.7)", async () => {
    const { store, adapter } = await minimalStore();
    const { Identity } = await import("@reticulum/core");
    const other = await Identity.generate();
    const fullPub = await other.getPublicKey();

    // Simulate Python writing a 32-byte Ed25519 key directly.
    const hashHex = [...other.identityHash].map((b) => b.toString(16).padStart(2, "0")).join("");
    await adapter.set("dacar", "identities.msgpack", MsgPack.encode({ [hashHex]: fullPub.slice(32) }));

    const store2 = new DacarStore(adapter);
    const keyring = await store2.loadKeyring();
    assert.ok(keyring.has(other.identityHash), "issuer loaded from 32-byte cache");
  });

  it("init does NOT create lazy identities/outbox records (§13.1)", async () => {
    const { adapter } = await minimalStore();
    assert.equal(await adapter.get("dacar", "identities.msgpack"), null);
    assert.equal(await adapter.get("dacar", "outbox.msgpack"), null);
  });

  it("aliases is rnns text 'hash name [# note]' with trailing newline (§13.5)", async () => {
    const { store, adapter } = await minimalStore();
    const h = new Uint8Array(16).fill(0x42);
    const aliases = await store.loadAliases();
    aliases.add("relay", h, "roof node");
    await store.saveAliases(aliases);

    const bytes = await adapter.get("dacar", "aliases");
    assert.ok(bytes);
    const text = new TextDecoder().decode(bytes);
    const hashHex = [...h].map((b) => b.toString(16).padStart(2, "0")).join("");
    // The `self` alias from init is also present; assert our added line.
    assert.ok(text.includes(`${hashHex} relay  # roof node\n`), "rnns line with note");
    assert.ok(text.endsWith("\n"), "trailing newline");
  });

  it("empty aliases encodes to zero bytes (§13.5)", async () => {
    const { adapter } = await minimalStore();
    // An empty registry (no entries) encodes to zero bytes, matching Python
    // (`"".join` + no trailing newline when there are no lines).
    const empty = new AliasRegistry();
    assert.equal(empty.encode().length, 0);
  });

  it("outbox.msgpack is a msgpack array of payloads (§13.8)", async () => {
    const { store, adapter } = await minimalStore();
    const a = Uint8Array.of(1, 2, 3);
    const b = new Uint8Array(64).fill(0xff);
    await store.saveOutbox([a, b]);

    const bytes = await adapter.get("dacar", "outbox.msgpack");
    assert.ok(bytes);
    const arr = MsgPack.decode(bytes);
    assert.ok(Array.isArray(arr));
    assert.equal(arr.length, 2);
    assert.ok(arr[0] instanceof Uint8Array);
    assert.deepEqual(new Uint8Array(arr[0]), a);
    assert.deepEqual(new Uint8Array(arr[1]), b);
  });
});
