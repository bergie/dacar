/**
 * Smoketests for the Node CLI's feature-parity with the canonical Python CLI
 * (`dacar/cli/commands.py`): salt rotation, anchors, identity show/new,
 * aliases, ledger annotate, show, validate, prune (outbox/sent horizon), and
 * the grant/revoke flag surface (`--no-apply`, `-o/--out`, `--binary`,
 * `--legacy` errors, `--copy-hashes`).
 *
 * The offline `cmd_*` implementations run against a real `DacarFileAdapter`
 * store directory (the same layout the Python CLI reads/writes); stderr is
 * captured so test output stays clean.
 *
 * Mirrors Python's `tests/test_cli_*.py` suites (the canonical implementation).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { toHex } from "@reticulum/core";

import { packHlc } from "../src/hlc.js";
import { Tuple } from "../src/tuple.js";

import {
  renderIdentity, utcFromHlc, hlcHex, prunePayloadList,
  runCommand,
  cmdInit, cmdSaltNew, cmdSaltSet, cmdAnchorAdd, cmdAnchorList,
  cmdIdentityNew, cmdGrant, cmdRevoke, cmdCheck, cmdShow, cmdValidate,
  cmdPrune, cmdAliasAdd, cmdAliasRemove, cmdAliasResolve, cmdLedgerAnnotate,
} from "../src/cli/dacar.js";
import { DacarStore } from "../src/cli/store.js";
import { DacarFileAdapter } from "../src/cli/fileStore.js";
import { NamespaceHasher, DEFAULT_SALT } from "../src/namespace.js";
import { Operation, Action } from "../src/operation.js";

/** Capture stderr (and optionally stdout) while running `fn`. */
async function capture(fn, { stdout = false } = {}) {
  const errChunks = [];
  const outChunks = [];
  const origErr = process.stderr.write.bind(process.stderr);
  const origOut = process.stdout.write.bind(process.stdout);
  process.stderr.write = (chunk) => { errChunks.push(String(chunk)); return true; };
  if (stdout) process.stdout.write = (chunk) => { outChunks.push(String(chunk)); return true; };
  try {
    const code = await fn();
    return { code, stderr: errChunks.join(""), stdout: outChunks.join("") };
  } finally {
    process.stderr.write = origErr;
    if (stdout) process.stdout.write = origOut;
  }
}

const HASHER = new NamespaceHasher(DEFAULT_SALT);
let root;

before(() => {
  root = mkdtempSync(join(tmpdir(), "dacar-cli-parity-"));
});
after(() => {
  rmSync(root, { recursive: true, force: true });
});

async function initStore(name, opts = {}) {
  const dir = join(root, name);
  const { code } = await capture(() => cmdInit({ store: dir, horizon: "180", ...opts }));
  assert.equal(code, 0);
  return dir;
}

async function storeAt(dir) {
  return new DacarStore(new DacarFileAdapter(dir));
}

// ===========================================================================
// helpers
// ===========================================================================

describe("parity helpers", () => {
  it("renderIdentity uses the <alias> (<hash>…) convention", () => {
    const registry = /** @type {any} */ ({
      primaryName: (h) => (toHex(h).startsWith("aa") ? "bergie" : null),
    });
    const hash = Uint8Array.from({ length: 16 }, (_, i) => 0xaa);
    assert.equal(renderIdentity(hash, registry, false), "bergie (aaaaaaa…)");
    assert.equal(renderIdentity(hash, registry, true), `bergie (${toHex(hash)})`);
    const unknown = Uint8Array.from({ length: 16 }, (_, i) => 0xbb);
    assert.equal(renderIdentity(unknown, registry, false), "? (bbbbbbb…)");
  });

  it("utcFromHlc renders '-' for null and UTC YYYY-MM-DD HH:MM otherwise", () => {
    assert.equal(utcFromHlc(null), "-");
    assert.equal(utcFromHlc(0n), "-");
    // 2025-01-02T03:04 UTC
    const ms = Date.UTC(2025, 0, 2, 3, 4);
    assert.equal(utcFromHlc(packHlc(ms, 0)), "2025-01-02 03:04");
  });

  it("hlcHex zero-pads to 16 hex digits", () => {
    assert.equal(hlcHex(0x1n), "0x0000000000000001");
  });
});

// ===========================================================================
// init / salt / anchors
// ===========================================================================

describe("init + salt + anchor commands", () => {
  it("init records the store and --salt accepts a 32-byte file path", async () => {
    const dir = join(root, "init-file-salt");
    const saltFile = join(root, "salt.bin");
    writeFileSync(saltFile, Uint8Array.from({ length: 32 }, (_, i) => i + 1));
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdInit({ store: dir, salt: saltFile, horizon: "180" })))
    assert.equal(code, 0);
    assert.match(stderr, /✔ initialized store/);
    const store = await storeAt(dir);
    const raw = await store.loadConfig();
    assert.deepEqual([...raw.primarySalt], Array.from({ length: 32 }, (_, i) => i + 1));
  });

  it("init refuses to re-initialize an existing store", async () => {
    const dir = await initStore("init-twice");
    const { code, stderr } = await capture(() => runCommand(() => cmdInit({ store: dir })));
    assert.equal(code, 1);
    assert.match(stderr, /store already initialized/);
  });

  it("salt new rotates primary → legacy0 (§10.2)", async () => {
    const dir = await initStore("salt-new");
    const store = await storeAt(dir);
    const before = await store.loadConfig();
    const { code, stderr } = await capture(() => runCommand(() => cmdSaltNew({ store: dir })));
    assert.equal(code, 0);
    assert.match(stderr, /rotated primary salt/);
    const after = await store.loadConfig();
    assert.deepEqual([...after.legacySalts[0]], [...before.primarySalt]);
    assert.notDeepEqual([...after.primarySalt], [...before.primarySalt]);
  });

  it("salt set --hex replaces the primary salt", async () => {
    const dir = await initStore("salt-set");
    const hex = "11".repeat(32);
    const { code } = await capture(() => runCommand(() => cmdSaltSet({ store: dir, hex })));
    assert.equal(code, 0);
    const store = await storeAt(dir);
    const raw = await store.loadConfig();
    assert.equal(toHex(raw.primarySalt), hex);
  });

  it("salt set rejects a wrong-length hex value", async () => {
    const dir = await initStore("salt-set-bad");
    const { code, stderr } = await capture(() => runCommand(() => cmdSaltSet({ store: dir, hex: "11".repeat(16) })));
    assert.equal(code, 1);
    assert.match(stderr, /salt must be 32 bytes/);
  });

  it("anchor add appends a Root Trust Anchor; duplicates are refused", async () => {
    const dir = await initStore("anchor");
    const hash = "22".repeat(16);
    const { code, stderr } = await capture(() => runCommand(() => cmdAnchorAdd({ store: dir, hash })));
    assert.equal(code, 0);
    assert.match(stderr, /added anchor/);
    const store = await storeAt(dir);
    const raw = await store.loadConfig();
    assert.ok(raw.anchors.some((a) => toHex(a) === hash));

    const dup = await capture(() => runCommand(() => cmdAnchorAdd({ store: dir, hash })));
    assert.equal(dup.code, 1);
    assert.match(dup.stderr, /anchor already present/);
  });

  it("anchor list reports the anchors", async () => {
    const dir = await initStore("anchor-list");
    const { code, stderr } = await capture(() => runCommand(() => cmdAnchorList({ store: dir })));
    assert.equal(code, 0);
    assert.match(stderr, /ROOT TRUST ANCHORS \(1\)/);
  });
});

// ===========================================================================
// identity show / new
// ===========================================================================

describe("identity show / new", () => {
  it("identity new rotates the self-anchor and the self alias", async () => {
    const dir = await initStore("identity-new");
    const store = await storeAt(dir);
    const before = await store.loadIdentity();
    const { code, stderr } = await capture(() => runCommand(() => cmdIdentityNew({ store: dir })));
    assert.equal(code, 0);
    assert.match(stderr, /generated new signing identity/);
    const after = await store.loadIdentity();
    assert.notEqual(toHex(after.identityHash), toHex(before.identityHash));
    const raw = await store.loadConfig();
    assert.ok(raw.anchors.some((a) => toHex(a) === toHex(after.identityHash)));
    assert.ok(!raw.anchors.some((a) => toHex(a) === toHex(before.identityHash)));
    const aliases = await store.loadAliases();
    assert.deepEqual([...aliases.resolve("self")], [...after.identityHash]);
  });
});

// ===========================================================================
// grant / revoke flag surface
// ===========================================================================

describe("grant / revoke flags", () => {
  /** @type {string} */ let dir;
  /** @type {DacarStore} */ let store;
  /** @type {string} */ let granteeHex;

  before(async () => {
    dir = await initStore("grant-flags");
    store = await storeAt(dir);
    granteeHex = toHex((await store.loadIdentity()).identityHash);
  });

  it("grant applies locally, records the ledger, and queues the outbox", async () => {
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdGrant({ store: dir, grantee: granteeHex, relation: "read", object: "sensor:wind" })))
    assert.equal(code, 0);
    assert.match(stderr, /granted/);
    const config = await store.loadConfigValidated();
    const state = await store.loadState(config);
    assert.equal(state.size, 1);
    assert.equal((await store.loadOutbox()).length, 1);
  });

  it("check ALLOWs the granted tuple and shows the trace", async () => {
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdCheck({ store: dir, grantee: granteeHex, relation: "read", object: "sensor:wind" })))
    assert.equal(code, 0);
    assert.match(stderr, /ALLOW/);
    assert.match(stderr, /is a Root Trust Anchor/);
  });

  it("check DENYs an ungranted object", async () => {
    const { code } = await capture(() => runCommand(() =>
      cmdCheck({ store: dir, grantee: granteeHex, relation: "read", object: "other" })))
    assert.equal(code, 1);
  });

  it("show resolves the alias:relation:object form", async () => {
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdShow({ store: dir, ref: `self:read:sensor:wind` })))
    assert.equal(code, 0);
    assert.match(stderr, /tuple   : /);
    assert.match(stderr, /status  : ACTIVE/);
  });

  it("--no-apply signs and queues without touching the CRDT", async () => {
    const config = await store.loadConfigValidated();
    const stateBefore = (await store.loadState(config)).size;
    const outboxBefore = (await store.loadOutbox()).length;
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdGrant({ store: dir, grantee: granteeHex, relation: "write", object: "sensor:temp", "no-apply": true })))
    assert.equal(code, 0);
    assert.match(stderr, /not applied locally: --no-apply/);
    assert.equal((await store.loadState(config)).size, stateBefore);
    assert.equal((await store.loadOutbox()).length, outboxBefore + 1);
  });

  it("-o/--out writes the binary payload to a file instead of stdout", async () => {
    const outFile = join(root, "delta.bin");
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdGrant({ store: dir, grantee: granteeHex, relation: "admin", object: "sensor:wind", out: outFile })), { stdout: true });
    assert.equal(code, 0);
    assert.match(stderr, /binary file/);
    const payload = readFileSync(outFile);
    // A §5.3 Operation payload parses back cleanly.
    const op = Operation.fromPayload(new Uint8Array(payload));
    assert.equal(op.action, Action.GRANT);
  });

  it("--legacy with an out-of-range index fails clearly", async () => {
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdGrant({ store: dir, grantee: granteeHex, relation: "read", object: "x", legacy: "0" })))
    assert.equal(code, 1);
    assert.match(stderr, /--legacy index 0 out of range/);
  });

  it("--copy-hashes revokes by exact pre-hashed tuple fields", async () => {
    const config = await store.loadConfigValidated();
    const state = await store.loadState(config);
    const entry = [...state._entries.values()]
      .find((e) => e.tuple.grantee.length && e.removeTs === null && e.addTs !== null);
    assert.ok(entry, "expected an active tuple");
    const t = entry.tuple;
    const copyFile = join(root, "copy-hashes.txt");
    writeFileSync(copyFile,
      `relation_hash=${toHex(t.relationHash)}\n` +
      `object_hashes=${t.objectHashes.map(toHex).join(":")}\n` +
      `wildcard=${t.wildcard}\n`);
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdRevoke({ store: dir, grantee: granteeHex, "copy-hashes": copyFile })))
    assert.equal(code, 0);
    assert.match(stderr, /copy-hashes/);
    // Same preimage → same CRDT entry got its remove timestamp.
    const after = await (await storeAt(dir)).loadState(config);
    const revoked = after.get(t.key);
    assert.ok(revoked && revoked.removeTs !== null);
  });
});

// ===========================================================================
// aliases / ledger annotate
// ===========================================================================

describe("alias + ledger commands", () => {
  /** @type {string} */ let dir;
  before(async () => {
    dir = await initStore("alias-ledger");
  });

  it("alias add → resolve → remove round-trips", async () => {
    const hash = "33".repeat(16);
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdAliasAdd({ store: dir, name: "peer", hash, note: "test peer" })))
    assert.equal(code, 0);
    assert.match(stderr, /alias "peer" → peer \(/);

    const { stdout } = await capture(() => runCommand(() =>
      cmdAliasResolve({ store: dir, name: "peer" })), { stdout: true });
    assert.equal(stdout.trim(), hash);

    // An alias may not be re-pointed at a different hash.
    const conflict = await capture(() => runCommand(() =>
      cmdAliasAdd({ store: dir, name: "peer", hash: "44".repeat(16) })))
    assert.equal(conflict.code, 1);
    assert.match(conflict.stderr, /already names a different hash/);

    const removed = await capture(() => runCommand(() => cmdAliasRemove({ store: dir, name: "peer" })))
    assert.equal(removed.code, 0);
    const missing = await capture(() => runCommand(() => cmdAliasResolve({ store: dir, name: "peer" })), { stdout: true });
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /unknown alias/);
  });

  it("ledger annotate attaches plaintext to a tuple hash", async () => {
    const tupleHash = "55".repeat(32);
    const { code, stderr } = await capture(() => runCommand(() =>
      cmdLedgerAnnotate({ store: dir, tupleHash, object: "sensor:wind", relation: "read" })))
    assert.equal(code, 0);
    assert.match(stderr, /annotated tuple/);
    const store = await storeAt(dir);
    const ledger = await store.loadLedger();
    const row = ledger.get(tupleHash);
    assert.equal(row.object, "sensor:wind");
    assert.equal(row.relation, "read");
  });
});

// ===========================================================================
// validate / prune
// ===========================================================================

describe("validate + prune", () => {
  it("validate passes on a clean store", async () => {
    const dir = await initStore("validate-clean");
    const { code, stderr } = await capture(() => runCommand(() => cmdValidate({ store: dir })))
    assert.equal(code, 0);
    assert.match(stderr, /No corruption detected/);
  });

  it("validate flags a comma-separated ledger object (Python parity)", async () => {
    const dir = await initStore("validate-corrupt");
    const store = await storeAt(dir);
    const ledger = await store.loadLedger();
    ledger.set("66".repeat(32), { object: "a,b", relation: "read", wildcard: false, firstSeen: 0 });
    await store.saveLedger(ledger);
    const { code, stderr } = await capture(() => runCommand(() => cmdValidate({ store: dir })));
    assert.equal(code, 1);
    assert.match(stderr, /object contains comma/);
  });

  it("prune drops outbox/sent deltas older than the §9 horizon", async () => {
    const dir = await initStore("prune");
    const store = await storeAt(dir);
    const identity = await store.loadIdentity();
    const grantee = identity.identityHash;
    const makeDelta = async (ms) => {
    const tuple = await Tuple.fromPlaintext({
        objectId: `o:${ms}`, relation: "read", grantee, issuer: identity.identityHash, hasher: HASHER,
      });
      const op = await new Operation({ tuple, action: Action.GRANT, hlc: packHlc(ms, 0) }).sign(identity);
      return op.toPayload();
    };
    const stale = await makeDelta(1000); // epoch-adjacent → far beyond the horizon
    const fresh = await makeDelta(Date.now());
    await store.saveOutbox([stale, fresh]);
    await store.saveSent([stale]);

    const { code, stderr } = await capture(() => runCommand(() => cmdPrune({ store: dir })));
    assert.equal(code, 0);
    assert.match(stderr, /outbox: pruned 1 stale delta/);
    assert.match(stderr, /sent: pruned 1 stale delta/);
    const after = await storeAt(dir);
    assert.deepEqual(await after.loadOutbox(), [fresh]);
    assert.deepEqual(await after.loadSent(), []);
  });

  it("prunePayloadList keeps undecodable payloads (never destroys on error)", () => {
    const garbage = Uint8Array.from([1, 2, 3]);
    const [kept, dropped] = prunePayloadList([garbage], 180 * 24 * 3600 * 1000);
    assert.equal(dropped, 0);
    assert.equal(kept.length, 1);
  });
});
