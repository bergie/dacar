import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc } from "../src/hlc.js";
import { groupId } from "../src/threshold.js";
import { StateVector } from "../src/crdt.js";
import { IssuerKeyset, Keyring, verifyOperation } from "../src/verifier.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const HLC = packHlc(1_700_000_000_000, 0);

/** The canonical 16-byte RNS identity hash exposed by @reticulum/core. */
function identityHash(identity) {
  return identity.identityHash;
}

/** @param {Uint8Array} issuer @param {Identity[]} signers @returns {Promise<Operation>} */
async function makeOp(issuer, signers = []) {
  const tuple = await Tuple.fromPlaintext({
    objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer, hasher: HASHER,
  });
  const base = new Operation({ tuple, action: Action.GRANT, hlc: HLC });
  return signers.length ? base.sign(...signers) : base;
}

describe("IssuerKeyset", () => {
  it("single() defaults to threshold 1", () => {
    const ks = IssuerKeyset.single(new Uint8Array(64));
    assert.equal(ks.threshold, 1);
    assert.equal(ks.memberPublicKeys.length, 1);
  });

  it("group() keeps keys and threshold", () => {
    const ks = IssuerKeyset.group([new Uint8Array(64), new Uint8Array(64).fill(1), new Uint8Array(64).fill(2)], 2);
    assert.equal(ks.threshold, 2);
    assert.equal(ks.memberPublicKeys.length, 3);
  });

  it("rejects a bad key length", () => {
    assert.throws(() => IssuerKeyset.single(new Uint8Array(31)));
  });

  it("rejects threshold below 1", () => {
    assert.throws(() => new IssuerKeyset([new Uint8Array(64)], 0));
  });

  it("rejects fewer keys than threshold", () => {
    assert.throws(() => new IssuerKeyset([new Uint8Array(64)], 2));
  });
});

describe("Keyring", () => {
  it("resolves a registered keyset", () => {
    const kr = new Keyring().registerSingle(new Uint8Array(16).fill(0xaa), new Uint8Array(64));
    const ks = kr.resolve(new Uint8Array(16).fill(0xaa));
    assert.ok(ks);
    assert.equal(ks.threshold, 1);
  });

  it("returns null for unknown issuers", () => {
    assert.equal(new Keyring().resolve(new Uint8Array(16).fill(0xbb)), null);
  });
});

describe("verifyOperation (§11.2.4)", () => {
  it("accepts a valid single-identity signature", async () => {
    const id = await Identity.generate();
    const issuer = await identityHash(id);
    const op = await makeOp(issuer, [id]);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    assert.equal(await verifyOperation(op, kr), true);
  });

  it("accepts via a plain function resolver", async () => {
    const id = await Identity.generate();
    const issuer = await identityHash(id);
    const op = await makeOp(issuer, [id]);
    const pub = await id.getPublicKey();
    assert.equal(await verifyOperation(op, (h) => (h.join() === issuer.join() ? IssuerKeyset.single(pub) : null)), true);
  });

  it("rejects a tampered operation", async () => {
    const id = await Identity.generate();
    const issuer = await identityHash(id);
    const op = await makeOp(issuer, [id]);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const tampered = new Operation({ tuple: op.tuple, action: Action.GRANT, hlc: packHlc(1, 1), signatures: op.signatures });
    assert.equal(await verifyOperation(tampered, kr), false);
  });

  it("rejects an unknown issuer", async () => {
    const id = await Identity.generate();
    const op = await makeOp(await identityHash(id), [id]);
    assert.equal(await verifyOperation(op, new Keyring()), false);
  });

  it("rejects a forged op claiming a root issuer", async () => {
    const root = await Identity.generate();
    const attacker = await Identity.generate();
    const rootHash = await identityHash(root);
    const op = await makeOp(rootHash, [attacker]); // signed by attacker, not root
    const kr = new Keyring().registerSingle(rootHash, await root.getPublicKey());
    assert.equal(await verifyOperation(op, kr), false);
  });

  it("accepts a valid threshold N-of-M", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = await Promise.all(keys.map((k) => k.getPublicKey()));
    const members = await Promise.all(keys.map(identityHash));
    const gid = await groupId(members, 2);
    const op = await makeOp(gid, [keys[0], keys[1]]);
    const kr = new Keyring().registerGroup(gid, pubs, 2);
    assert.equal(await verifyOperation(op, kr), true);
  });

  it("rejects a threshold below N", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = await Promise.all(keys.map((k) => k.getPublicKey()));
    const members = await Promise.all(keys.map(identityHash));
    const gid = await groupId(members, 2);
    const op = await makeOp(gid, [keys[0]]); // only 1 of 2
    const kr = new Keyring().registerGroup(gid, pubs, 2);
    assert.equal(await verifyOperation(op, kr), false);
  });

  it("rejects a non-member signature", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = await Promise.all(keys.map((k) => k.getPublicKey()));
    const members = await Promise.all(keys.map(identityHash));
    const gid = await groupId(members, 2);
    const outsider = await Identity.generate();
    const op = await makeOp(gid, [keys[0], outsider]);
    const kr = new Keyring().registerGroup(gid, pubs, 2);
    assert.equal(await verifyOperation(op, kr), false);
  });
});

describe("StateVector.ingest (§11.2.4)", () => {
  it("applies a valid single-identity op", async () => {
    const id = await Identity.generate();
    const issuer = await identityHash(id);
    const op = await makeOp(issuer, [id]);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const state = new StateVector();
    assert.equal(await state.ingest(op, kr, { nowMs: 1_700_000_000_000 }), true);
    assert.equal(state.isActive(op.tuple.key), true);
  });

  it("drops a forged op without mutating state", async () => {
    const id = await Identity.generate();
    const issuer = await identityHash(id);
    const op = await makeOp(issuer, [await Identity.generate()]); // wrong signer
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const state = new StateVector();
    assert.equal(await state.ingest(op, kr, { nowMs: 1_700_000_000_000 }), false);
    assert.equal(state.isActive(op.tuple.key), false);
    assert.equal(state.size, 0);
  });

  it("drops an op from an unknown issuer", async () => {
    const id = await Identity.generate();
    const op = await makeOp(await identityHash(id), [id]);
    const state = new StateVector();
    assert.equal(await state.ingest(op, new Keyring(), { nowMs: 1_700_000_000_000 }), false);
    assert.equal(state.size, 0);
  });

  it("applies a valid threshold op", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = await Promise.all(keys.map((k) => k.getPublicKey()));
    const members = await Promise.all(keys.map(identityHash));
    const gid = await groupId(members, 2);
    const op = await makeOp(gid, [keys[0], keys[2]]);
    const kr = new Keyring().registerGroup(gid, pubs, 2);
    const state = new StateVector();
    assert.equal(await state.ingest(op, kr, { nowMs: 1_700_000_000_000 }), true);
    assert.equal(state.isActive(op.tuple.key), true);
  });

  it("apply() trusts its caller and does not verify", async () => {
    const issuer = new Uint8Array(16).fill(0xcc);
    const op = await makeOp(issuer); // unsigned
    const state = new StateVector();
    assert.equal(state.apply(op, { nowMs: 1_700_000_000_000 }), true);
    assert.equal(state.isActive(op.tuple.key), true);
  });
});
