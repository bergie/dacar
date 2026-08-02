import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Identity, MsgPack } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc } from "../src/hlc.js";
import { groupId } from "../src/threshold.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";

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

describe("DeltaReceiver (§11.2.4)", () => {
  it("applies a valid signed delta", async () => {
    const id = await Identity.generate();
    const issuer = identityHash(id);
    const op = await makeOp(issuer, [id]);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: 1_700_000_000_000 }), true);
    assert.equal(state.isActive(op.tuple.key), true);
  });

  it("drops a forged delta without mutating state", async () => {
    const id = await Identity.generate();
    const issuer = identityHash(id);
    const op = await makeOp(issuer, [await Identity.generate()]); // wrong signer
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: 1_700_000_000_000 }), false);
    assert.equal(state.size, 0);
  });

  it("swallows malformed payloads (transport callbacks never crash)", async () => {
    const state = new StateVector();
    const rx = new DeltaReceiver(state, new Keyring());
    assert.equal(await rx.applyPayload(new TextEncoder().encode("not msgpack at all")), false);
    assert.equal(await rx.applyPayload(new Uint8Array(0)), false);
    assert.equal(await rx.applyPayload(new Uint8Array([0, 1, 2])), false); // truncated
    assert.equal(state.size, 0);
  });

  it("drops a delta from an unknown issuer", async () => {
    const id = await Identity.generate();
    const op = await makeOp(identityHash(id), [id]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, new Keyring()); // empty keyring
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: 1_700_000_000_000 }), false);
    assert.equal(state.size, 0);
  });

  it("applies a valid threshold delta", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = await Promise.all(keys.map((k) => k.getPublicKey()));
    const members = keys.map(identityHash);
    const gid = await groupId(members, 2);
    const op = await makeOp(gid, [keys[0], keys[1]]);
    const kr = new Keyring().registerGroup(gid, pubs, 2);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: 1_700_000_000_000 }), true);
    assert.equal(state.isActive(op.tuple.key), true);
  });
});

describe("DeltaReceiver.applyPayloads (§11.1 batch — secure alternative to merge())", () => {
  it("applies a batch of valid signed deltas", async () => {
    const id = await Identity.generate();
    const issuer = identityHash(id);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const opA = await makeOp(issuer, [id]);
    const tupleB = await Tuple.fromPlaintext({
      objectId: "sensor:temp", relation: "read", grantee: GRANTEE, issuer, hasher: HASHER,
    });
    const opB = await new Operation({ tuple: tupleB, action: Action.GRANT, hlc: HLC }).sign(id);
    const batch = DeltaReceiver.packPayloads([opA.toPayload(), opB.toPayload()]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayloads(batch, { nowMs: 1_700_000_000_000 }), 2);
    assert.equal(state.isActive(opA.tuple.key), true);
    assert.equal(state.isActive(opB.tuple.key), true);
  });

  it("drops a forged element but still applies the valid one", async () => {
    const id = await Identity.generate();
    const attacker = await Identity.generate();
    const issuer = identityHash(id);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const good = await makeOp(issuer, [id]);
    // forged targets a *distinct* tuple (different object) so its activity can
    // be checked independently; it claims the same issuer but a wrong signature.
    const forgedTuple = await Tuple.fromPlaintext({
      objectId: "sensor:temp", relation: "read", grantee: GRANTEE, issuer, hasher: HASHER,
    });
    const forged = await new Operation({ tuple: forgedTuple, action: Action.GRANT, hlc: HLC }).sign(attacker);
    const batch = DeltaReceiver.packPayloads([good.toPayload(), forged.toPayload()]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayloads(batch, { nowMs: 1_700_000_000_000 }), 1);
    assert.equal(state.isActive(good.tuple.key), true);
    assert.equal(state.isActive(forged.tuple.key), false);
  });

  it("drops elements from an unknown issuer", async () => {
    const id = await Identity.generate();
    const op = await makeOp(identityHash(id), [id]);
    const batch = DeltaReceiver.packPayloads([op.toPayload()]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, new Keyring()); // empty keyring
    assert.equal(await rx.applyPayloads(batch, { nowMs: 1_700_000_000_000 }), 0);
    assert.equal(state.size, 0);
  });

  it("swallows a malformed outer payload (transport callbacks never crash)", async () => {
    const state = new StateVector();
    const rx = new DeltaReceiver(state, new Keyring());
    assert.equal(await rx.applyPayloads(new TextEncoder().encode("not msgpack")), 0);
    assert.equal(await rx.applyPayloads(new Uint8Array(0)), 0);
    // a msgpack value that is not an array
    assert.equal(await rx.applyPayloads(MsgPack.encode(42)), 0);
    assert.equal(await rx.applyPayloads(MsgPack.encode("x")), 0);
    assert.equal(state.size, 0);
  });

  it("skips non-bin elements without aborting the batch", async () => {
    const id = await Identity.generate();
    const issuer = identityHash(id);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const good = await makeOp(issuer, [id]);
    // array mixing a valid bin with non-bin junk
    const batch = MsgPack.encode([good.toPayload(), "not-a-delta", 7]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayloads(batch, { nowMs: 1_700_000_000_000 }), 1);
    assert.equal(state.isActive(good.tuple.key), true);
  });

  it("rejects a future-skewed element per §12", async () => {
    const id = await Identity.generate();
    const issuer = identityHash(id);
    const kr = new Keyring().registerSingle(issuer, await id.getPublicKey());
    const tuple = await Tuple.fromPlaintext({
      objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer, hasher: HASHER,
    });
    const future = await new Operation({
      tuple,
      action: Action.GRANT,
      hlc: packHlc(1_700_000_000_000 + 400 * 24 * 3600 * 1000, 0),
    }).sign(id);
    const batch = DeltaReceiver.packPayloads([future.toPayload()]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, kr);
    assert.equal(await rx.applyPayloads(batch, { nowMs: 1_700_000_000_000 }), 0);
    assert.equal(state.size, 0);
  });
});
