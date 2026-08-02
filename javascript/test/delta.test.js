import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
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
