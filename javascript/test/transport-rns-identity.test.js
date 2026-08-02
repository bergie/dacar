import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Destination, Identity } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc } from "../src/hlc.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";
import { RnsIdentityResolver } from "../src/transport/rnsIdentity.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const NOW = 1_700_000_000_000;

/** @param {Uint8Array} issuer @param {Identity[]} signers @returns {Promise<Operation>} */
async function makeOp(issuer, signers = []) {
  const tuple = await Tuple.fromPlaintext({
    objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer, hasher: HASHER,
  });
  const base = new Operation({ tuple, action: Action.GRANT, hlc: packHlc(NOW, 0) });
  return signers.length ? base.sign(...signers) : base;
}

/** Populate RNS's recall store for *identity* (as an announce would). */
async function remember(identity) {
  await Destination.remember(
    new Uint8Array(16),
    new Uint8Array(16),
    await identity.getPublicKey(),
    null,
  );
}

describe("RnsIdentityResolver (§3.1, §11.2.4)", () => {
  /** @type {Identity} */ let identity;
  /** @type {Uint8Array} */ let issuer;
  /** @type {Uint8Array} */ let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = await identity.getPublicKey();
    issuer = identity.identityHash;
    await remember(identity);
  });

  // -- recall → keyset ---------------------------------------------------

  it("resolves an announced identity to its full 64-byte public key", async () => {
    const keyset = await new RnsIdentityResolver().resolve(issuer);
    assert.ok(keyset);
    assert.equal(keyset.threshold, 1);
    assert.equal(keyset.memberPublicKeys.length, 1);
    assert.deepEqual(keyset.memberPublicKeys[0], publicKey);
  });

  it("an unknown hash resolves to null without a fallback", async () => {
    const stranger = await Identity.generate();
    assert.equal(await new RnsIdentityResolver().resolve(stranger.identityHash), null);
  });

  // -- the real path: recall → verify-on-ingest → CRDT merge -------------

  it("applies a signed Delta from an announced identity", async () => {
    const op = await makeOp(issuer, [identity]); // signed by the real identity
    const state = new StateVector();
    const rx = new DeltaReceiver(state, new RnsIdentityResolver());
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: NOW }), true);
    assert.equal(state.size, 1);
  });

  it("drops a forged Delta (wrong signer)", async () => {
    // Issuer hash recalls the real identity, but the op is signed by a
    // different key → signature verification fails → Delta dropped.
    const op = await makeOp(issuer, [await Identity.generate()]);
    const state = new StateVector();
    const rx = new DeltaReceiver(state, new RnsIdentityResolver());
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: NOW }), false);
    assert.equal(state.size, 0);
  });

  // -- composition: RNS-first, then fallback -----------------------------

  it("falls back to a Keyring for groups and unknowns", async () => {
    const group = Uint8Array.from({ length: HASH_SIZE }, () => 0xaa);
    const fallback = new Keyring().registerSingle(group, Uint8Array.from({ length: 64 }, () => 0xbb));
    const resolver = new RnsIdentityResolver(fallback);
    assert.ok(await resolver.resolve(group)); // fallback single
    const stranger = await Identity.generate();
    assert.equal(await resolver.resolve(stranger.identityHash), null); // neither knows it
  });

  it("RNS takes precedence over the fallback", async () => {
    // Fallback would answer the issuer with a *wrong* key; RNS must win.
    const fallback = new Keyring().registerSingle(
      issuer,
      Uint8Array.from({ length: 64 }, () => 0xcc),
    );
    const keyset = await new RnsIdentityResolver(fallback).resolve(issuer);
    assert.deepEqual(keyset.memberPublicKeys[0], publicKey);
  });

  it("works as a KeyResolver function via .resolve", async () => {
    const resolver = new RnsIdentityResolver();
    const rx = new DeltaReceiver(new StateVector(), resolver.resolve.bind(resolver));
    const op = await makeOp(issuer, [identity]);
    assert.equal(await rx.applyPayload(op.toPayload(), { nowMs: NOW }), true);
  });
});
