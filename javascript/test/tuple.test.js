import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Tuple, MAX_SEGMENTS } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";

const SALT = Uint8Array.from({ length: 32 }, (_, i) => i);
const HASHER = new NamespaceHasher(SALT);
const ISSUER = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);

/** @param {Object} opts @returns {Promise<Tuple>} */
function tuple(opts) {
  return Tuple.fromPlaintext({ ...opts, hasher: HASHER });
}

describe("Tuple.fromPlaintext (§3.3)", () => {
  it("hashes labels with the salt", async () => {
    const t = await tuple({ objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer: ISSUER });
    assert.deepEqual(t.relationHash, await HASHER.hashRelation("calibrate"));
    assert.deepEqual(t.objectHashes, (await HASHER.hashObject("sensor:wind")).hashes);
    assert.equal(t.wildcard, false);
  });

  it("preserves the wildcard flag", async () => {
    const t = await tuple({ objectId: "sensor:*", relation: "admin", grantee: GRANTEE, issuer: ISSUER });
    assert.equal(t.wildcard, true);
    assert.deepEqual(t.objectHashes, (await HASHER.hashObject("sensor:*")).hashes);
  });
});

describe("Tuple §6.1 hash layout", () => {
  it("pre-image excludes action and HLC", async () => {
    const t = await tuple({ objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer: ISSUER });
    const rel = await HASHER.hashRelation("calibrate");
    const { hashes } = await HASHER.hashObject("sensor:wind");
    const expected = new Uint8Array(16 + 16 + 16 + 1 + 1 + 16 * 2);
    expected.set(ISSUER, 0);
    expected.set(GRANTEE, 16);
    expected.set(rel, 32);
    expected[48] = 0x00; // wildcard flag
    expected[49] = 2; // segment count
    expected.set(hashes[0], 50);
    expected.set(hashes[1], 66);
    assert.deepEqual(t.preimage, expected);
  });

  it("hash() is SHA-256 of the pre-image", async () => {
    const t = await tuple({ objectId: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", t.preimage));
    assert.deepEqual(await t.hash(), digest);
  });

  it("grant and revoke share a key", async () => {
    const t = await tuple({ objectId: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    assert.equal(typeof t.key, "string");
    assert.equal(t.key, (await tuple({ objectId: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER })).key);
  });
});

describe("Tuple distinctness (§3.1)", () => {
  it("per-issuer", async () => {
    const other = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 1);
    const t1 = await tuple({ objectId: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const t2 = await tuple({ objectId: "o", relation: "r", grantee: GRANTEE, issuer: other });
    assert.notEqual(t1.key, t2.key);
  });

  it("per-grantee", async () => {
    const other = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 2);
    const t1 = await tuple({ objectId: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const t2 = await tuple({ objectId: "o", relation: "r", grantee: other, issuer: ISSUER });
    assert.notEqual(t1.key, t2.key);
  });

  it("wildcard differs from exact", async () => {
    const tExact = await tuple({ objectId: "sensor", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const tWild = await tuple({ objectId: "sensor:*", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    assert.notEqual(tExact.key, tWild.key);
  });
});

describe("Tuple validation", () => {
  it("rejects malformed hashes", async () => {
    const rel = await HASHER.hashRelation("r");
    assert.throws(() => new Tuple({ relationHash: rel, objectHashes: [new Uint8Array(3)], wildcard: false, grantee: GRANTEE, issuer: ISSUER }));
    assert.throws(() => new Tuple({ relationHash: new Uint8Array(3), objectHashes: [], wildcard: false, grantee: GRANTEE, issuer: ISSUER }));
    assert.throws(() => new Tuple({ relationHash: rel, objectHashes: [], wildcard: false, grantee: new Uint8Array(3), issuer: ISSUER }));
  });

  it("rejects too many segments", async () => {
    const rel = await HASHER.hashRelation("r");
    const seg = new Uint8Array(HASH_SIZE);
    const tooMany = Array.from({ length: MAX_SEGMENTS + 1 }, () => seg);
    assert.throws(() => new Tuple({ relationHash: rel, objectHashes: tooMany, wildcard: false, grantee: GRANTEE, issuer: ISSUER }));
  });
});
