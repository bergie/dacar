import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Identity } from "@reticulum/core";
import { HASH_SIZE } from "../src/namespace.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { ThresholdGroup, groupId } from "../src/threshold.js";

const M1 = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const M2 = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 1);
const M3 = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 2);

/** Independent Group ID via node:crypto (cross-check, big-endian N). */
async function expectedGroupId(members, threshold) {
  const sorted = [...members].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const nBytes = new Uint8Array(8);
  new DataView(nBytes.buffer).setBigUint64(0, BigInt(threshold), false); // big-endian
  const blob = Buffer.concat([...sorted.map((m) => Buffer.from(m)), Buffer.from(nBytes)]);
  return new Uint8Array(createHash("sha256").update(blob).digest().subarray(0, HASH_SIZE));
}

describe("groupId (§4.1)", () => {
  it("is SHA-256(sorted members + N) truncated to 16 bytes", async () => {
    assert.deepEqual(await groupId([M1, M2, M3], 2), await expectedGroupId([M1, M2, M3], 2));
    assert.equal((await groupId([M1, M2, M3], 2)).length, HASH_SIZE);
  });

  it("is order-invariant", async () => {
    assert.deepEqual(await groupId([M1, M2, M3], 2), await groupId([M3, M2, M1], 2));
  });

  it("changes with the threshold", async () => {
    assert.notDeepEqual(await groupId([M1, M2, M3], 1), await groupId([M1, M2, M3], 2));
  });

  it("changes with membership", async () => {
    assert.notDeepEqual(await groupId([M1, M2], 1), await groupId([M1, M3], 1));
  });

  it("validates inputs", async () => {
    await assert.rejects(() => groupId([M1], 1));
    await assert.rejects(() => groupId([M1, M2], 0));
    await assert.rejects(() => groupId([M1, M2], 3)); // N > M
    await assert.rejects(() => groupId([new Uint8Array(3), M2], 1));
  });

  it("accepts unanimous N === M", async () => {
    // N === M (all members must sign) is a legitimate config the spec permits.
    const id = await groupId([M1, M2], 2);
    assert.equal(id.length, HASH_SIZE);
    assert.deepEqual(id, await expectedGroupId([M1, M2], 2));
    assert.notDeepEqual(await groupId([M1, M2], 2), await groupId([M1, M2], 1));
  });
});

describe("ThresholdGroup (§4.1)", () => {
  it("stores members sorted and exposes size", () => {
    const g = new ThresholdGroup([M3, M1, M2], 2);
    assert.deepEqual(g.members, [M1, M2, M3]);
    assert.equal(g.size, 3);
  });

  it("groupId() matches the helper and is cached", async () => {
    const g = new ThresholdGroup([M1, M2, M3], 2);
    const id = await g.groupId();
    assert.deepEqual(id, await groupId([M1, M2, M3], 2));
    assert.deepEqual(await g.groupId(), id); // cached
  });

  it("validates inputs", () => {
    assert.throws(() => new ThresholdGroup([M1], 1));
  });
});

describe("ThresholdGroup unanimous consent (N === M)", () => {
  it("constructs at N === M and an all-member signature verifies", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = await Promise.all(keys.map((k) => k.getPublicKey()));
    const members = pubs.map((p) => createHash("sha256").update(p).digest().subarray(0, HASH_SIZE));
    const g = new ThresholdGroup(members, 3);
    const gid = await g.groupId();
    const tuple = new Tuple({
      relationHash: new Uint8Array(HASH_SIZE),
      objectHashes: [new Uint8Array(HASH_SIZE)],
      wildcard: false,
      grantee: new Uint8Array(HASH_SIZE),
      issuer: gid,
    });
    const op = await new Operation({ tuple, action: Action.GRANT, hlc: 1n }).sign(...keys);
    assert.equal(await op.verifyThreshold(pubs, 3), true);
    // Only 2 of 3 must NOT verify.
    const short = await new Operation({ tuple, action: Action.GRANT, hlc: 1n }).sign(keys[0], keys[1]);
    assert.equal(await short.verifyThreshold(pubs, 3), false);
  });
});
