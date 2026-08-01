import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  DEFAULT_SALT,
  HASH_SIZE,
  MAX_LEGACY_SALTS,
  SALT_SIZE,
  NamespaceHasher,
  covers,
  parseObject,
  split,
} from "../src/namespace.js";

const SALT_A = Uint8Array.from({ length: SALT_SIZE }, (_, i) => i);
const SALT_B = Uint8Array.from({ length: SALT_SIZE }, (_, i) => SALT_SIZE - 1 - i);

/** Independent HMAC-SHA256 truncated to 16 bytes (node:crypto cross-check). */
function hmac16(salt, msg) {
  return new Uint8Array(
    createHmac("sha256", Buffer.from(salt)).update(msg).digest().subarray(0, HASH_SIZE),
  );
}

describe("NamespaceHasher relations (§3.3)", () => {
  it("truncates HMAC-SHA256 to 16 bytes", async () => {
    const h = new NamespaceHasher(SALT_A);
    assert.equal((await h.hashRelation("admin")).length, HASH_SIZE);
    assert.equal((await h.hashRelation("-calibrate")).length, HASH_SIZE);
  });

  it("matches an independent HMAC-SHA256 computation", async () => {
    const h = new NamespaceHasher(SALT_A);
    assert.deepEqual(await h.hashRelation("calibrate"), hmac16(SALT_A, "calibrate"));
    // Explicit denies hash the whole string including the hyphen (§3.3).
    assert.deepEqual(await h.hashRelation("-calibrate"), hmac16(SALT_A, "-calibrate"));
  });

  it("is salt-sensitive", async () => {
    const a = new NamespaceHasher(SALT_A);
    const b = new NamespaceHasher(SALT_B);
    assert.notDeepEqual(await a.hashRelation("read"), await b.hashRelation("read"));
  });

  it("defaults to the fail-open null salt", () => {
    assert.deepEqual(new NamespaceHasher().salt, DEFAULT_SALT);
    assert.deepEqual(DEFAULT_SALT, new Uint8Array(SALT_SIZE));
    assert.equal(MAX_LEGACY_SALTS, 2);
  });
});

describe("NamespaceHasher objects (§3.3)", () => {
  it("hashes each segment individually", async () => {
    const h = new NamespaceHasher(SALT_A);
    const { hashes, wildcard } = await h.hashObject("sensor:wind");
    assert.equal(wildcard, false);
    assert.deepEqual(hashes, [hmac16(SALT_A, "sensor"), hmac16(SALT_A, "wind")]);
  });

  it("strips the terminal wildcard into the flag", async () => {
    const h = new NamespaceHasher(SALT_A);
    const { hashes, wildcard } = await h.hashObject("sensor:*");
    assert.equal(wildcard, true);
    assert.deepEqual(hashes, [hmac16(SALT_A, "sensor")]);
  });

  it("handles the root wildcard", async () => {
    const h = new NamespaceHasher(SALT_A);
    const { hashes, wildcard } = await h.hashObject("*");
    assert.equal(wildcard, true);
    assert.deepEqual(hashes, []);
  });

  it("derives a stable, salt-distinct id_tag", async () => {
    assert.deepEqual(
      await new NamespaceHasher(SALT_A).idTag(),
      await new NamespaceHasher(SALT_A).idTag(),
    );
    assert.notDeepEqual(
      await new NamespaceHasher(SALT_A).idTag(),
      await new NamespaceHasher(SALT_B).idTag(),
    );
  });
});

describe("covers (§3.3 matching)", () => {
  const A = new Uint8Array(16).fill(0xaa);
  const B = new Uint8Array(16).fill(0xbb);
  const C = new Uint8Array(16).fill(0xcc);

  it("exact match", () => {
    assert.equal(covers([A, B], false, [A, B]), true);
    assert.equal(covers([A], false, [A, B]), false);
  });

  it("wildcard prefix", () => {
    assert.equal(covers([A], true, [A, B, C]), true);
    assert.equal(covers([], true, [A, B, C]), true); // root wildcard
    assert.equal(covers([new Uint8Array(16).fill(0xdd)], true, [A, B, C]), false);
  });

  it("wildcard not longer than request", () => {
    assert.equal(covers([A, B], true, [A]), false);
  });
});

describe("object parsing helpers", () => {
  it("parseObject", () => {
    assert.deepEqual(parseObject("a:b:c"), { segments: ["a", "b", "c"], wildcard: false });
    assert.deepEqual(parseObject("a:*"), { segments: ["a"], wildcard: true });
    assert.deepEqual(parseObject("*"), { segments: [], wildcard: true });
  });

  it("split", () => {
    assert.deepEqual(split("a:b:c"), ["a", "b", "c"]);
  });

  it("rejects a short salt", () => {
    assert.throws(() => new NamespaceHasher(new Uint8Array(3)));
  });
});
