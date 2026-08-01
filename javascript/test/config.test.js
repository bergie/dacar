import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Config, DEFAULT_DELETION_HORIZON_DAYS } from "../src/config.js";
import { DEFAULT_SALT, HASH_SIZE, MAX_LEGACY_SALTS, NamespaceHasher } from "../src/namespace.js";
import { ThresholdGroup } from "../src/threshold.js";

const ROOT = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const SALT_A = Uint8Array.from({ length: 32 }, (_, i) => i);
const SALT_B = Uint8Array.from({ length: 32 }, (_, i) => 31 - i);
const SALT_C = new Uint8Array(32).fill(3);
const SALT_D = new Uint8Array(32).fill(4);

describe("Config anchors (§4)", () => {
  it("requires at least one anchor", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [] }));
  });

  it("validates anchor length", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [new Uint8Array(3)] }));
  });

  it("isRootAnchor", () => {
    const other = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 1);
    const cfg = new Config({ rootTrustAnchors: [ROOT, other] });
    assert.equal(cfg.isRootAnchor(ROOT), true);
    assert.equal(cfg.isRootAnchor(other), true);
    assert.equal(cfg.isRootAnchor(new Uint8Array(HASH_SIZE)), false);
  });

  it("validates authoritative identity length", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [ROOT], authoritativeIdentity: new Uint8Array(3) }));
  });
});

describe("Config salts (§3.3, §10)", () => {
  it("defaults to the fail-open null salt", () => {
    const cfg = new Config({ rootTrustAnchors: [ROOT] });
    assert.deepEqual(cfg.primarySalt, DEFAULT_SALT);
    assert.equal(cfg.hashers.length, 1);
    assert.deepEqual(cfg.hashers[0].salt, DEFAULT_SALT);
  });

  it("orders primary then legacy hashers", () => {
    const cfg = new Config({ rootTrustAnchors: [ROOT], primarySalt: SALT_A, legacySalts: [SALT_B, SALT_C] });
    assert.deepEqual(cfg.hashers.map((h) => h.salt), [SALT_A, SALT_B, SALT_C]);
  });

  it("enforces the legacy cap", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [ROOT], primarySalt: SALT_A, legacySalts: [SALT_B, SALT_C, SALT_D] }));
  });

  it("validates salt lengths", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [ROOT], primarySalt: new Uint8Array(3) }));
    assert.throws(() => new Config({ rootTrustAnchors: [ROOT], legacySalts: [new Uint8Array(3)] }));
  });
});

describe("Config threshold groups (§4.1)", () => {
  it("looks up a group by its Group ID", async () => {
    const m1 = ROOT;
    const m2 = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 1);
    const group = new ThresholdGroup([m1, m2], 1);
    const gid = await group.groupId();
    const cfg = new Config({ rootTrustAnchors: [gid], thresholdGroups: [group] });
    assert.equal(await cfg.groupFor(gid), group);
    assert.equal(await cfg.groupFor(new Uint8Array(HASH_SIZE)), undefined);
    assert.equal(cfg.isRootAnchor(gid), true);
  });
});

describe("Config horizon (§9)", () => {
  it("defaults to 180 days", () => {
    assert.equal(new Config({ rootTrustAnchors: [ROOT] }).deletionHorizonDays, DEFAULT_DELETION_HORIZON_DAYS);
  });

  it("validates the horizon", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [ROOT], deletionHorizonDays: 0 }));
  });
});
