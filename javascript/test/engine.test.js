import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Config } from "../src/config.js";
import { StateVector } from "../src/crdt.js";
import { Engine } from "../src/engine.js";
import { Clock } from "../src/hlc.js";
import { Action, Operation } from "../src/operation.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { ThresholdGroup } from "../src/threshold.js";
import { Tuple } from "../src/tuple.js";
import { packHlc } from "../src/hlc.js";

const SALT = Uint8Array.from({ length: 32 }, (_, i) => i);
const HASHER = new NamespaceHasher(SALT);

const ROOT = id(0);
const ADMIN1 = id(1);
const ADMIN2 = id(2);
const BOB = id(3);
const ALICE = id(4);

/** @param {number} n @returns {Uint8Array} a distinct 16-byte identity hash */
function id(n) {
  const b = new Uint8Array(16);
  b[0] = 0x01;
  b[15] = n & 0xff;
  return b;
}

/**
 * @param {Object} [opts]
 * @returns {Promise<{ state: StateVector, clock: Clock, engine: Engine, grant: (o: string, r: string, g: Uint8Array, i: Uint8Array) => Promise<void>, config: Config }>}
 */
async function fixture({
  maxDepth = 10,
  maxVisited = 50,
  primarySalt = SALT,
  legacySalts = [],
  thresholdGroups = [],
  anchors = [ROOT],
} = {}) {
  const state = new StateVector();
  const clock = new Clock();
  const config = new Config({
    rootTrustAnchors: anchors,
    primarySalt,
    legacySalts,
    thresholdGroups,
  });
  const engine = new Engine(config, state, { maxDepth, maxVisited });
  /**
   * @param {string} o
   * @param {string} r
   * @param {Uint8Array} g
   * @param {Uint8Array} i
   */
  async function grant(o, r, g, i) {
    state.apply(
      new Operation({
        tuple: await Tuple.fromPlaintext({ objectId: o, relation: r, grantee: g, issuer: i, hasher: HASHER }),
        action: Action.GRANT,
        hlc: clock.now(),
      }),
    );
  }
  return { state, clock, engine, grant, config };
}

describe("Engine resolution (§7.3)", () => {
  it("default deny", async () => {
    const { engine } = await fixture();
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), false);
  });

  it("root anchor direct grant", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "calibrate", BOB, ROOT);
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), true);
  });

  it("wrong grantee denied", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "calibrate", BOB, ROOT);
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", ALICE), false);
  });

  it("wrong relation denied", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "read", BOB, ROOT);
    assert.equal(await engine.evaluate("sensor:wind", "write", BOB), false);
  });
});

describe("Engine delegation (§7.2, §3.2)", () => {
  it("delegated admin chain", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "admin", ADMIN1, ROOT);
    await grant("sensor:wind", "calibrate", BOB, ADMIN1);
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), true);
  });

  it("undelegated issuer denied", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "calibrate", BOB, ADMIN1);
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), false);
  });

  it("wildcard admin cascades to child namespaces", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:*", "admin", ADMIN1, ROOT);
    await grant("sensor:wind:north", "calibrate", BOB, ADMIN1);
    assert.equal(await engine.evaluate("sensor:wind:north", "calibrate", BOB), true);
  });

  it("exact admin does NOT cascade", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "admin", ADMIN1, ROOT);
    await grant("sensor:wind:north", "calibrate", BOB, ADMIN1);
    assert.equal(await engine.evaluate("sensor:wind:north", "calibrate", BOB), false);
  });
});

describe("Engine explicit deny", () => {
  it("deny overrides allow", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:wind", "calibrate", BOB, ROOT);
    await grant("sensor:wind", "-calibrate", BOB, ROOT);
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), false);
  });

  it("exact deny overrides wildcard allow, sibling still allowed", async () => {
    const { engine, grant } = await fixture();
    await grant("sensor:*", "calibrate", BOB, ROOT);
    await grant("sensor:wind", "-calibrate", BOB, ROOT);
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), false);
    assert.equal(await engine.evaluate("sensor:rain", "calibrate", BOB), true);
  });
});

describe("Engine safety bounds", () => {
  it("rejects cycles and terminates", async () => {
    const { engine, grant } = await fixture();
    await grant("o", "admin", ADMIN1, ADMIN2);
    await grant("o", "admin", ADMIN2, ADMIN1);
    await grant("o", "r", BOB, ADMIN1);
    assert.equal(await engine.evaluate("o", "r", BOB), false);
  });

  it("depth cap rejects overlong chains", async () => {
    const { engine, grant } = await fixture({ maxDepth: 10 });
    const ids = [];
    for (let i = 1; i <= 16; i++) ids.push(id(i));
    for (let k = 1; k < ids.length; k++) await grant("o", "admin", ids[k], ids[k - 1]);
    await grant("o", "r", BOB, ids[ids.length - 1]);
    assert.equal(await engine.evaluate("o", "r", BOB), false);
  });

  it("valid chain within depth is allowed", async () => {
    const { engine, grant } = await fixture({ maxDepth: 10 });
    const a = id(10);
    const b = id(20);
    await grant("o", "admin", a, ROOT);
    await grant("o", "admin", b, a);
    await grant("o", "read", BOB, b);
    assert.equal(await engine.evaluate("o", "read", BOB), true);
  });
});

describe("Engine multi-salt (§10)", () => {
  it("matches a tuple hashed under a legacy salt", async () => {
    const legacy = Uint8Array.from({ length: 32 }, (_, i) => 31 - i);
    const legacyHasher = new NamespaceHasher(legacy);
    const { state, engine } = await fixture({ primarySalt: SALT, legacySalts: [legacy] });
    state.apply(
      new Operation({
        tuple: await Tuple.fromPlaintext({
          objectId: "sensor:wind", relation: "calibrate", grantee: BOB, issuer: ROOT, hasher: legacyHasher,
        }),
        action: Action.GRANT,
        hlc: packHlc(1_700_000_000_000, 0),
      }),
      { nowMs: 1_700_000_000_000 },
    );
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), true);
  });
});

describe("Engine threshold issuer (§4.1)", () => {
  it("treats a threshold group as a root anchor", async () => {
    const group = new ThresholdGroup([ADMIN1, ADMIN2], 1);
    const gid = await group.groupId();
    const { state, engine } = await fixture({ thresholdGroups: [group], anchors: [gid] });
    state.apply(
      new Operation({
        tuple: await Tuple.fromPlaintext({
          objectId: "sensor:wind", relation: "calibrate", grantee: BOB, issuer: gid, hasher: HASHER,
        }),
        action: Action.GRANT,
        hlc: packHlc(1_700_000_000_000, 0),
      }),
      { nowMs: 1_700_000_000_000 },
    );
    assert.equal(await engine.evaluate("sensor:wind", "calibrate", BOB), true);
  });
});
