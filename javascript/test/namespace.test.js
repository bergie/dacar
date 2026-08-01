import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { match, permutations } from "../src/namespace.js";

describe("namespace match (§3.3)", () => {
  it("exact match", () => {
    assert.equal(match("sensor:wind", "sensor:wind"), true);
    assert.equal(match("sensor:wind", "sensor:rain"), false);
  });

  it("terminal wildcard", () => {
    assert.equal(match("sensor:*", "sensor:wind"), true);
    assert.equal(match("sensor:*", "sensor:wind:north"), true);
    assert.equal(match("sensor:*", "actuator:pump"), false);
  });

  it("root wildcard", () => {
    assert.equal(match("*", "anything"), true);
    assert.equal(match("*", "a:b:c:d"), true);
  });

  it("prefix mismatch", () => {
    assert.equal(match("sensor:wind:*", "actuator:wind:north"), false);
  });

  it("non-wildcard tuple must be exactly as long as the request", () => {
    assert.equal(match("sensor:wind", "sensor:wind:north"), false);
  });
});

describe("namespace permutations", () => {
  it("covers all suffix-wildcard levels", () => {
    assert.deepEqual(
      new Set(permutations("sensor:wind:north")),
      new Set(["sensor:wind:north", "sensor:wind:*", "sensor:*", "*"]),
    );
  });

  it("handles a single segment", () => {
    assert.deepEqual(new Set(permutations("sensor")), new Set(["sensor", "*"]));
  });

  it("every generated pattern covers the original request", () => {
    for (const obj of ["sensor:wind:north", "a", "a:b:c:d:e"]) {
      for (const pattern of permutations(obj)) {
        assert.equal(match(pattern, obj), true);
      }
    }
  });
});
