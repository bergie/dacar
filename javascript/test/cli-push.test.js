/**
 * Smoketests for the `dacar push` CLI command (§11, doc #16 Phase 4a).
 *
 * The network leg (`pushDelta` → RNS boot → Link → per-Delta requests) is
 * covered seam-by-seam in `transport-rns-sync.test.js` and mirrors the
 * Python-side tests (`test_cli_push.py`). Here we dispatch the real CLI entry
 * (`src/cli/dacar.js push`) in a subprocess to cover the *offline* argument
 * handling: target-node positionals, alias resolution, and the empty-outbox
 * no-op — all of which fail fast without ever booting RNS.
 *
 * Node-only: spawning the CLI entry needs `process.execPath` to be Node
 * (the entry is a Node/Deno-style script run directly, not importable under
 * Deno's permissionless test runner with fs writes).
 *
 * @import {DacarStore} from "../src/cli/store.js"
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const IS_NODE = typeof process !== "undefined" &&
  !!process.versions?.node &&
  !process.versions?.deno &&
  !process.versions?.bun;
const CLI = fileURLToPath(new URL("../src/cli/dacar.js", import.meta.url));
const NODE_HASH = "aabbccdd".repeat(4); // 32 hex = 16 bytes (fake node hash)

/** @returns {string} A fresh scratch store directory. */
function makeStore() {
  return mkdtempSync(join(tmpdir(), "dacar-push-cli-"));
}

/** @param {string} dir */
function cleanup(dir) {
  rmSync(dir, { recursive: true, force: true });
}

/**
 * Run `dacar push ...` in a subprocess.
 * @param {string[]} args
 * @param {string} storeDir
 * @returns {{code: number, stdout: string, stderr: string}}
 */
function runPush(args, storeDir) {
  const r = spawnSync(process.execPath, [CLI, "push", ...args, "--store", storeDir], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return { code: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}
describe("dacar push dispatch (offline argument handling, doc #16 4a)", { skip: !IS_NODE }, () => {
  it("fails fast on a store with no signing identity", () => {
    const dir = makeStore();
    try {
      const r = runPush([NODE_HASH], dir);
      assert.equal(r.code, 1);
      assert.match(r.stderr, /no signing identity/);
    } finally {
      cleanup(dir);
    }
  });

  it("fails fast with no target node given", () => {
    const dir = makeStore();
    try {
      // Identity is checked before the target, so initialize a store first.
      spawnSync(process.execPath, [CLI, "init", "--store", dir], {
        encoding: "utf8",
        stdio: ["ignore", "ignore", "ignore"],
      });
      const r = runPush([], dir);
      assert.equal(r.code, 1);
      assert.match(r.stderr, /no target node given/);
    } finally {
      cleanup(dir);
    }
  });

  it("fails fast on an unknown alias/identity", () => {
    const dir = makeStore();
    try {
      // No `dacar init`, but identity is checked before the target — so
      // initialize a store first via a second invocation of the CLI.
      spawnSync(process.execPath, [CLI, "init", "--store", dir], {
        encoding: "utf8",
        stdio: ["ignore", "ignore", "ignore"],
      });
      const r = runPush(["no-such-alias"], dir);
      assert.equal(r.code, 1);
      assert.match(r.stderr, /unknown identity/);
    } finally {
      cleanup(dir);
    }
  });

  it("is a no-op (exit 0) when the outbox is empty", () => {
    const dir = makeStore();
    try {
      spawnSync(process.execPath, [CLI, "init", "--store", dir], {
        encoding: "utf8",
        stdio: ["ignore", "ignore", "ignore"],
      });
      const r = runPush([NODE_HASH], dir);
      assert.equal(r.code, 0);
      assert.match(r.stderr, /nothing to push \(outbox empty\)/);
    } finally {
      cleanup(dir);
    }
  });
});
