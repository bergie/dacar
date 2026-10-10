/**
 * Smoketests for the `@reticulum/dacar/cli/fileStore` package export — the
 * Node-only `DacarFileAdapter` (Python-canonical loose-file store layout).
 *
 * The export was added to the `package.json` exports map so library consumers
 * can reuse the Python-store-compatible adapter (`./cli/session` and
 * `./cli/store` are already public; the adapter is their Node filesystem
 * backend). These tests verify the two things the change promises:
 *
 *   - the subpath is **resolvable through the package specifier** (Node
 *     package self-reference) — i.e. the exports map actually exposes it;
 *   - the adapter still round-trips records with the Python `Store` file
 *     layout (loose files at the store root, Python-matching modes).
 *
 * Runtime-agnostic: the self-reference resolution works under Node, Deno, and
 * Bun alike (all three run this suite).
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { toHex } from "@reticulum/core";

// The actual verification of the exports-map entry: import through the
// package specifier, not a relative path.
const fileStoreModule = await import("@reticulum/dacar/cli/fileStore");

let root;
const written = [];

before(() => {
  root = mkdtempSync(join(tmpdir(), "dacar-filestore-export-"));
});
after(() => {
  for (const dir of written) rmSync(dir, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
});

function newAdapter(name) {
  const dir = join(root, name);
  written.push(dir);
  return { adapter: new fileStoreModule.DacarFileAdapter(dir), dir };
}

/** File mode as seen by statSync (e.g. 0o600). */
function modeOf(path) {
  return statSync(path).mode & 0o777;
}

describe("@reticulum/dacar/cli/fileStore export", () => {
  it("is exposed by the package exports map", () => {
    const pkgRoot = join(fileURLToPath(new URL(".", import.meta.url)), "..");
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8"));
    assert.equal(pkg.exports["./cli/fileStore"], "./src/cli/fileStore.js");
  });

  it("resolves via the package specifier and exports DacarFileAdapter", () => {
    assert.equal(typeof fileStoreModule.DacarFileAdapter, "function");
  });

  it("round-trips dacar records as Python-parity loose files", async () => {
    const { adapter, dir } = newAdapter("roundtrip");
    const payload = Uint8Array.from({ length: 8 }, (_, i) => i + 0xa0);
    await adapter.set("dacar", "outbox.msgpack", payload);
    assert.deepEqual(await adapter.get("dacar", "outbox.msgpack"), payload);

    // Python `Store` writes loose files at the store root, not
    // `<namespace>/<key>.bin` bundles.
    assert.ok(existsSync(join(dir, "outbox.msgpack")));
    // Secret record mode (Python `Store._SECRET_MODE`).
    assert.equal(modeOf(join(dir, "outbox.msgpack")), 0o600);

    // Missing records read back as null; delete removes the file.
    assert.equal(await adapter.get("dacar", "sent.msgpack"), null);
    await adapter.delete("dacar", "outbox.msgpack");
    assert.equal(await adapter.get("dacar", "outbox.msgpack"), null);
    assert.ok(!existsSync(join(dir, "outbox.msgpack")));
  });

  it("applies the Python-matching mode per record name", async () => {
    const { adapter, dir } = newAdapter("modes");
    await adapter.set("dacar", "clock.msgpack", Uint8Array.of(1));
    await adapter.set("dacar", "state.msgpack", Uint8Array.of(1));
    // Public record (Python parity: clock 0644) vs secret (state 0600).
    assert.equal(modeOf(join(dir, "clock.msgpack")), 0o644);
    assert.equal(modeOf(join(dir, "state.msgpack")), 0o600);
    // The store directory itself is 0700 (Python `Store._DIR_MODE`).
    assert.equal(modeOf(dir), 0o700);
  });

  it("delegates non-dacar namespaces and the identity key to @reticulum/node", async () => {
    const { adapter, dir } = newAdapter("delegate");
    const payload = Uint8Array.from({ length: 4 }, (_, i) => i + 1);
    await adapter.set("other", "record", payload);
    assert.deepEqual(await adapter.get("other", "record"), payload);

    // The signing identity stays library-native (`identity.key`).
    const key = Uint8Array.from({ length: 128 }, (_, i) => (i * 7) & 0xff);
    await adapter.saveKey(key);
    assert.equal(toHex(await adapter.loadKey()), toHex(key));
    assert.ok(existsSync(join(dir, "identity.key")));
  });
});
