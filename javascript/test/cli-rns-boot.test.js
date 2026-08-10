/**
 * Smoketests for `bootRns` / `attachInterface` (`src/cli/rns_boot.js`).
 *
 * Guards the `dacar sync --discover` silent-timeout regression: `bootRns`
 * must (a) `await iface.connect()` before attaching — otherwise the
 * interface's streams are never set up, `_packetWriter` stays null, and
 * `TransportCore.broadcast()` silently skips it (no announces in *or* out) —
 * and (b) attach the interface with `isDefault = true` so routed sends have
 * a fallback. Both are asserted via injectable factory fakes (network-free).
 *
 * Also covers `--verbose`: it raises the Reticulum log threshold to DEBUG and
 * logs interface status + each validated announce the transport sees, so a
 * failing `--discover` shows whether any announces arrive and for which
 * aspects.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { getLogLevel, LogLevel, Reticulum, toHex } from "@reticulum/core";
import { FileStorageAdapter } from "@reticulum/node";
import { bootRns, attachInterface } from "../src/cli/rns_boot.js";
import { rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Minimal Interface stand-in: a real EventTarget (so `transport.addInterface`
 * can `addEventListener("packet"/"closed"/"error")`) with a `connect()` that
 * flips `online` and records that it was awaited. No `writable` (so the
 * transport skips writer acquisition) — we only assert the connect/default
 * contract, not packet flow.
 */
class FakeInterface extends EventTarget {
  /**
   * @param {string} name
   */
  constructor(name) {
    super();
    this.name = name;
    this.online = false;
    this.bitrate = 0;
    this.writable = null;
    this._packetWriter = null;
    this.rxb = 0;
    this.txb = 0;
    this.created = Date.now();
    this.connectCalls = 0;
    this.isConnectedToSharedInstance = false;
  }
  async connect() {
    this.connectCalls += 1;
    this.online = true;
  }
  async disconnect() {
    this.online = false;
  }
  get isOpen() {
    return this.online;
  }
}

/**
 * Mirrors `LocalClientInterface.connectToSharedInstance()`: constructs a fake
 * and **connects it** before returning (the real factory connects internally
 * and hands back a live interface; `attachInterface` does not call `connect()`
 * on the shared path).
 * @param {string} name
 * @returns {Promise<FakeInterface>}
 */
async function connectedShared(name) {
  const iface = new FakeInterface(name);
  await iface.connect();
  return iface;
}

function tmpConfigDir() {
  return mkdtempSync(join(tmpdir(), "dacar-rns-boot-"));
}

describe("bootRns / attachInterface — connect + default-attach contract", () => {
  it("shared path: connects the shared interface and attaches it as default", async () => {
    const shared = await connectedShared("shared-rnsd");
    const rns = await bootRns(tmpConfigDir(), "shared", {
      sharedFactory: async () => shared,
    });
    // The shared factory (connectToSharedInstance) connects internally.
    assert.equal(shared.connectCalls, 1, "the shared factory must connect the interface");
    assert.equal(shared.online, true, "interface must be online after connect");
    assert.equal(
      rns.transport.defaultInterface,
      shared,
      "interface must be attached as the default (isDefault=true)",
    );
    assert.equal(rns.transport.interfaces.size, 1, "exactly one interface attached");
  });

  it("shared path falls back to AutoInterface when no rnsd is reachable", async () => {
    const auto = new FakeInterface("auto-fallback");
    const rns = await bootRns(tmpConfigDir(), "shared", {
      sharedFactory: async () => null, // no shared instance available
      autoFactory: () => auto,
    });
    assert.equal(auto.connectCalls, 1, "fallback AutoInterface must be connected");
    assert.equal(auto.online, true);
    assert.equal(rns.transport.defaultInterface, auto);
    assert.equal(rns.transport.interfaces.size, 1);
  });

  it("auto path: connects and default-attaches the AutoInterface", async () => {
    const auto = new FakeInterface("auto");
    const rns = await bootRns(tmpConfigDir(), "auto", { autoFactory: () => auto });
    assert.equal(auto.connectCalls, 1);
    assert.equal(rns.transport.defaultInterface, auto);
  });

  it("tcp path: connects and default-attaches the TCPClientInterface", async () => {
    const tcp = new FakeInterface("tcp");
    const rns = await bootRns(tmpConfigDir(), "tcp", {
      tcpFactory: () => tcp,
    });
    assert.equal(tcp.connectCalls, 1);
    assert.equal(rns.transport.defaultInterface, tcp);
  });

  it("attachInterface returns a human-readable label", async () => {
    const shared = await connectedShared("shared");
    const rns = new Reticulum({});
    const label = await attachInterface(rns, "shared", {
      sharedFactory: async () => shared,
    });
    assert.equal(label, "shared rnsd instance");
  });

  it("attachInterface returns the fallback label when shared is unavailable", async () => {
    const auto = new FakeInterface("auto");
    const rns = new Reticulum({});
    const label = await attachInterface(rns, "shared", {
      sharedFactory: async () => null,
      autoFactory: () => auto,
    });
    assert.equal(label, "AutoInterface (shared instance unavailable)");
  });
});

describe("bootRns — verbose diagnostics", () => {
  it("raises the Reticulum log threshold to DEBUG", async () => {
    const before = getLogLevel();
    try {
      await bootRns(tmpConfigDir(), "shared", {
        verbose: true,
        sharedFactory: async () => connectedShared("shared"),
      });
      assert.equal(getLogLevel(), LogLevel.DEBUG);
    } finally {
      // Restore: parse the level name back. setLogLevel is importable but we
      // only need to not leave the global threshold altered for other tests.
      const { setLogLevel } = await import("@reticulum/core");
      setLogLevel(before);
    }
  });

  it("logs interface status and each announce the transport validates", async () => {
    const before = getLogLevel();
    const writes = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (/** @type {string} */ s) => {
      writes.push(s);
      return true;
    };
    try {
      const shared = await connectedShared("shared");
      const rns = await bootRns(tmpConfigDir(), "shared", {
        verbose: true,
        sharedFactory: async () => shared,
      });
      // Interface status line.
      assert.ok(
        writes.some((s) => /interface=shared rnsd instance attached=1 online=1/.test(s)),
        `expected interface status line, got: ${writes.join("")}`,
      );
      // Dispatch a synthetic announce the verbose listener should log.
      const destHash = new Uint8Array(16).fill(0xab);
      const nameHash = new Uint8Array(10).fill(0xcd);
      rns.transport.dispatchEvent(
        new CustomEvent("announce", {
          detail: { destinationHash: destHash, nameHash, packet: { hops: 2 } },
        }),
      );
      assert.ok(
        writes.some((s) =>
          /announce: dest=abababababababababababababababab name=cdcdcdcdcdcdcdcdcdcd hops=2/.test(s),
        ),
        `expected announce line, got: ${writes.join("")}`,
      );
    } finally {
      process.stderr.write = orig;
      const { setLogLevel } = await import("@reticulum/core");
      setLogLevel(before);
    }
  });

  it("does not raise the log threshold or write diagnostics when verbose is off", async () => {
    const before = getLogLevel();
    const writes = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (/** @type {string} */ s) => {
      writes.push(s);
      return true;
    };
    try {
      await bootRns(tmpConfigDir(), "shared", {
        sharedFactory: async () => connectedShared("shared"),
      });
      assert.equal(getLogLevel(), before, "verbose off must not change the log level");
      assert.ok(
        writes.every((s) => !/rns: interface=/.test(s)),
        "verbose off must not log interface status",
      );
    } finally {
      process.stderr.write = orig;
    }
  });
});
