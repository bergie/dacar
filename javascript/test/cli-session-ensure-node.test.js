/**
 * Smoketests for `ensureNodeIdentity` (work doc #6, §7.1/§7.2.4).
 *
 * When `--node <hash>` (or `--discover`) resolves to an rfed destination whose
 * announce isn't in the recall store yet, `RFedClient.subscribe` can't open a
 * link and fails with `rfed node identity unknown for <hash>; wait for its
 * announce`. `ensureNodeIdentity` proactively sends a `path?` request and waits
 * for the node's path-response announce to populate the recall store (or a
 * timeout elapses) — so an explicit `--node` makes dacar try to *get* the
 * identity instead of just failing.
 *
 * Exercises the real headless `Reticulum` + `Identity`/`Destination` seam: the
 * "known" path uses `rns.transport.rememberIdentity` to populate the recall
 * store; the "request + wait" path spies on `transport.requestPath` and
 * dispatches the transport's `announce` event, mirroring
 * `transport.recallOrSolicitIdentity` (reticulum-js 0.9.3) internals for
 * deterministic, network-free coverage.
 *
 * Mirrors Python's `tests/test_cli_ensure_node_identity.py`.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Identity, Reticulum, toHex } from "@reticulum/core";
import {
  DEFAULT_NODE_DISCOVERY_TIMEOUT,
  ensureNodeIdentity,
} from "../src/cli/session.js";

const NODE_HASH = Uint8Array.from({ length: 16 }, (_, i) => i + 1);

describe("ensureNodeIdentity (work doc #6 — proactive identity fetch)", () => {
  it("returns immediately when the identity is already known (no path request)", async () => {
    const rns = new Reticulum({});
    const identity = await Identity.generate();
    await rns.transport.rememberIdentity(
      new Uint8Array(16),
      NODE_HASH,
      await identity.getPublicKey(),
      null,
    );

    let requested = 0;
    const result = await ensureNodeIdentity(rns, NODE_HASH, {
      onRequest: () => requested++,
    });
    assert.equal(result.identityHash.length, 16);
    assert.equal(requested, 0); // no path request — already known
  });

  it("sends a path request then returns when the announce arrives", async () => {
    const rns = new Reticulum({});
    const identity = await Identity.generate();

    const requestedPath = [];
    const originalRecall = rns.transport.recallIdentity.bind(rns.transport);
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.recallIdentity = async () => null; // never in the store
    rns.transport.requestPath = async (destinationHash) => {
      requestedPath.push(destinationHash);
      // The path-response announce arrives while the solicitation waits.
      rns.transport.dispatchEvent(
        new CustomEvent("announce", {
          detail: { destinationHash: NODE_HASH, identity },
        }),
      );
    };
    try {
      let requested = 0;
      const result = await ensureNodeIdentity(rns, NODE_HASH, {
        timeout: 2000,
        onRequest: () => requested++,
      });
      assert.equal(result.identityHash.length, 16);
      assert.equal(requested, 1); // the path request fired once
      assert.equal(requestedPath.length, 1);
      assert.deepEqual(requestedPath[0], NODE_HASH);
    } finally {
      rns.transport.recallIdentity = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("raises the 'wait for its announce' error after the timeout when never announced", async () => {
    const rns = new Reticulum({});
    // recall stays null forever -> path request fires, polls until timeout,
    // then raises the same "wait for its announce" error the client raises.
    const originalRecall = rns.transport.recallIdentity.bind(rns.transport);
    rns.transport.recallIdentity = async () => null;
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async () => {};
    try {
      let requested = 0;
      await assert.rejects(
        () =>
          ensureNodeIdentity(rns, NODE_HASH, { timeout: 50, onRequest: () => requested++ }),
        /rfed node identity unknown for .*; wait for its announce/i,
      );
      assert.equal(requested, 1);
    } finally {
      rns.transport.recallIdentity = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("the error message contains the node hash", async () => {
    const rns = new Reticulum({});
    const originalRecall = rns.transport.recallIdentity.bind(rns.transport);
    rns.transport.recallIdentity = async () => null;
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async () => {};
    try {
      await assert.rejects(
        () => ensureNodeIdentity(rns, NODE_HASH, { timeout: 50 }),
        (err) => err.message.includes(toHex(NODE_HASH)),
      );
    } finally {
      rns.transport.recallIdentity = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("default timeout is reasonable for a one-shot CLI", () => {
    assert.ok(DEFAULT_NODE_DISCOVERY_TIMEOUT > 0);
    assert.ok(DEFAULT_NODE_DISCOVERY_TIMEOUT <= 60_000);
  });
});
