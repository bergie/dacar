/**
 * Smoketests for `ensureNodeIdentity` (work doc #6, §7.1/§7.2.4).
 *
 * When `--node <hash>` (or `--discover`) resolves to an rfed destination whose
 * announce isn't in the recall store yet, `RFedClient.subscribe` can't open a
 * link and fails with `rfed node identity unknown for <hash>; wait for its
 * announce`. `ensureNodeIdentity` proactively sends a `path?` request and polls
 * `Destination.recall` until the node's path-response announce populates it (or
 * a timeout elapses) — so an explicit `--node` makes dacar try to *get* the
 * identity instead of just failing.
 *
 * Exercises the real headless `Reticulum` + `Identity`/`Destination` seam: the
 * "known" path uses `Destination.remember` to populate the recall store; the
 * "request + wait" path spies on `Destination.recall`/`transport.requestPath`
 * for deterministic, network-free coverage of the poll loop.
 *
 * Mirrors Python's `tests/test_cli_ensure_node_identity.py`.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Destination, Identity, Reticulum, toHex } from "@reticulum/core";
import {
  DEFAULT_NODE_DISCOVERY_TIMEOUT,
  ensureNodeIdentity,
} from "../src/cli/session.js";

const NODE_HASH = Uint8Array.from({ length: 16 }, (_, i) => i + 1);

describe("ensureNodeIdentity (work doc #6 — proactive identity fetch)", () => {
  it("returns immediately when the identity is already known (no path request)", async () => {
    const rns = new Reticulum({});
    const identity = await Identity.generate();
    await Destination.remember(new Uint8Array(16), NODE_HASH, await identity.getPublicKey(), null);

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
    const state = { requested: false };

    // recall returns null until requestPath fires, then "the announce arrived"
    const recallCalls = { count: 0 };
    const originalRecall = Destination.recall;
    Destination.recall = async (targetHash) => {
      recallCalls.count += 1;
      return state.requested ? identity : null;
    };
    const requestedPath = [];
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async (destinationHash) => {
      state.requested = true; // simulate the announce arriving
      requestedPath.push(destinationHash);
    };
    try {
      let requested = 0;
      const result = await ensureNodeIdentity(rns, NODE_HASH, {
        timeout: 2000,
        pollInterval: 10,
        onRequest: () => requested++,
      });
      assert.equal(result.identityHash.length, 16);
      assert.equal(requested, 1); // the path request fired once
      assert.equal(requestedPath.length, 1);
      assert.deepEqual(requestedPath[0], NODE_HASH);
      assert.ok(recallCalls.count >= 2); // initial miss + at least one poll hit
    } finally {
      Destination.recall = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("raises the 'wait for its announce' error after the timeout when never announced", async () => {
    const rns = new Reticulum({});
    // recall stays null forever -> path request fires, polls until timeout,
    // then raises the same "wait for its announce" error the client raises.
    const originalRecall = Destination.recall;
    Destination.recall = async () => null;
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async () => {};
    try {
      let requested = 0;
      await assert.rejects(
        () =>
          ensureNodeIdentity(rns, NODE_HASH, {
            timeout: 0,
            pollInterval: 0,
            onRequest: () => requested++,
          }),
        /rfed node identity unknown for .*; wait for its announce/i,
      );
      assert.equal(requested, 1);
    } finally {
      Destination.recall = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("the error message contains the node hash", async () => {
    const rns = new Reticulum({});
    const originalRecall = Destination.recall;
    Destination.recall = async () => null;
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async () => {};
    try {
      await assert.rejects(
        () => ensureNodeIdentity(rns, NODE_HASH, { timeout: 0, pollInterval: 0 }),
        (err) => err.message.includes(toHex(NODE_HASH)),
      );
    } finally {
      Destination.recall = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("default timeout is reasonable for a one-shot CLI", () => {
    assert.ok(DEFAULT_NODE_DISCOVERY_TIMEOUT > 0);
    assert.ok(DEFAULT_NODE_DISCOVERY_TIMEOUT <= 60_000);
  });
});
