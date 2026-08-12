/**
 * Smoketests for `ensureRfedPath` (path-request-before-link, §7.1/§7.2.4).
 *
 * `@reticulum/core`'s `RFedClient` opens a `Link` via `Destination.createLink()`,
 * which sends a `LINKREQUEST` addressed to the *derived* channel destination
 * (e.g. `rfed.channel.subscribe`). The JS `Link` does not proactively request a
 * path before the first attempt — a `LINKREQUEST` to a destination with no
 * known route is silently dropped by multi-hop peers (Transport "branch 5"), so
 * the link times out. `ensureRfedPath` mirrors rngit's `await_path` and the LXMF
 * router's `_requestAndAwaitPath`: compute the derived destination hash, send a
 * `path?` request for it, and wait for the node's path-response announce before
 * the client links.
 *
 * Mirrors Python's `tests/test_rfed_client_response.py::EnsurePathTest`.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Destination, Identity, Reticulum, toHex } from "@reticulum/core";
import {
  DEFAULT_PATH_TIMEOUT,
  ensureRfedPath,
} from "../src/cli/session.js";

const NODE_HASH = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const DEST_NAME = "rfed.channel.subscribe";

/** A minimal Reticulum whose transport path API we can stub. */
function fakeRns({ hasPath = () => false } = {}) {
  const rns = new Reticulum({});
  rns.transport.hasPath = hasPath;
  return rns;
}

describe("ensureRfedPath (rngit await_path pattern)", () => {
  it("is a no-op (no requestPath) when the path is already known", async () => {
    const identity = await Identity.generate();
    const originalRecall = Destination.recall;
    Destination.recall = async () => identity;
    let requested = 0;
    const rns = fakeRns({ hasPath: () => true });
    rns.transport.requestPath = async () => {
      requested++;
    };
    try {
      const destHash = await ensureRfedPath(rns, NODE_HASH, DEST_NAME, {
        onRequest: () => requested++,
      });
      assert.equal(destHash.length, 16);
      assert.equal(requested, 0); // no path request — already known
    } finally {
      Destination.recall = originalRecall;
    }
  });

  it("computes a real rfed.channel.* hash (matches Destination._computeHashes)", async () => {
    const identity = await Identity.generate();
    const originalRecall = Destination.recall;
    Destination.recall = async () => identity;
    const rns = fakeRns({ hasPath: () => true });
    try {
      const destHash = await ensureRfedPath(rns, NODE_HASH, DEST_NAME);
      // nameHash = SHA-256("rfed.channel.subscribe")[:10]
      // destHash = SHA-256(nameHash || identityHash)[:16]
      const enc = new TextEncoder();
      const nameHash = new Uint8Array(
        (await crypto.subtle.digest("SHA-256", enc.encode(DEST_NAME))).slice(0, 10),
      );
      const combined = new Uint8Array(nameHash.length + identity.identityHash.length);
      combined.set(nameHash, 0);
      combined.set(identity.identityHash, nameHash.length);
      const expected = new Uint8Array(
        (await crypto.subtle.digest("SHA-256", combined)).slice(0, 16),
      );
      assert.deepEqual(destHash, expected);
    } finally {
      Destination.recall = originalRecall;
    }
  });

  it("sends a path request then returns when the announce arrives", async () => {
    const identity = await Identity.generate();
    const originalRecall = Destination.recall;
    Destination.recall = async () => identity;
    const state = { requested: false };
    const requestedPath = [];
    const rns = fakeRns({ hasPath: (h) => state.requested });
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async (destinationHash) => {
      state.requested = true; // simulate the path-response announce arriving
      requestedPath.push(destinationHash);
    };
    try {
      let requested = 0;
      const destHash = await ensureRfedPath(rns, NODE_HASH, DEST_NAME, {
        timeout: 2000,
        pollInterval: 10,
        onRequest: () => requested++,
      });
      assert.equal(destHash.length, 16);
      assert.equal(requested, 1); // the path request fired once
      assert.equal(requestedPath.length, 1);
      assert.deepEqual(requestedPath[0], destHash); // requested the derived hash
    } finally {
      Destination.recall = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("raises the 'no path' error after the timeout when never announced", async () => {
    const identity = await Identity.generate();
    const originalRecall = Destination.recall;
    Destination.recall = async () => identity;
    const rns = fakeRns({ hasPath: () => false });
    const originalRequestPath = rns.transport.requestPath.bind(rns.transport);
    rns.transport.requestPath = async () => {};
    try {
      let requested = 0;
      await assert.rejects(
        () =>
          ensureRfedPath(rns, NODE_HASH, DEST_NAME, {
            timeout: 0,
            pollInterval: 0,
            onRequest: () => requested++,
          }),
        (err) =>
          /no path to .* could be resolved/i.test(err.message) &&
          err.message.includes(DEST_NAME),
      );
      assert.equal(requested, 1);
    } finally {
      Destination.recall = originalRecall;
      rns.transport.requestPath = originalRequestPath;
    }
  });

  it("raises 'identity unknown' when the node identity cannot be recalled", async () => {
    const originalRecall = Destination.recall;
    Destination.recall = async () => null;
    const rns = fakeRns();
    try {
      await assert.rejects(
        () => ensureRfedPath(rns, NODE_HASH, DEST_NAME, { timeout: 0 }),
        (err) =>
          /rfed node identity unknown for /i.test(err.message) &&
          err.message.includes(toHex(NODE_HASH)),
      );
    } finally {
      Destination.recall = originalRecall;
    }
  });

  it("is a no-op when the transport lacks the path-discovery API (mock)", async () => {
    const identity = await Identity.generate();
    const originalRecall = Destination.recall;
    Destination.recall = async () => identity;
    // A mock transport with neither hasPath nor requestPath.
    const rns = new Reticulum({});
    rns.transport = {};
    try {
      const destHash = await ensureRfedPath(rns, NODE_HASH, DEST_NAME);
      assert.equal(destHash.length, 16);
    } finally {
      Destination.recall = originalRecall;
    }
  });

  it("default timeout is reasonable for a one-shot CLI", () => {
    assert.ok(DEFAULT_PATH_TIMEOUT > 0);
    assert.ok(DEFAULT_PATH_TIMEOUT <= 60_000);
  });
});
