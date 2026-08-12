/**
 * Smoketests for `runPublish`/`runSync` surfacing a failed subscribe.
 *
 * A rejected `/rfed/subscribe` (the node replies `{ ok: false }`) must raise,
 * not be swallowed — the topic must have a subscription on the node for peer
 * sync to work, and a silent failure left `dacar sync` completing without
 * increasing the node's subscription count (the payload-encoding bug it masked
 * is fixed in the Python client; this guards the "loud failure" contract on
 * both runtimes).
 *
 * Mirrors Python's `tests/test_cli_online.py` `*_raises_on_failed_subscribe`.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import { runPublish, runSync } from "../src/cli/session.js";
import { DeltaReceiver } from "../src/delta.js";
import { Keyring } from "../src/verifier.js";

const NODE = Uint8Array.from({ length: 16 }, () => 7);
const TOPIC = "dacar.policy.v1";

/** A fake RFedClient whose subscribe returns `{ ok: false }`. */
class FailingSubscribeClient {
  constructor() {
    this.published = [];
    this.subscribed = null;
    this.pulled = false;
  }
  async subscribe(nodeHash, channelName) {
    this.subscribed = [nodeHash, channelName];
    return { ok: false, stampCost: null };
  }
  async unsubscribe() {
    return { ok: true };
  }
  async publish(nodeHash, channelName, lxm) {
    this.published.push([nodeHash, channelName, lxm]);
  }
  async pull() {
    this.pulled = true;
    return { items: [], morePending: false };
  }
}

describe("runPublish/runSync — failed subscribe is loud (not silent)", () => {
  it("runPublish raises when the node rejects the subscribe", async () => {
    const client = new FailingSubscribeClient();
    await assert.rejects(
      () => runPublish({ deltaPayload: new Uint8Array([1, 2, 3]), nodeHash: NODE, topic: TOPIC, client }),
      /rfed subscribe to .* failed/i,
    );
    // Publish never happened — the failed subscribe short-circuits.
    assert.equal(client.published.length, 0);
  });

  it("runSync raises when the node rejects the subscribe", async () => {
    const client = new FailingSubscribeClient();
    const identity = await Identity.generate();
    const keyring = new Keyring().registerSingle(
      identity.identityHash,
      await identity.getPublicKey(),
    );
    const receiver = new DeltaReceiver(null, keyring);
    await assert.rejects(
      () => runSync({ nodeHash: NODE, topic: TOPIC, client, receiver }),
      /rfed subscribe to .* failed/i,
    );
    // Pull never happened — the failed subscribe short-circuits.
    assert.equal(client.pulled, false);
  });
});
