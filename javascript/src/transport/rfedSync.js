/**
 * §11.1 eventual consistency via RFed (Reticulum Federation).
 *
 * Global convergence of the CRDT is handled by RFed's many-to-many broadcast:
 * each node publishes its signed Operations (§5.3 Deltas) to a shared channel
 * (default `dacar.policy.v1`, deployment-overridable), and receives peers'
 * Deltas via RFed fanout. Because every Delta is individually Ed25519-signed,
 * RFed need not be trusted: received bytes flow through the *same* verify-on-
 * ingest seam (`DeltaReceiver.applyPayload()`, §11.2.4) as LXMF and optical
 * delivery — **never** through the unauthenticated `StateVector.merge()` path.
 * A forged or stale Delta is simply dropped before it can mutate state.
 *
 * `RfedDeltaSync` wraps a `@reticulum/core` `RFedClient`. A Delta is wrapped as
 * the LXMF *content* of a channel message under the fixed `dacar/sync/delta`
 * title; on receipt the channel is the feed discriminator (every message on it
 * is a Dacar Delta), and the content bytes are fed to `DeltaReceiver`.
 *
 * §11.3 air-gapped/optical transport is served by `./lxmfSync.js` (Paper
 * Messages); RFed is the online many-to-many path.
 *
 * This module is part of the optional transport layer: importing the pure core
 * never pulls it in. It depends only on `@reticulum/core`, which the core
 * already depends on, so no new dependency is added.
 *
 * Typical use:
 *
 * ```js
 * const client = new RFedClient({ identity, rns });
 * const sync = new RfedDeltaSync({ receiver: new DeltaReceiver(state, resolver), client });
 * await sync.subscribe(nodeHash);   // cache the channel's stamp cost
 * await sync.listen();              // receive live fanout Deltas
 * await sync.publish(deltaPayload, nodeHash);
 * ```
 */

import { LXMessage } from "@reticulum/core/src/lxmf/index.js";
import {
  deliveryHashFor,
  deriveChannel,
  unwrapChannelMessage,
} from "@reticulum/core/src/rfed/index.js";
import { LXMF_DELIVERY_TITLE, RFED_TOPIC } from "../naming.js";
import { messageContent } from "./lxmfSync.js";

/**
 * The shape of the decoded fanout callback argument from `RFedClient.listen`.
 * Only `message` is consumed here.
 * @typedef {Object} RfedDecoded
 * @property {import("@reticulum/core/src/lxmf/index.js").LXMessage} message
 * @property {import("@reticulum/core/src/core/identity.js").Identity} senderIdentity
 * @property {Uint8Array} senderPub
 * @property {Uint8Array} sourceHash
 * @property {boolean} signatureValid
 * @property {Uint8Array} channelHash
 * @property {string} channelName
 */

/**
 * The minimal `RFedClient` surface this adapter relies on. The real client from
 * `@reticulum/core` satisfies it; tests inject a fake.
 * @typedef {Object} RFedClientLike
 * @property {(nodeHash: Uint8Array, channelName: string) => Promise<{ ok: boolean, stampCost: number | null }>} subscribe
 * @property {(nodeHash: Uint8Array, channelName: string) => Promise<{ ok: boolean }>} [unsubscribe]
 * @property {(nodeHash: Uint8Array, channelName: string, lxmMessage: import("@reticulum/core/src/lxmf/index.js").LXMessage) => Promise<void>} publish
 * @property {(nodeHash: Uint8Array, channelName: string) => Promise<{ items: Array<{ channelHash: Uint8Array, blob: Uint8Array }>, morePending: boolean }>} pull
 * @property {(onMessage: (decoded: RfedDecoded) => void) => Promise<Uint8Array>} listen
 */

/**
 * §11.1 RFed Delta broadcast + receive, routed through verify-on-ingest.
 */
export class RfedDeltaSync {
  /** Default RFed channel (deployment-overridable, spec §11.1). */
  static DEFAULT_TOPIC = RFED_TOPIC;

  /**
   * @param {Object} opts
   * @param {import("../delta.js").DeltaReceiver | null} [opts.receiver]
   *   The shared DeltaReceiver (state + key resolver). May be omitted on a
   *   publish-only node (then `listen`/`pull` throw if called).
   * @param {RFedClientLike} opts.client A `@reticulum/core` `RFedClient`.
   * @param {string} [opts.topic] RFed channel name (default `dacar.policy.v1`).
   */
  constructor({ receiver = null, client, topic = RFED_TOPIC }) {
    if (!client) throw new TypeError("RfedDeltaSync requires an RFedClient");
    /** @type {import("../delta.js").DeltaReceiver | null} */
    this._receiver = receiver;
    /** @type {RFedClientLike} */
    this._client = client;
    /** @type {string} */
    this._topic = topic;
  }

  /** @returns {string} The configured RFed channel name. */
  get topic() {
    return this._topic;
  }

  /**
   * Builds the LXMF channel message wrapping one §5.3 Delta payload.
   *
   * The message's `sourceHash`/`destinationHash` are placeholders: the rfed
   * Phase-0 codec (`wrapChannelMessage`) overwrites them with the channel's
   * `lxmf.delivery` hashes before serialization, so the classic "source_hash
   * is the bare identity hash" bug cannot occur.
   * @param {Uint8Array} deltaPayload
   * @returns {import("@reticulum/core/src/lxmf/index.js").LXMessage}
   */
  makeMessage(deltaPayload) {
    if (!(deltaPayload instanceof Uint8Array)) {
      throw new TypeError("deltaPayload must be a Uint8Array");
    }
    return new LXMessage({
      // Overwritten by the rfed codec before going on the wire.
      destinationHash: new Uint8Array(16),
      sourceHash: new Uint8Array(16),
      content: new Uint8Array(deltaPayload),
      title: LXMF_DELIVERY_TITLE,
    });
  }

  /**
   * Subscribes to the channel on a node, caching its advertised stamp cost.
   * Call at least once per session and after any publish seems dropped.
   * @param {Uint8Array} nodeHash Any `rfed.*` destination hash of the node.
   * @returns {Promise<{ ok: boolean, stampCost: number | null }>} The client's `{ ok, stampCost }` result.
   */
  async subscribe(nodeHash) {
    return this._client.subscribe(nodeHash, this._topic);
  }

  /**
   * Removes the subscription.
   * @param {Uint8Array} nodeHash
   * @returns {Promise<{ ok: boolean }>}
   */
  async unsubscribe(nodeHash) {
    if (!this._client.unsubscribe) {
      throw new Error("RFedClient has no unsubscribe");
    }
    return this._client.unsubscribe(nodeHash, this._topic);
  }

  /**
   * Publishes a Delta to the channel (fire-and-forget, §11.1).
   *
   * Call {@link subscribe} first so the channel's stamp cost is cached; an
   * unstamped publish may be silently dropped by a cost-enforcing node.
   * @param {Uint8Array} deltaPayload
   * @param {Uint8Array} nodeHash
   * @returns {Promise<import("@reticulum/core/src/lxmf/index.js").LXMessage>} The published message.
   */
  async publish(deltaPayload, nodeHash) {
    const message = this.makeMessage(deltaPayload);
    await this._client.publish(nodeHash, this._topic, message);
    return message;
  }

  /**
   * Starts listening for live fanout Deltas and routes each through
   * verify-on-ingest (§11.1, §11.2.4).
   *
   * The channel is the feed discriminator, so every received message is a
   * Dacar Delta; `DeltaReceiver.applyPayload()` authenticates it by signature
   * and swallows any malformed/forged payload so a bad message can never crash
   * the transport or mutate state.
   * @returns {Promise<Uint8Array>} The local `rfed.delivery` destination hash.
   */
  async listen() {
    if (!this._receiver) {
      throw new Error("RfedDeltaSync.listen requires a receiver");
    }
    const receiver = this._receiver;
    return this._client.listen((decoded) => {
      // RFedClient.invoke does not await the callback; run applyPayload without
      // leaving an unhandled rejection (it swallows malformed payloads itself).
      Promise.resolve(receiver.applyPayload(messageContent(decoded.message))).catch(
        () => {},
      );
    });
  }

  /**
   * Drains the node's deferred queue (offline catch-up) and routes each blob
   * through verify-on-ingest (§11.1).
   *
   * Each blob is EC-decrypted with the derived channel identity and the
   * recovered LXMF message's content is applied. Foreign/undecryptable blobs
   * are dropped, not fatal. Repeats until the node reports no more pending
   * pages. Returns the count of Deltas newly applied to the CRDT.
   *
   * > **Assumption:** the node serves each deferred entry's `blob` as the rfed
   * > `inner_blob` (the EC-encrypted channel message), matching the fanout
   * > payload's inner half. Verify against a live rfed node on first deploy.
   *
   * @param {Uint8Array} nodeHash
   * @returns {Promise<number>}
   */
  async pull(nodeHash) {
    if (!this._receiver) {
      throw new Error("RfedDeltaSync.pull requires a receiver");
    }
    const { identity: channelIdentity } = await deriveChannel(this._topic);
    const channelDeliveryHash = await deliveryHashFor(channelIdentity);
    const receiver = this._receiver;
    let applied = 0;
    let morePending = true;
    while (morePending) {
      const page = await this._client.pull(nodeHash, this._topic);
      for (const item of page.items) {
        try {
          const decoded = await unwrapChannelMessage({
            innerBlob: item.blob,
            channelIdentity,
            channelDeliveryHash,
          });
          if (await receiver.applyPayload(messageContent(decoded.message))) {
            applied++;
          }
        } catch {
          // a foreign/undecryptable blob is dropped, never fatal
        }
      }
      morePending = page.morePending;
    }
    return applied;
  }
}
