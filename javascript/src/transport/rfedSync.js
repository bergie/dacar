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
 * `RfedDeltaSync` wraps a `@reticulum/core` `RFedClient`. A Delta travels in
 * Dacar's **compact inner format** (§11.1.1): the raw §5.3 payload is placed
 * straight after the RTID source-identity prelude and EC-encrypted to the
 * derived channel identity — no LXMF envelope, which would only duplicate the
 * Delta's own destination/source/signature/timestamp and push a typical
 * 170-byte Delta past the 500-byte RNS MTU. On receipt the channel is the feed
 * discriminator (every message on it is a Dacar Delta), and the recovered Delta
 * bytes are fed to `DeltaReceiver`.
 *
 * The compact format is built on `@reticulum/core`'s raw RFed primitives —
 * `subscribeRaw` / `publishRaw` / `unwrapRawChannelMessage` — which carry an
 * arbitrary self-authenticating payload in place of the LXMF tail. The Delta's
 * own Ed25519 signature (§5.3 field [7]) is the authenticity check at
 * verify-on-ingest; the prelude's `sender_identity_pub` only identifies the
 * transport sender.
 *
 * §11.2 targeted delivery and §11.3 air-gapped/optical transport still use full
 * LXMF framing (`./lxmfSync.js`, Paper Messages); only the RFed broadcast
 * channel uses the compact format.
 *
 * This module is part of the optional transport layer: importing the pure core
 * never pulls it in. It depends only on `@reticulum/core`, which the core
 * already depends on, so no new dependency is added. It mirrors
 * `python/dacar/transport/rfed_sync.py` (the canonical implementation).
 *
 * Typical use:
 *
 * ```js
 * const client = new RFedClient({ identity, rns });
 * const sync = new RfedDeltaSync({ receiver: new DeltaReceiver(state, resolver), client });
 * await sync.subscribe(nodeHash);   // subscribeRaw: cache stamp cost + mark raw
 * await sync.listen();              // receive live fanout Deltas (kind: "raw")
 * await sync.publish(deltaPayload, nodeHash);
 * ```
 */

import { Destination } from "@reticulum/core/src/core/destination.js";
import {
  deriveChannel,
  unwrapRawChannelMessage,
} from "@reticulum/core/src/rfed/index.js";
import { MicroMsgPack } from "@reticulum/core/src/utils/msgpack.js";
import { RFED_TOPIC } from "../naming.js";

/**
 * The minimal `RFedClient` surface this adapter relies on. The real client from
 * `@reticulum/core` satisfies it; tests inject a fake. The raw-publish API
 * (`subscribeRaw` / `publishRaw`) carries a self-authenticating payload in the
 * RTID prelude instead of an LXMF envelope (§11.1.1).
 *
 * @typedef {Object} RFedClientLike
 * @property {(nodeHash: Uint8Array, channelName: string) => Promise<{ ok: boolean, stampCost: number | null }>} subscribeRaw
 *   Subscribes and marks the channel raw so fanout is decoded via
 *   `unwrapRawChannelMessage` (not the LXMF path).
 * @property {(nodeHash: Uint8Array, channelName: string) => Promise<{ ok: boolean }>} [unsubscribe]
 * @property {(nodeHash: Uint8Array, channelName: string, payload: Uint8Array) => Promise<void>} publishRaw
 *   Fire-and-forget SEND of a raw application payload (wrapped in the RTID
 *   prelude + EC-encrypted to the channel identity by the client).
 * @property {(nodeHash: Uint8Array, channelName: string) => Promise<{ items: Array<{ channelHash: Uint8Array, blob: Uint8Array }>, morePending: boolean }>} pull
 * @property {(onMessage: (decoded: RfedDecodedRaw) => void) => Promise<Uint8Array>} listen
 *   Delivers a decoded fanout object; channels subscribed via `subscribeRaw`
 *   carry `kind: "raw"` with a `payload` field (the unwrapped application
 *   bytes). The client performs the EC-decrypt + RTID-prelude unwrap.
 */

/**
 * The shape of the decoded fanout callback argument from `RFedClient.listen` for
 * a raw channel. Only `kind` and `payload` are consumed here.
 *
 * @typedef {Object} RfedDecodedRaw
 * @property {"raw"|"lxmf"} kind
 * @property {Uint8Array} [payload] Raw application payload (`kind === "raw"`).
 * @property {import("@reticulum/core/src/core/identity.js").Identity} [senderIdentity]
 * @property {Uint8Array} [senderPub]
 * @property {Uint8Array} [channelHash]
 * @property {string} [channelName]
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
   * Subscribes to the channel on a node (raw mode) and caches its advertised
   * stamp cost. Call at least once per session and after any publish seems
   * dropped.
   *
   * Uses `subscribeRaw` so incoming fanout is decoded via
   * `unwrapRawChannelMessage` (the Dacar compact inner format), not the LXMF
   * path. The wire protocol is identical to `subscribe` — the node never
   * inspects the `inner_blob` — only this client's local decode changes.
   * @param {Uint8Array} nodeHash Any `rfed.*` destination hash of the node.
   * @returns {Promise<{ ok: boolean, stampCost: number | null }>}
   */
  async subscribe(nodeHash) {
    return this._client.subscribeRaw(nodeHash, this._topic);
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
   * The client wraps the raw Delta in the RTID prelude + EC-encrypts it to the
   * channel identity (`publishRaw` → `wrapRawChannelMessage`) and sends it as a
   * fire-and-forget DATA packet. Call {@link subscribe} first so the channel's
   * stamp cost is cached; an unstamped publish may be silently dropped by a
   * cost-enforcing node. Returns `true` if the transport accepted the outbound
   * packet (no throw) — transport acceptance ≠ node storage (fire-and-forget).
   * @param {Uint8Array} deltaPayload
   * @param {Uint8Array} nodeHash
   * @returns {Promise<boolean>}
   */
  async publish(deltaPayload, nodeHash) {
    if (!(deltaPayload instanceof Uint8Array)) {
      throw new TypeError("deltaPayload must be a Uint8Array");
    }
    await this._client.publishRaw(nodeHash, this._topic, new Uint8Array(deltaPayload));
    return true; // fire-and-forget: no throw ⇒ transport accepted the packet
  }

  /**
   * Starts listening for live fanout Deltas and routes each through
   * verify-on-ingest (§11.1, §11.2).
   *
   * Because the channel was subscribed via `subscribeRaw`, the client decodes
   * each fanout delivery with `unwrapRawChannelMessage` and the callback
   * receives `{ kind: "raw", payload }`. The `payload` is the carried §5.3
   * Delta, fed to `DeltaReceiver.applyPayload()`, which authenticates it by
   * signature and swallows any malformed/forged payload so a bad message can
   * never crash the transport or mutate state.
   * @returns {Promise<Uint8Array>} The local `rfed.delivery` destination hash.
   */
  async listen() {
    if (!this._receiver) {
      throw new Error("RfedDeltaSync.listen requires a receiver");
    }
    const receiver = this._receiver;
    return this._client.listen(async (decoded) => {
      if (decoded?.kind !== "raw") return; // not a raw channel payload

      // Remember the sender identity so future RNS recalls succeed without
      // needing an announce. Best-effort: decode must still succeed without it.
      try {
        // Extract issuer_hash (field [0]) from the delta to map identity.
        const decodedDelta = MicroMsgPack.decode(decoded.payload);
        if (Array.isArray(decodedDelta) && decodedDelta.length > 0) {
          const issuerHash = decodedDelta[0];
          if (issuerHash instanceof Uint8Array && issuerHash.length === 16) {
            await Destination.remember(
              decoded.senderIdentity.identityHash,
              decoded.senderIdentity.identityHash,
              decoded.senderPub,
              null,
            );
          }
        }
      } catch {
        // Remembering is best-effort; failure doesn't affect correctness.
      }

      // RFedClient.invoke does not await the callback; run applyPayload without
      // leaving an unhandled rejection (it swallows malformed payloads itself).
      Promise.resolve(receiver.applyPayload(decoded.payload)).catch(() => {});
    });
  }

  /**
   * Drains the node's deferred queue (offline catch-up) and routes each blob
   * through verify-on-ingest (§11.1).
   *
   * Each blob is the EC-encrypted `inner_blob` (the node serves it verbatim, as
   * stored); it is EC-decrypted with the derived channel identity and the
   * recovered Dacar Delta (`unwrapRawChannelMessage`) is applied. Foreign/
   * undecryptable blobs are dropped, not fatal. Repeats until the node reports
   * no more pending pages. Returns the count of Deltas newly applied to the
   * CRDT.
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
    const receiver = this._receiver;
    let applied = 0;
    let morePending = true;
    while (morePending) {
      const page = await this._client.pull(nodeHash, this._topic);
      for (const item of page.items) {
        try {
          const decoded = await unwrapRawChannelMessage({
            innerBlob: item.blob,
            channelIdentity,
          });

          // Remember the sender identity so future RNS recalls succeed without
          // needing an announce. Best-effort: decode must still succeed without it.
          try {
            // Extract issuer_hash (field [0]) from the delta to map identity.
            const decodedDelta = MicroMsgPack.decode(decoded.payload);
            if (Array.isArray(decodedDelta) && decodedDelta.length > 0) {
              const issuerHash = decodedDelta[0];
              if (issuerHash instanceof Uint8Array && issuerHash.length === 16) {
                await Destination.remember(
                  decoded.senderIdentity.identityHash,
                  decoded.senderIdentity.identityHash,
                  decoded.senderPub,
                  null,
                );
              }
            }
          } catch {
            // Remembering is best-effort; failure doesn't affect correctness.
          }

          if (await receiver.applyPayload(decoded.payload)) {
            applied++;
          }
        } catch {
          // a foreign/undecryptable blob is dropped, never fatal
        }
      }
      morePending = !!page.morePending;
    }
    return applied;
  }
}
