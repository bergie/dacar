/**
 * §11.2 targeted Delta delivery + §11.3 Paper Messages over LXMF.
 *
 * LXMF gives Dacar forward-secret, store-and-forward, point-to-point delivery
 * of Deltas to (possibly offline) nodes, alongside the public RFed broadcast
 * (§11.1, served by `./rfedSync.js`). A Delta (the §5.3 MessagePack payload)
 * is embedded as the *content* of an LXMF message whose title is the fixed
 * discriminator `dacar/sync/delta`; on receipt, only messages with that title
 * are fed to the shared {@link import("../delta.js").DeltaReceiver
 * DeltaReceiver} (verify-on-ingest, §11.2.4).
 *
 * §11.3 reuses the very same LXMF messages in LXMF's Paper Message encoding
 * (the `lxm://` URI, high-density QR), giving a fully air-gapped, optical
 * channel: export produces the encrypted URI; import feeds it straight back
 * through the router.
 *
 * This module is part of the optional transport layer: importing the pure core
 * never pulls it in. It depends only on `@reticulum/core`, which the core
 * already depends on, so no new dependency is added.
 *
 * Typical use (receiver, wired to a {@link import("@reticulum/core/src/lxmf/index.js").LXMRouter
 * LXMRouter}):
 *
 * ```js
 * router.addEventListener("message", async (event) => {
 *   await delivery.handleMessage(event.detail.message);
 * });
 * ```
 *
 * Typical use (sender, to a known recipient `lxmf.delivery` hash):
 *
 * ```js
 * await delivery.deliver(deltaPayload, recipientDeliveryHash);
 * ```
 *
 * @example Receiver with a DeltaReceiver wired in
 * // event.detail.message is the LXMF message the router just decrypted.
 * await delivery.handleMessage(event.detail.message);
 */

import { LXMessage as LXMFMessage } from "@reticulum/core/src/lxmf/index.js";
import { LXMF_DELIVERY_TITLE } from "../naming.js";

/**
 * Best-effort title of an LXMF message as text.
 *
 * Tolerates the title being a `Uint8Array` (some code paths leave it binary),
 * decoding it leniently. Used to filter on the fixed `dacar/sync/delta`
 * discriminator without ever touching the payload.
 * @param {{ title?: string | Uint8Array } | null} message
 * @returns {string}
 */
export function messageTitle(message) {
  const t = message ? message.title : undefined;
  if (typeof t === "string") return t;
  if (t instanceof Uint8Array) return new TextDecoder().decode(t);
  return "";
}

/**
 * Best-effort content of an LXMF message as raw bytes (the §5.3 Delta payload).
 *
 * `@reticulum/core`'s `Message.deserialize()` UTF-8-decodes the content element
 * into `message.content`, which corrupts arbitrary binary Deltas. The raw bytes
 * are preserved on `_decodedPayload[2]` (the same field the library uses
 * internally for §5.6 signature re-verification), so this helper recovers the
 * exact bytes a Python peer sent with `content=<delta bytes>`. For an
 * in-process-constructed message whose `content` is already a `Uint8Array`, it
 * returns that directly.
 * @param {{ content?: string | Uint8Array, _decodedPayload?: any[] } | null} message
 * @returns {Uint8Array}
 */
export function messageContent(message) {
  // Deserialized message: the raw content bytes survive on the decoded payload.
  const raw = message ? message._decodedPayload : undefined;
  if (Array.isArray(raw) && raw[2] instanceof Uint8Array) {
    return new Uint8Array(raw[2]);
  }
  const c = message ? message.content : undefined;
  if (c instanceof Uint8Array) return new Uint8Array(c);
  if (typeof c === "string") return new TextEncoder().encode(c);
  return new Uint8Array(0);
}

/**
 * §11.2 targeted Delta delivery over LXMF; §11.3 Paper Message channel.
 *
 * The send paths (`deliver`, `makePaperUri`) are thin wrappers over a bound
 * `LXMRouter` / outbound `Destination`; the receive path (`handleMessage`) is
 * the title filter + verify-on-ingest seam and is fully testable without a
 * live network (the LXMF codec is pure).
 */
export class LxmfDeltaDelivery {
  /** Fixed title discriminator (spec §11.2). Aliases `LXMF_DELIVERY_TITLE`. */
  static TITLE = LXMF_DELIVERY_TITLE;

  /**
   * @param {Object} [opts]
   * @param {import("../delta.js").DeltaReceiver | null} [opts.receiver]
   *   The shared DeltaReceiver (state + key resolver). May be omitted on a
   *   send-only node (then `handleMessage` throws if called).
   * @param {import("@reticulum/core/src/lxmf/index.js").LXMRouter | null} [opts.router]
   *   Optional bound `LXMRouter` for `deliver` / `ingestPaperUri`.
   */
  constructor({ receiver = null, router = null } = {}) {
    /** @type {import("../delta.js").DeltaReceiver | null} */
    this._receiver = receiver;
    /** @type {import("@reticulum/core/src/lxmf/index.js").LXMRouter | null} */
    this._router = router;
  }

  // -- §11.2 send --------------------------------------------------------

  /**
   * Builds an LXMF message wrapping one §5.3 Delta payload (§11.2.2).
   *
   * The content is the raw Delta bytes (encoded `bin` on the wire, matching the
   * Python reference's `content=<delta bytes>`), under the fixed
   * `dacar/sync/delta` title. The returned message is *not yet sent*; pass it
   * to `router.send()` (or call {@link deliver}) to queue it for the network.
   * @param {Uint8Array} deltaPayload
   * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
   * @param {Uint8Array} sourceHash The sender's `lxmf.delivery` hash.
   * @returns {import("@reticulum/core/src/lxmf/index.js").LXMessage}
   */
  makeMessage(deltaPayload, destinationHash, sourceHash) {
    if (!(deltaPayload instanceof Uint8Array)) {
      throw new TypeError("deltaPayload must be a Uint8Array");
    }
    return new LXMFMessage({
      destinationHash,
      sourceHash,
      // bin on the wire — round-trips byte-identical with the Python reference.
      content: new Uint8Array(deltaPayload),
      title: LxmfDeltaDelivery.TITLE,
    });
  }

  /**
   * Builds and queues a Delta for LXMF delivery via the bound router (§11.2).
   *
   * Uses the router's identity as the LXMF sender (and source hash). Delivery
   * method is chosen by the router (DIRECT link, falling back to opportunistic).
   * @param {Uint8Array} deltaPayload
   * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
   * @param {Object} [opts]
   * @param {Uint8Array | null} [opts.linkId] Reuse an existing DIRECT link id.
   * @returns {Promise<import("@reticulum/core/src/lxmf/index.js").LXMessage>}
   */
  async deliver(deltaPayload, destinationHash, { linkId = null } = {}) {
    if (!this._router) {
      throw new Error("LxmfDeltaDelivery.deliver requires a router");
    }
    const sourceHash = this._router.identity.identityHash;
    const message = this.makeMessage(deltaPayload, destinationHash, sourceHash);
    await this._router.send(message, this._router.identity, linkId);
    return message;
  }

  // -- §11.2 receive -----------------------------------------------------

  /**
   * LXMF `message` event handler: filter by title, then apply the Delta
   * (§11.2.4).
   *
   * Returns `true` iff a Dacar Delta was applied to the CRDT, `false`
   * otherwise (wrong title, or a malformed/forged payload — which
   * `DeltaReceiver.applyPayload()` swallows so a bad message can never crash
   * the transport). Non-Dacar messages are passed through untouched.
   * @param {{ title?: string | Uint8Array, content?: string | Uint8Array, _decodedPayload?: any[] } | null} message
   * @returns {Promise<boolean>}
   */
  async handleMessage(message) {
    if (messageTitle(message) !== LxmfDeltaDelivery.TITLE) return false;
    if (!this._receiver) {
      throw new Error("LxmfDeltaDelivery.handleMessage requires a receiver");
    }
    return this._receiver.applyPayload(messageContent(message));
  }

  // -- §11.3 Paper Messages (air-gapped / optical) ----------------------

  /**
   * Builds a §11.3 Paper Message (`lxm://` URI, QR-encodable) wrapping one
   * Delta.
   *
   * Same wrapping as {@link makeMessage} but encrypted to the recipient via
   * the outbound `lxmf.delivery` destination (which holds the recipient public
   * key), so the returned URI carries no plaintext Delta. `sourceIdentity`
   * signs the message; `outboundDestination` is the recipient's OUT
   * `lxmf.delivery` destination.
   * @param {Uint8Array} deltaPayload
   * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
   * @param {Object} opts
   * @param {import("@reticulum/core").Identity} opts.sourceIdentity
   * @param {import("@reticulum/core").Destination} opts.outboundDestination
   * @returns {Promise<string>} The `lxm://` paper URI.
   */
  async makePaperUri(deltaPayload, destinationHash, { sourceIdentity, outboundDestination }) {
    const message = this.makeMessage(deltaPayload, destinationHash, sourceIdentity.identityHash);
    return message.toPaperUri(sourceIdentity, outboundDestination);
  }

  /**
   * Feeds a scanned Paper Message URI back through the bound router (§11.3).
   *
   * The router decrypts it (it must own the delivery Identity) and dispatches
   * the recovered LXMF message as a `message` event, which
   * {@link handleMessage} then filters and applies. Returns the router's
   * ingest result (the reconstructed message, or `null` if it was not for this
   * node / already ingested).
   * @param {string} uri
   * @returns {Promise<import("@reticulum/core/src/lxmf/index.js").LXMessage | null>}
   */
  async ingestPaperUri(uri) {
    if (!this._router) {
      throw new Error("LxmfDeltaDelivery.ingestPaperUri requires a router");
    }
    return this._router.ingestUri(uri);
  }
}
