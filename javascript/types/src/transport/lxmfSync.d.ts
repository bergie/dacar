/**
 * Best-effort title of an LXMF message as text.
 *
 * Tolerates the title being a `Uint8Array` (some code paths leave it binary),
 * decoding it leniently. Used to filter on the fixed `dacar/sync/delta`
 * discriminator without ever touching the payload.
 * @param {{ title?: string | Uint8Array } | null} message
 * @returns {string}
 */
export function messageTitle(message: {
    title?: string | Uint8Array;
} | null): string;
/**
 * Best-effort content of an LXMF message as raw bytes (the §5.3 Delta payload).
 *
 * `@reticulum/lxmf`'s `Message.deserialize()` UTF-8-decodes the content element
 * into `message.content`, which corrupts arbitrary binary Deltas. The raw bytes
 * are preserved on `_decodedPayload[2]` (the same field the library uses
 * internally for §5.6 signature re-verification), so this helper recovers the
 * exact bytes a Python peer sent with `content=<delta bytes>`. For an
 * in-process-constructed message whose `content` is already a `Uint8Array`, it
 * returns that directly.
 * @param {{ content?: string | Uint8Array, _decodedPayload?: any[] } | null} message
 * @returns {Uint8Array}
 */
export function messageContent(message: {
    content?: string | Uint8Array;
    _decodedPayload?: any[];
} | null): Uint8Array;
/**
 * Encode signed Delta payloads as one batch envelope (§11.2, work doc #14).
 *
 * The wire format is the msgpack array `[payload, …]` (each element the exact
 * signed §5.3 bytes, `bin` on the wire) under the fixed title
 * {@link LXMF_BATCH_TITLE} — byte-identical with the Python reference's
 * `encode_batch`. Pure packing: every element keeps its own signature and is
 * verified individually at ingest.
 * @param {Uint8Array[]} payloads
 * @returns {Uint8Array}
 */
export function encodeBatch(payloads: Uint8Array[]): Uint8Array;
/**
 * Decode a batch envelope into its Delta payloads.
 *
 * Strict: the content must be a msgpack array of binary payloads. Throws
 * `Error` for anything else (not msgpack, not an array, non-binary elements)
 * so {@link LxmfDeltaDelivery.handleMessage} can drop a malformed batch whole
 * without ever crashing the transport.
 * @param {Uint8Array | string} content
 * @returns {Uint8Array[]}
 */
export function decodeBatch(content: Uint8Array | string): Uint8Array[];
/**
 * Greedily split payloads into chunks whose *encoded* batch fits `maxBytes`.
 *
 * Each chunk satisfies `encodeBatch(chunk).length <= maxBytes`; payloads stay
 * in order and are never split. A single payload whose encoded batch exceeds
 * `maxBytes` becomes an (oversized) singleton chunk — the caller checks the
 * transport limit (e.g. paper packing throws on `PAPER_MDU` overflow).
 * @param {Uint8Array[]} payloads
 * @param {number} maxBytes
 * @returns {Uint8Array[][]}
 */
export function packChunks(payloads: Uint8Array[], maxBytes: number): Uint8Array[][];
/**
 * Split payloads into as few paper URIs as the paper MDU allows (§11.3, work
 * doc #14): greedy {@link packChunks} packing under
 * {@link PAPER_CONTENT_BUDGET}, then an adaptive pass — any chunk whose
 * packed paper payload exceeds `PAPER_MDU` (ratchets change the encryption
 * overhead) is halved and retried until every chunk fits. A lone payload
 * that still exceeds the MDU propagates the `TypeError`. Returns the list of
 * `lxm://` URIs (one per QR), unordered and independently verifiable.
 *
 * @param {Uint8Array[]} payloads
 * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
 * @param {Object} opts
 * @param {import("@reticulum/core").Identity} opts.sourceIdentity
 * @param {import("@reticulum/core").Destination} opts.outboundDestination
 * @returns {Promise<string[]>}
 */
export function packPaperUris(payloads: Uint8Array[], destinationHash: Uint8Array, { sourceIdentity, outboundDestination }: {
    sourceIdentity: import("@reticulum/core").Identity;
    outboundDestination: import("@reticulum/core").Destination;
}): Promise<string[]>;
/**
 * Conservative content budget for paper chunks: `PAPER_MDU` minus the fixed
 * paper overhead measured against the reference LXMF (16 B destination prefix
 * + ~92 B identity encryption + ~127 B LXM msgpack framing ≈ 235 B; ratchets
 * shift it slightly, which `packPaperUris` absorbs by halving).
 * Cross-implementation chunk *boundaries* are irrelevant — only the batch
 * codec must interop — so a conservative budget is safe.
 */
export const PAPER_CONTENT_BUDGET: number;
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
    static TITLE: string;
    /**
     * @param {Object} [opts]
     * @param {import("../delta.d.ts").DeltaReceiver | null} [opts.receiver]
     *   The shared DeltaReceiver (state + key resolver). May be omitted on a
     *   send-only node (then `handleMessage` throws if called).
     * @param {import("@reticulum/lxmf").LXMRouter | null} [opts.router]
     *   Optional bound `LXMRouter` for `deliver` / `ingestPaperUri`.
     */
    constructor({ receiver, router }?: {
        receiver?: import("../delta.d.ts").DeltaReceiver | null;
        router?: import("@reticulum/lxmf").LXMRouter | null;
    });
    /** @type {import("../delta.d.ts").DeltaReceiver | null} */
    _receiver: import("../delta.d.ts").DeltaReceiver | null;
    /** @type {import("@reticulum/lxmf").LXMRouter | null} */
    _router: import("@reticulum/lxmf").LXMRouter | null;
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
     * @returns {import("@reticulum/lxmf").LXMessage}
     */
    makeMessage(deltaPayload: Uint8Array, destinationHash: Uint8Array, sourceHash: Uint8Array): import("@reticulum/lxmf").LXMessage;
    /**
     * Builds and queues a Delta for LXMF delivery via the bound router (§11.2).
     *
     * Uses the router's identity as the LXMF sender (and source hash). Delivery
     * method is chosen by the router (DIRECT link, falling back to opportunistic,
     * with identity solicitation when the recipient is not yet recallable).
     * @param {Uint8Array} deltaPayload
     * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
     * @param {Object} [opts]
     * @param {Uint8Array | null} [opts.linkId] Reuse an existing DIRECT link id.
     * @returns {Promise<import("@reticulum/lxmf").LXMessage>}
     */
    deliver(deltaPayload: Uint8Array, destinationHash: Uint8Array, { linkId }?: {
        linkId?: Uint8Array | null;
    }): Promise<import("@reticulum/lxmf").LXMessage>;
    /**
     * Builds an LXMF message wrapping multiple Deltas (batch envelope, §11.2,
     * work doc #14).
     *
     * Content is {@link encodeBatch} of `payloads` under the fixed title
     * `dacar/sync/batch`. Callers pre-chunk with {@link packChunks} so the
     * encoded content fits the transport limit. The message is *not yet sent*;
     * submit it to a propagation node or send it like any other.
     * @param {Uint8Array[]} payloads
     * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
     * @param {Uint8Array} sourceHash The sender's `lxmf.delivery` hash.
     * @returns {import("@reticulum/lxmf").LXMessage}
     */
    makeBatchMessage(payloads: Uint8Array[], destinationHash: Uint8Array, sourceHash: Uint8Array): import("@reticulum/lxmf").LXMessage;
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
    handleMessage(message: {
        title?: string | Uint8Array;
        content?: string | Uint8Array;
        _decodedPayload?: any[];
    } | null): Promise<boolean>;
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
    makePaperUri(deltaPayload: Uint8Array, destinationHash: Uint8Array, { sourceIdentity, outboundDestination }: {
        sourceIdentity: import("@reticulum/core").Identity;
        outboundDestination: import("@reticulum/core").Destination;
    }): Promise<string>;
    /**
     * Builds a §11.3 Paper Message URI wrapping a *chunk* of Deltas (work doc
     * #14): the batch envelope encrypted to the recipient, as one `lxm://` URI
     * (one QR). Pre-chunk with {@link packChunks} under
     * {@link PAPER_CONTENT_BUDGET}. Throws when the packed paper payload
     * exceeds `PAPER_MDU`.
     * @param {Uint8Array[]} payloads
     * @param {Uint8Array} destinationHash The recipient `lxmf.delivery` hash.
     * @param {Object} opts
     * @param {import("@reticulum/core").Identity} opts.sourceIdentity
     * @param {import("@reticulum/core").Destination} opts.outboundDestination
     * @returns {Promise<string>} The `lxm://` paper URI.
     */
    makeBatchPaperUri(payloads: Uint8Array[], destinationHash: Uint8Array, { sourceIdentity, outboundDestination }: {
        sourceIdentity: import("@reticulum/core").Identity;
        outboundDestination: import("@reticulum/core").Destination;
    }): Promise<string>;
    /**
     * Feeds a scanned Paper Message URI back through the bound router (§11.3).
     *
     * The router decrypts it (it must own the delivery Identity) and dispatches
     * the recovered LXMF message as a `message` event, which
     * {@link handleMessage} then filters and applies. Returns the router's
     * ingest result (the reconstructed message, or `null` if it was not for this
     * node / already ingested).
     * @param {string} uri
     * @returns {Promise<import("@reticulum/lxmf").LXMessage | null>}
     */
    ingestPaperUri(uri: string): Promise<import("@reticulum/lxmf").LXMessage | null>;
}
