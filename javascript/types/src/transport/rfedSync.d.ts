/**
 * The minimal `RFedClient` surface this adapter relies on. The real client from
 * `@reticulum/rfed` satisfies it; tests inject a fake. The raw-publish API
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
 * @property {import("@reticulum/core").Identity} [senderIdentity]
 * @property {Uint8Array} [senderPub]
 * @property {Uint8Array} [channelHash]
 * @property {string} [channelName]
 */
/**
 * §11.1 RFed Delta broadcast + receive, routed through verify-on-ingest.
 */
export class RfedDeltaSync {
    /** Default RFed channel (deployment-overridable, spec §11.1). */
    static DEFAULT_TOPIC: string;
    /**
     * @param {Object} opts
     * @param {import("../delta.d.ts").DeltaReceiver | null} [opts.receiver]
     *   The shared DeltaReceiver (state + key resolver). May be omitted on a
     *   publish-only node (then `listen`/`pull` throw if called).
     * @param {RFedClientLike} opts.client A `@reticulum/rfed` `RFedClient`.
     * @param {import("@reticulum/core").Reticulum} [opts.rns] The Reticulum
     *   instance owning the identity recall store. When given, each received
     *   Delta's transport sender is remembered into it
     *   (`rns.transport.rememberIdentity`) so future RNS recalls succeed without
     *   an announce. Best-effort: reception works without it.
     * @param {string} [opts.topic] RFed channel name (default `dacar.policy.v1`).
     */
    constructor({ receiver, client, rns, topic }: {
        receiver?: import("../delta.d.ts").DeltaReceiver | null;
        client: RFedClientLike;
        rns?: import("@reticulum/core").Reticulum;
        topic?: string;
    });
    /** @type {import("../delta.d.ts").DeltaReceiver | null} */
    _receiver: import("../delta.d.ts").DeltaReceiver | null;
    /** @type {RFedClientLike} */
    _client: RFedClientLike;
    /** @type {import("@reticulum/core").Reticulum | null} */
    _rns: import("@reticulum/core").Reticulum | null;
    /** @type {string} */
    _topic: string;
    /** @returns {string} The configured RFed channel name. */
    get topic(): string;
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
    subscribe(nodeHash: Uint8Array): Promise<{
        ok: boolean;
        stampCost: number | null;
    }>;
    /**
     * Removes the subscription.
     * @param {Uint8Array} nodeHash
     * @returns {Promise<{ ok: boolean }>}
     */
    unsubscribe(nodeHash: Uint8Array): Promise<{
        ok: boolean;
    }>;
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
    publish(deltaPayload: Uint8Array, nodeHash: Uint8Array): Promise<boolean>;
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
    listen(): Promise<Uint8Array>;
    /**
     * Remembers a fanout/pull sender into the RNS identity recall store so
     * future RNS recalls succeed without needing an announce (best-effort —
     * failure never affects correctness, and it is skipped entirely when no
     * `rns` instance was given).
     *
     * The delta's issuer hash (field [0]) is inspected to confirm the payload
     * is a Dacar Delta before caching the transport sender's key under the
     * sender's identity hash.
     * @param {RfedDecodedRaw} decoded A decoded fanout delivery.
     * @returns {Promise<void>}
     */
    _rememberSender(decoded: RfedDecodedRaw): Promise<void>;
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
    pull(nodeHash: Uint8Array): Promise<number>;
}
/**
 * The minimal `RFedClient` surface this adapter relies on. The real client from
 * `@reticulum/rfed` satisfies it; tests inject a fake. The raw-publish API
 * (`subscribeRaw` / `publishRaw`) carries a self-authenticating payload in the
 * RTID prelude instead of an LXMF envelope (§11.1.1).
 */
export type RFedClientLike = {
    /**
     *   Subscribes and marks the channel raw so fanout is decoded via
     *   `unwrapRawChannelMessage` (not the LXMF path).
     */
    subscribeRaw: (nodeHash: Uint8Array, channelName: string) => Promise<{
        ok: boolean;
        stampCost: number | null;
    }>;
    unsubscribe?: (nodeHash: Uint8Array, channelName: string) => Promise<{
        ok: boolean;
    }>;
    /**
     *   Fire-and-forget SEND of a raw application payload (wrapped in the RTID
     *   prelude + EC-encrypted to the channel identity by the client).
     */
    publishRaw: (nodeHash: Uint8Array, channelName: string, payload: Uint8Array) => Promise<void>;
    pull: (nodeHash: Uint8Array, channelName: string) => Promise<{
        items: Array<{
            channelHash: Uint8Array;
            blob: Uint8Array;
        }>;
        morePending: boolean;
    }>;
    /**
     *   Delivers a decoded fanout object; channels subscribed via `subscribeRaw`
     *   carry `kind: "raw"` with a `payload` field (the unwrapped application
     *   bytes). The client performs the EC-decrypt + RTID-prelude unwrap.
     */
    listen: (onMessage: (decoded: RfedDecodedRaw) => void) => Promise<Uint8Array>;
};
/**
 * The shape of the decoded fanout callback argument from `RFedClient.listen` for
 * a raw channel. Only `kind` and `payload` are consumed here.
 */
export type RfedDecodedRaw = {
    kind: "raw" | "lxmf";
    /**
     * Raw application payload (`kind === "raw"`).
     */
    payload?: Uint8Array;
    senderIdentity?: import("@reticulum/core").Identity;
    senderPub?: Uint8Array;
    channelHash?: Uint8Array;
    channelName?: string;
};
