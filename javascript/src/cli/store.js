/**
 * DacarStore: persistent node store over a `StorageAdapter` (work doc #6).
 *
 * Backend-neutral: built on `@reticulum/core`'s `StorageAdapter` KV contract
 * (`get`/`set`/`delete`/`keys`, namespaced). Mirrors Python's `Store` fields
 * logically, but stores each as a namespaced KV record rather than an INI +
 * loose files — JS has no `0600`-mode INI convention, and the KV contract is
 * the idiomatic, portable choice (Node `FileStorageAdapter`, in-memory for
 * tests, IndexedDB for browsers).
 *
 * Records:
 *   - `config`      — msgpack `{ primarySalt, legacySalts[], anchors[],
 *                      authoritative?, horizonDays, rfedTopic, rfedNode? }`
 *   - `clock`       — msgpack `{ lastMs, logical }`
 *   - `state`       — `StateVector.toPayload()` (the CRDT, trusted-local)
 *   - `aliases`     — msgpack `[{ hash, names[], note? }]`
 *   - `ledger`      — msgpack `{ tupleHashHex: { object?, relation?, wildcard?, firstSeen } }`
 *   - `identities`  — msgpack `{ hashHex: pubKeyBytes }` (durable issuer cache, doc #5)
 *
 * Secret material (the node's own identity private key) uses the adapter's
 * dedicated `loadKey`/`saveKey` slot, matching `@reticulum/core`.
 */

import { MsgPack, Identity, toHex } from "@reticulum/core";
import { Config, DEFAULT_DELETION_HORIZON_DAYS } from "../config.js";
import { StateVector } from "../crdt.js";
import { Clock } from "../hlc.js";
import { RFED_TOPIC } from "../naming.js";
import {
  DEFAULT_SALT,
  HASH_SIZE,
  MAX_LEGACY_SALTS,
  SALT_SIZE,
} from "../namespace.js";
import { Keyring, IssuerKeyset } from "../verifier.js";

/** The alias that always names the node's own signing identity. */
export const SELF_ALIAS = "self";

/** The 64-byte RNS public key (X25519 ‖ Ed25519). */
const RNS_PUBLIC_KEY_SIZE = 64;

const NS = "dacar";

/**
 * @typedef {Object} StoreConfig
 * @property {Uint8Array} primarySalt
 * @property {Uint8Array[]} legacySalts
 * @property {Uint8Array[]} anchors
 * @property {Uint8Array | null} [authoritative]
 * @property {number} horizonDays
 * @property {string} rfedTopic
 * @property {Uint8Array | null} [rfedNode]
 */

/**
 * @typedef {Object} AliasEntry
 * @property {Uint8Array} hash
 * @property {string[]} names
 * @property {string | null} [note]
 */

/**
 * A dacar node store backed by a `StorageAdapter`. Each CLI invocation builds a
 * store, loads what it needs, mutates in memory, and writes back — the
 * offline-first, daemon-free model.
 */
export class DacarStore {
  /**
   * @param {import("@reticulum/core").StorageAdapter} adapter
   * @param {Object} [opts]
   * @param {Uint8Array | string} [opts.identityBytes] A 128-byte private-key blob
   *   overriding the store's own identity (mirrors Python's `--identity PATH`).
   */
  constructor(adapter, opts = {}) {
    this._adapter = adapter;
    this._identityOverride = opts.identityBytes ?? null;
  }

  // -- config --------------------------------------------------------------

  /**
   * Bootstrap a fresh node store (work doc #6 `init`).
   * @param {import("@reticulum/core").StorageAdapter} adapter
   * @param {Object} [opts]
   * @param {Uint8Array} [opts.salt] 32-byte Privacy Salt (default: random).
   * @param {number} [opts.horizonDays]
   * @param {Uint8Array} [opts.identityBytes] 128-byte private-key blob to adopt.
   * @returns {Promise<DacarStore>}
   */
  static async init(adapter, opts = {}) {
    const store = new DacarStore(adapter, opts);
    // Identity: adopt the override, else generate + persist via saveKey.
    let identity;
    if (opts.identityBytes) {
      identity = await Identity.fromBytes(opts.identityBytes);
      if (!identity) throw new Error("could not load identity from provided bytes");
      await adapter.saveKey(opts.identityBytes);
    } else {
      identity = await Identity.loadOrGenerate(adapter);
    }
    const salt = opts.salt ?? _randomBytes(SALT_SIZE);
    /** @type {StoreConfig} */
    const config = {
      primarySalt: salt,
      legacySalts: [],
      anchors: [identity.identityHash],
      authoritative: null,
      horizonDays: opts.horizonDays ?? DEFAULT_DELETION_HORIZON_DAYS,
      rfedTopic: RFED_TOPIC,
      rfedNode: null,
    };
    await store.saveConfig(config);
    await store.saveState(new StateVector({ deletionHorizonDays: config.horizonDays }));
    await store.saveClock(new Clock());
    await store.saveLedger(new Map());
    const aliases = new AliasRegistry();
    aliases.add(SELF_ALIAS, identity.identityHash);
    await store.saveAliases(aliases);
    await store.saveKeyring(new Keyring());
    return store;
  }

  /** @returns {Promise<boolean>} */
  async exists() {
    return (await this._adapter.get(NS, "config")) !== null;
  }

  /** @returns {Promise<StoreConfig>} */
  async loadConfig() {
    const bytes = await this._adapter.get(NS, "config");
    if (!bytes) throw new Error("store not initialized (run `dacar init`)");
    return _decodeConfig(bytes);
  }

  /** @param {StoreConfig} config */
  async saveConfig(config) {
    const obj = [
      config.primarySalt,
      config.legacySalts,
      config.anchors,
      config.authoritative ?? null,
      config.horizonDays,
      config.rfedTopic,
      config.rfedNode ?? null,
    ];
    await this._adapter.set(NS, "config", MsgPack.encode(obj));
  }

  /**
   * Build a validated {@link Config} from the stored config.
   * @returns {Promise<Config>}
   */
  async loadConfigValidated() {
    const raw = await this.loadConfig();
    return new Config({
      rootTrustAnchors: raw.anchors,
      primarySalt: raw.primarySalt,
      legacySalts: raw.legacySalts,
      authoritativeIdentity: raw.authoritative ?? undefined,
      deletionHorizonDays: raw.horizonDays,
    });
  }

  // -- identity ------------------------------------------------------------

  /** @returns {Promise<Identity | null>} */
  async loadIdentity() {
    if (this._identityOverride) {
      const bytes = typeof this._identityOverride === "string"
        ? _hexToBytes(this._identityOverride)
        : this._identityOverride;
      const id = await Identity.fromBytes(bytes);
      if (!id) throw new Error("could not load identity from override");
      return id;
    }
    const keyBytes = await this._adapter.loadKey();
    if (!keyBytes) return null;
    const id = await Identity.fromBytes(keyBytes);
    if (!id) throw new Error("could not load stored identity (corrupt?)");
    return id;
  }

  /** @returns {Promise<Uint8Array>} */
  async identityHash() {
    const id = await this.loadIdentity();
    if (!id) throw new Error("no signing identity (run `dacar init`)");
    return id.identityHash;
  }

  // -- clock (HLC) ---------------------------------------------------------

  /** @returns {Promise<Clock>} */
  async loadClock() {
    const clock = new Clock();
    const bytes = await this._adapter.get(NS, "clock");
    if (bytes) {
      const obj = MsgPack.decode(bytes);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        if (typeof obj.lastMs === "number" && typeof obj.logical === "number") {
          clock.restore(obj);
        }
      }
    }
    return clock;
  }

  /** @param {Clock} clock */
  async saveClock(clock) {
    await this._adapter.set(
      NS,
      "clock",
      MsgPack.encode(clock.snapshot()),
    );
  }

  // -- state (CRDT) --------------------------------------------------------

  /** @param {Config} [config] @returns {Promise<StateVector>} */
  async loadState(config) {
    const horizon = config?.deletionHorizonDays ?? (await this.loadConfig()).horizonDays;
    const bytes = await this._adapter.get(NS, "state");
    if (bytes && bytes.length) {
      return StateVector.fromPayload(bytes, { deletionHorizonDays: horizon });
    }
    return new StateVector({ deletionHorizonDays: horizon });
  }

  /** @param {StateVector} state */
  async saveState(state) {
    await this._adapter.set(NS, "state", state.toPayload());
  }

  // -- aliases -------------------------------------------------------------

  /** @returns {Promise<AliasRegistry>} */
  async loadAliases() {
    const bytes = await this._adapter.get(NS, "aliases");
    if (!bytes) return new AliasRegistry();
    return AliasRegistry.decode(bytes);
  }

  /** @param {AliasRegistry} aliases */
  async saveAliases(aliases) {
    await this._adapter.set(NS, "aliases", aliases.encode());
  }

  // -- ledger --------------------------------------------------------------

  /**
   * @returns {Promise<Map<string, { object?: string, relation?: string, wildcard?: boolean, firstSeen?: number }>>}
   */
  async loadLedger() {
    const bytes = await this._adapter.get(NS, "ledger");
    /** @type {Map<string, any>} */
    const ledger = new Map();
    if (bytes) {
      const obj = MsgPack.decode(bytes);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        for (const [k, v] of Object.entries(obj)) ledger.set(k, v);
      }
    }
    return ledger;
  }

  /** @param {Map<string, any>} ledger */
  async saveLedger(ledger) {
    const obj = Object.fromEntries(ledger);
    await this._adapter.set(NS, "ledger", MsgPack.encode(obj));
  }

  // -- issuer identity cache (work doc #5) ---------------------------------

  /**
   * Load the persisted issuer identity cache. Returns an empty {@link Keyring}
   * if no cache record exists yet.
   * @returns {Promise<Keyring>}
   */
  async loadKeyring() {
    const keyring = new Keyring();
    const bytes = await this._adapter.get(NS, "identities");
    if (bytes) {
      const obj = MsgPack.decode(bytes);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        for (const [hashHex, pubKey] of Object.entries(obj)) {
          if (pubKey instanceof Uint8Array && pubKey.length === RNS_PUBLIC_KEY_SIZE) {
            try {
              keyring.registerSingle(_hexToBytes(hashHex), pubKey);
            } catch {
              // skip malformed hash
            }
          }
        }
      }
    }
    return keyring;
  }

  /** @param {Keyring} keyring */
  async saveKeyring(keyring) {
    const obj = {};
    for (const [hashHex, keyset] of keyring.entries()) {
      if (keyset.threshold === 1 && keyset.memberPublicKeys.length === 1) {
        obj[hashHex] = keyset.memberPublicKeys[0];
      }
    }
    await this._adapter.set(NS, "identities", MsgPack.encode(obj));
  }

  /**
   * Build a verify-on-ingest keyring from the persisted cache + own identity.
   * @returns {Promise<Keyring>}
   */
  async keyringForVerify() {
    const keyring = await this.loadKeyring();
    const own = await this.loadIdentity();
    if (own) keyring.registerSingle(own.identityHash, await own.getPublicKey());
    return keyring;
  }
}

/**
 * In-memory alias registry: `hash → names[]` with an optional note. Mirrors
 * Python's `AliasRegistry` (rnns `hash name [# note]`).
 */
export class AliasRegistry {
  /** @param {AliasEntry[]} [entries] */
  constructor(entries = []) {
    /** @type {AliasEntry[]} */ this.entries = entries;
  }

  /** @param {Uint8Array} bytes @returns {AliasRegistry} */
  static decode(bytes) {
    const obj = MsgPack.decode(bytes);
    if (!Array.isArray(obj)) return new AliasRegistry();
    /** @type {AliasEntry[]} */
    const entries = [];
    for (const row of obj) {
      if (!Array.isArray(row)) continue;
      const [hash, names, note] = row;
      if (!(hash instanceof Uint8Array) || !Array.isArray(names)) continue;
      entries.push({ hash, names, note: note ?? null });
    }
    return new AliasRegistry(entries);
  }

  /** @returns {Uint8Array} */
  encode() {
    return MsgPack.encode(this.entries.map((e) => [e.hash, e.names, e.note ?? null]));
  }

  /** @param {string} name @returns {Uint8Array | null} */
  resolve(name) {
    for (const e of this.entries) {
      if (e.names.includes(name)) return e.hash;
    }
    return null;
  }

  /** @param {Uint8Array} hash @returns {string[]} */
  namesFor(hash) {
    for (const e of this.entries) {
      if (_bytesEqual(e.hash, hash)) return [...e.names];
    }
    return [];
  }

  /** @param {Uint8Array} hash @returns {string | null} */
  primaryName(hash) {
    const names = this.namesFor(hash);
    return names[0] ?? null;
  }

  /** @param {string} name @param {Uint8Array} hash @param {string | null} [note] */
  add(name, hash, note) {
    for (const e of this.entries) {
      if (_bytesEqual(e.hash, hash)) {
        if (!e.names.includes(name)) e.names.push(name);
        if (note !== undefined) e.note = note;
        return;
      }
    }
    this.entries.push({ hash, names: [name], note: note ?? null });
  }

  /** @param {Uint8Array} hash */
  setSelf(hash) {
    for (const e of this.entries) {
      const i = e.names.indexOf(SELF_ALIAS);
      if (i !== -1) e.names.splice(i, 1);
    }
    this.entries = this.entries.filter((e) => e.names.length > 0);
    this.add(SELF_ALIAS, hash);
  }
}

// -- decode helpers ---------------------------------------------------------

/**
 * @param {Uint8Array} bytes
 * @returns {StoreConfig}
 */
function _decodeConfig(bytes) {
  const arr = MsgPack.decode(bytes);
  if (!Array.isArray(arr) || arr.length !== 7) {
    throw new Error("config record must be a 7-element MessagePack array");
  }
  const [primarySalt, legacySalts, anchors, authoritative, horizonDays, rfedTopic, rfedNode] = arr;
  return {
    primarySalt: _expectBytes(primarySalt, SALT_SIZE, "primary_salt"),
    legacySalts: legacySalts.map((s) => _expectBytes(s, SALT_SIZE, "legacy_salt")),
    anchors: anchors.map((a) => _expectBytes(a, HASH_SIZE, "anchor")),
    authoritative: authoritative instanceof Uint8Array ? authoritative : null,
    horizonDays: Number(horizonDays),
    rfedTopic: String(rfedTopic),
    rfedNode: rfedNode instanceof Uint8Array ? rfedNode : null,
  };
}

/**
 * @param {unknown} value
 * @param {number} len
 * @param {string} name
 * @returns {Uint8Array}
 */
function _expectBytes(value, len, name) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`${name} must be a ${len}-byte Uint8Array`);
  }
  return value;
}

/** @param {Uint8Array} a @param {Uint8Array} b @returns {boolean} */
function _bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** @param {string} hex @returns {Uint8Array} */
function _hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** @param {number} n @returns {Uint8Array} */
function _randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
