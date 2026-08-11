/**
 * DacarStore: persistent node store over a `StorageAdapter` (work doc #6).
 *
 * Backend-neutral: built on `@reticulum/core`'s `StorageAdapter` KV contract
 * (`get`/`set`/`delete`/`keys`, namespaced). The on-disk **record bytes are
 * byte-for-byte identical to the canonical Python `Store`** (work doc #9), so a
 * store directory written by one CLI is readable — and writable — by the other:
 *
 *   - `config`            — INI (`configparser` layout: `[salt]`/`[trust]`/
 *                            `[policy]`/`[rfed]`, `key = value`, `legacy{i}`).
 *   - `clock.msgpack`     — msgpack `{ last_ms, logical }` (snake_case).
 *   - `state.msgpack`     — `StateVector.toPayload()` (the CRDT, trusted-local).
 *   - `aliases`           — rnns text `hash name [# note]` (NOT msgpack).
 *   - `ledger.msgpack`    — msgpack `{ tuple_hash_hex: { object, relation,
 *                            wildcard, first_seen } }` (snake_case; the tuple
 *                            hash key is `sha256(preimage).hex()`).
 *   - `identities.msgpack`— msgpack `{ hash_hex: 32-byte Ed25519 pub }` (the
 *                            Ed25519 half of the 64-byte RNS pub key).
 *   - `outbox.msgpack`    — msgpack `[payload_bytes, ...]` of locally-issued,
 *                            not-yet-published signed Deltas (doc #8).
 *
 * Record names are the exact Python filenames (with `.msgpack` where Python
 * uses it); a Node `DacarFileAdapter` (`./fileStore.js`) writes them as loose
 * files in the store root with Python-matching modes. `MemoryStorageAdapter`
 * (tests) just stores the same bytes keyed by name.
 *
 * The node's own signing **identity private key** is the ONE intentional
 * divergence: it stays library-native (Python RNS → 64-byte priv-only
 * `identity`; `@reticulum/core` → 128-byte priv+pub `identity.key` via
 * `adapter.loadKey`/`saveKey`). The two files coexist under different names; a
 * store carries the identity of whichever CLI initialized it.
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
import { Keyring } from "../verifier.js";

/** The alias that always names the node's own signing identity. */
export const SELF_ALIAS = "self";

/** Ed25519 public keys are 32 raw bytes (the verify half of a 64-byte RNS key). */
const ED25519_PUB_SIZE = 32;

const NS = "dacar";

// Record names mirror the canonical Python `Store` filenames exactly.
const CONFIG_RECORD = "config";
const CLOCK_RECORD = "clock.msgpack";
const STATE_RECORD = "state.msgpack";
const ALIASES_RECORD = "aliases";
const LEDGER_RECORD = "ledger.msgpack";
const IDENTITIES_RECORD = "identities.msgpack";
const OUTBOX_RECORD = "outbox.msgpack";

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
 * @typedef {Object} LedgerRow
 * @property {string | null} [object]
 * @property {string | null} [relation]
 * @property {boolean | null} [wildcard]
 * @property {number} [firstSeen]
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
   *
   * Produces the same file set as Python `Store.init`: `config` (INI),
   * `state.msgpack`, `clock.msgpack`, `ledger.msgpack`, `aliases` (with the
   * `self` alias). `identities.msgpack` / `outbox.msgpack` are NOT pre-written
   * (Python creates them lazily on first save).
   * @param {import("@reticulum/core").StorageAdapter} adapter
   * @param {Object} [opts]
   * @param {Uint8Array} [opts.salt] 32-byte Privacy Salt (default: random).
   * @param {number} [opts.horizonDays]
   * @param {Uint8Array} [opts.identityBytes] 128-byte private-key blob to adopt.
   * @returns {Promise<DacarStore>}
   */
  static async init(adapter, opts = {}) {
    const store = new DacarStore(adapter, opts);
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
    return store;
  }

  /** @returns {Promise<boolean>} */
  async exists() {
    return (await this._adapter.get(NS, CONFIG_RECORD)) !== null;
  }

  /** @returns {Promise<StoreConfig>} */
  async loadConfig() {
    const bytes = await this._adapter.get(NS, CONFIG_RECORD);
    if (!bytes) throw new Error("store not initialized (run `dacar init`)");
    return _decodeConfigIni(bytes);
  }

  /** @param {StoreConfig} config */
  async saveConfig(config) {
    await this._adapter.set(NS, CONFIG_RECORD, _encodeConfigIni(config));
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
    const bytes = await this._adapter.get(NS, CLOCK_RECORD);
    if (bytes) {
      const obj = MsgPack.decode(bytes);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        // snake_case on disk (Python parity); Clock API is camelCase.
        const lastMs = obj.last_ms ?? obj.lastMs;
        const logical = obj.logical;
        if (typeof lastMs === "number" && typeof logical === "number") {
          clock.restore({ lastMs, logical });
        }
      }
    }
    return clock;
  }

  /** @param {Clock} clock */
  async saveClock(clock) {
    await this._adapter.set(
      NS,
      CLOCK_RECORD,
      MsgPack.encode({ last_ms: clock.lastMs, logical: clock.logical }),
    );
  }

  // -- state (CRDT) --------------------------------------------------------

  /** @param {Config} [config] @returns {Promise<StateVector>} */
  async loadState(config) {
    const horizon = config?.deletionHorizonDays ?? (await this.loadConfig()).horizonDays;
    const bytes = await this._adapter.get(NS, STATE_RECORD);
    if (bytes && bytes.length) {
      // `trusted: true` — these are this node's own persisted CRDT snapshot
      // (written by `saveState()` → `toPayload()`), never network bytes.
      // Network Operations arrive as signed Deltas through `DeltaReceiver`
      // (the verify-on-ingest path), not here.
      return StateVector.fromPayload(bytes, {
        deletionHorizonDays: horizon,
        trusted: true,
      });
    }
    return new StateVector({ deletionHorizonDays: horizon });
  }

  /** @param {StateVector} state */
  async saveState(state) {
    await this._adapter.set(NS, STATE_RECORD, state.toPayload());
  }

  // -- aliases -------------------------------------------------------------

  /** @returns {Promise<AliasRegistry>} */
  async loadAliases() {
    const bytes = await this._adapter.get(NS, ALIASES_RECORD);
    if (!bytes) return new AliasRegistry();
    return AliasRegistry.decode(bytes);
  }

  /** @param {AliasRegistry} aliases */
  async saveAliases(aliases) {
    await this._adapter.set(NS, ALIASES_RECORD, aliases.encode());
  }

  // -- ledger --------------------------------------------------------------

  /**
   * Plaintext ledger: `Map<tuple_hash_hex, row>`. The on-disk key is
   * `sha256(preimage).hex()` (Python `Tuple.key`); callers MUST set/lookup with
   * that key (e.g. `toHex(await tuple.hash())`) for cross-CLI parity.
   * @returns {Promise<Map<string, LedgerRow>>}
   */
  async loadLedger() {
    const bytes = await this._adapter.get(NS, LEDGER_RECORD);
    /** @type {Map<string, LedgerRow>} */
    const ledger = new Map();
    if (bytes) {
      const obj = MsgPack.decode(bytes);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        for (const [k, v] of Object.entries(obj)) {
          ledger.set(k, _decodeLedgerRow(v));
        }
      }
    }
    return ledger;
  }

  /** @param {Map<string, LedgerRow>} ledger */
  async saveLedger(ledger) {
    const obj = {};
    for (const [k, row] of ledger) obj[k] = _encodeLedgerRow(row);
    await this._adapter.set(NS, LEDGER_RECORD, MsgPack.encode(obj));
  }

  // -- issuer identity cache (work doc #5) ---------------------------------

  /**
   * Load the persisted issuer identity cache. Returns an empty {@link Keyring}
   * if no cache record exists yet.
   *
   * On disk each value is the 32-byte Ed25519 public key (Python canonical);
   * it is padded back to a 64-byte RNS public key (zeros ‖ Ed25519) for the
   * in-memory `IssuerKeyset`, whose verify path only uses the Ed25519 half.
   * @returns {Promise<Keyring>}
   */
  async loadKeyring() {
    const keyring = new Keyring();
    const bytes = await this._adapter.get(NS, IDENTITIES_RECORD);
    if (bytes) {
      const obj = MsgPack.decode(bytes);
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        for (const [hashHex, pubKey] of Object.entries(obj)) {
          if (!(pubKey instanceof Uint8Array) || pubKey.length !== ED25519_PUB_SIZE) {
            continue; // skip malformed (wrong-length) entries
          }
          try {
            keyring.registerSingle(_hexToBytes(hashHex), _padToRnsPub(pubKey));
          } catch {
            // skip malformed hash
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
        // Store the 32-byte Ed25519 half (last 32 bytes of the 64-byte RNS key).
        obj[hashHex] = keyset.memberPublicKeys[0].slice(32, 64);
      }
    }
    await this._adapter.set(NS, IDENTITIES_RECORD, MsgPack.encode(obj));
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

  // -- outbox (work doc #8) -----------------------------------------------

  /**
   * Load the outbox of locally-issued, not-yet-published signed Delta
   * payloads, in the order they were issued. Returns an empty array when no
   * outbox record exists yet.
   * @returns {Promise<Uint8Array[]>}
   */
  async loadOutbox() {
    const bytes = await this._adapter.get(NS, OUTBOX_RECORD);
    if (!bytes) return [];
    let obj;
    try {
      obj = MsgPack.decode(bytes);
    } catch {
      return []; // corrupted -> treat as empty (do not crash the CLI)
    }
    if (!Array.isArray(obj)) return [];
    return obj.filter((p) => p instanceof Uint8Array).map((p) => new Uint8Array(p));
  }

  /**
   * Persist the outbox as a MessagePack array of signed Delta payloads.
   * @param {Uint8Array[]} payloads
   */
  async saveOutbox(payloads) {
    await this._adapter.set(
      NS,
      OUTBOX_RECORD,
      MsgPack.encode(payloads.map((p) => new Uint8Array(p))),
    );
  }
}

/**
 * In-memory alias registry: `hash → names[]` with an optional note. Mirrors
 * Python's `AliasRegistry` (rnns `hash name [# note]`); `encode()`/`decode()`
 * produce the exact rnns text bytes Python does.
 */
export class AliasRegistry {
  /** @param {AliasEntry[]} [entries] */
  constructor(entries = []) {
    /** @type {AliasEntry[]} */ this.entries = entries;
  }

  /**
   * Parse rnns `hash name [# note]` lines (mirrors Python `AliasRegistry.parse`).
   * Blank lines and lines whose first token is not a 32-hex hash are skipped.
   * @param {Uint8Array} bytes
   * @returns {AliasRegistry}
   */
  static decode(bytes) {
    const registry = new AliasRegistry();
    const text = new TextDecoder().decode(bytes);
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      let head = line;
      let note = null;
      const hashIdx = line.indexOf("#");
      if (hashIdx !== -1) {
        head = line.slice(0, hashIdx);
        note = line.slice(hashIdx + 1).trim() || null;
      }
      const tokens = head.trim().split(/\s+/).filter(Boolean);
      if (tokens.length === 0) continue;
      const hashHex = tokens[0];
      const names = tokens.slice(1);
      if (hashHex.length !== HASH_SIZE * 2) continue;
      let hashBytes;
      try {
        hashBytes = _hexToBytes(hashHex);
      } catch {
        continue;
      }
      if (hashBytes.length !== HASH_SIZE) continue;
      if (names.length === 0) continue;
      const existing = registry._entryFor(hashBytes);
      if (existing) {
        for (const n of names) {
          if (!existing.names.includes(n)) existing.names.push(n);
        }
        if (note !== null) existing.note = note;
      } else {
        registry.entries.push({ hash: hashBytes, names: [...names], note });
      }
    }
    return registry;
  }

  /** @returns {Uint8Array} rnns text bytes (`hash name [# note]` per line). */
  encode() {
    if (this.entries.length === 0) return new Uint8Array(0);
    const lines = [];
    for (const e of this.entries) {
      const hashHex = toHex(e.hash);
      let field = e.names.length ? `${hashHex} ${e.names.join(" ")}` : hashHex;
      if (e.note) field += `  # ${e.note}`;
      lines.push(field);
    }
    return new TextEncoder().encode(lines.join("\n") + "\n");
  }

  /** @param {Uint8Array} hash @returns {AliasEntry | undefined} */
  _entryFor(hash) {
    return this.entries.find((e) => _bytesEqual(e.hash, hash));
  }

  /**
   * @param {string} name
   * @param {Uint8Array} hash
   * @param {string} [note]
   */
  add(name, hash, note) {
    const existing = this._entryFor(hash);
    if (existing) {
      if (!existing.names.includes(name)) existing.names.push(name);
      if (note != null) existing.note = note;
    } else {
      this.entries.push({ hash, names: [name], note: note ?? null });
    }
  }

  /**
   * Point the `self` alias at `hash` (replacing any prior), mirroring Python
   * `set_self`: strip `SELF_ALIAS` from every entry, prune now-empty entries,
   * then add `SELF_ALIAS` to the new hash.
   * @param {Uint8Array} hash
   */
  setSelf(hash) {
    for (const e of this.entries) {
      e.names = e.names.filter((n) => n !== SELF_ALIAS);
    }
    this.entries = this.entries.filter((e) => e.names.length > 0);
    this.add(SELF_ALIAS, hash);
  }

  /**
   * Remove `name` from its entry (mirrors Python `remove`). Returns `true` if
   * the name existed; the entry is dropped when it has no names left.
   * @param {string} name
   * @returns {boolean}
   */
  remove(name) {
    for (const e of this.entries) {
      const idx = e.names.indexOf(name);
      if (idx !== -1) {
        e.names.splice(idx, 1);
        if (e.names.length === 0) {
          this.entries = this.entries.filter((en) => en !== e);
        }
        return true;
      }
    }
    return false;
  }

  /** @param {string} name @returns {Uint8Array | undefined} */
  resolve(name) {
    const e = this.entries.find((en) => en.names.includes(name));
    return e?.hash;
  }

  /** @param {Uint8Array} hash @returns {string[]} */
  namesFor(hash) {
    return this._entryFor(hash)?.names ?? [];
  }

  /** @param {Uint8Array} hash @returns {string | null} */
  primaryName(hash) {
    const names = this.namesFor(hash);
    return names.length > 0 ? names[0] : null;
  }
}

// =========================================================================
// Helpers — record encode/decode (Python-canonical bytes) + small utilities
// =========================================================================

/**
 * Encode a {@link StoreConfig} as the INI text `configparser` would write
 * (sections `[salt]`/`[trust]`/`[policy]`/`[rfed]`, `key = value`, a blank
 * line after each section, trailing blank line). Byte-identical to Python's
 * `Store.save_config` output.
 * @param {StoreConfig} config
 * @returns {Uint8Array}
 */
function _encodeConfigIni(config) {
  let out = "";
  out += "[salt]\n";
  out += `primary = ${toHex(config.primarySalt)}\n`;
  for (let i = 0; i < config.legacySalts.length && i < MAX_LEGACY_SALTS; i++) {
    out += `legacy${i} = ${toHex(config.legacySalts[i])}\n`;
  }
  out += "\n";
  out += "[trust]\n";
  out += `anchors = ${config.anchors.map(toHex).join(", ")}\n`;
  if (config.authoritative) out += `authoritative = ${toHex(config.authoritative)}\n`;
  out += "\n";
  out += "[policy]\n";
  out += `deletion_horizon_days = ${config.horizonDays}\n`;
  out += "\n";
  out += "[rfed]\n";
  out += `topic = ${config.rfedTopic}\n`;
  if (config.rfedNode) out += `node = ${toHex(config.rfedNode)}\n`;
  out += "\n";
  return new TextEncoder().encode(out);
}

/**
 * Decode an INI `config` blob (as written by Python `configparser`) into a
 * {@link StoreConfig}. Mirrors Python `Store.load_config_raw`: option keys are
 * case-insensitive (configparser lowercases them); missing fields fall back to
 * defaults; optional sections (`authoritative`, `node`, `legacy{i}`) are
 * omitted when absent.
 * @param {Uint8Array} bytes
 * @returns {StoreConfig}
 */
function _decodeConfigIni(bytes) {
  const sections = _parseIni(bytes);
  const salt = sections.get("salt") ?? new Map();
  const primaryHex = salt.get("primary") ?? toHex(DEFAULT_SALT);
  const primarySalt = _expectHex("primary", primaryHex, SALT_SIZE);
  const legacySalts = [];
  for (let i = 0; i < MAX_LEGACY_SALTS; i++) {
    const v = salt.get(`legacy${i}`);
    if (v) legacySalts.push(_expectHex(`legacy${i}`, v, SALT_SIZE));
  }
  const trust = sections.get("trust") ?? new Map();
  const anchorsRaw = trust.get("anchors") ?? "";
  const anchors = anchorsRaw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((h, i) => _expectHex(`anchors[${i}]`, h, HASH_SIZE));
  const authoritative = trust.has("authoritative")
    ? _expectHex("authoritative", trust.get("authoritative"), HASH_SIZE)
    : null;
  const policy = sections.get("policy") ?? new Map();
  const horizonDays = parseInt(policy.get("deletion_horizon_days") ?? String(DEFAULT_DELETION_HORIZON_DAYS), 10);
  const rfed = sections.get("rfed") ?? new Map();
  const rfedTopic = rfed.get("topic") ?? RFED_TOPIC;
  const rfedNode = rfed.has("node") ? _expectHex("node", rfed.get("node"), HASH_SIZE) : null;
  return { primarySalt, legacySalts, anchors, authoritative, horizonDays, rfedTopic, rfedNode };
}

/**
 * Minimal INI parser compatible with Python `configparser` output: sections in
 * `[brackets]`, `key = value` (or `key: value`) lines, `#`/`;` comments and
 * blank lines ignored. Option keys are lowercased (configparser `optionxform`).
 * @param {Uint8Array} bytes
 * @returns {Map<string, Map<string, string>>}
 */
function _parseIni(bytes) {
  const text = new TextDecoder().decode(bytes);
  /** @type {Map<string, Map<string, string>>} */
  const sections = new Map();
  let cur = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = line.match(/^\[(.+)\]$/);
    if (sec) {
      cur = sec[1];
      sections.set(cur, new Map());
      continue;
    }
    if (!cur) continue;
    const idx = line.search(/[=:]/);
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    sections.get(cur).set(key, val);
  }
  return sections;
}

/**
 * @param {string} name
 * @param {string} hex
 * @param {number} len
 * @returns {Uint8Array}
 */
function _expectHex(name, hex, len) {
  const bytes = _hexToBytes(hex);
  if (bytes.length !== len) {
    throw new Error(`${name} must be ${len} bytes (${len * 2} hex), got ${bytes.length}`);
  }
  return bytes;
}

/**
 * @param {unknown} v
 * @returns {LedgerRow}
 */
function _decodeLedgerRow(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) {
    return { object: null, relation: null, wildcard: null, firstSeen: 0 };
  }
  const o = /** @type {Record<string, unknown>} */ (v);
  return {
    object: _optStr(o.object),
    relation: _optStr(o.relation),
    wildcard: _optBool(o.wildcard),
    firstSeen: typeof o.first_seen === "number" ? o.first_seen : 0,
  };
}

/**
 * @param {LedgerRow} row
 * @returns {Record<string, unknown>}
 */
function _encodeLedgerRow(row) {
  return {
    object: row.object ?? null,
    relation: row.relation ?? null,
    wildcard: row.wildcard ?? null,
    first_seen: row.firstSeen ?? 0,
  };
}

/** @param {unknown} v @returns {string | null} */
function _optStr(v) {
  return typeof v === "string" ? v : null;
}

/** @param {unknown} v @returns {boolean | null} */
function _optBool(v) {
  return typeof v === "boolean" ? v : null;
}

/**
 * Pad a 32-byte Ed25519 public key to a 64-byte RNS public key
 * (`X25519(pub=zeros) ‖ Ed25519(pub)`). The verifier's `IssuerKeyset` holds
 * 64-byte RNS keys; the X25519 half is unused for signature verification.
 * @param {Uint8Array} ed25519Pub
 * @returns {Uint8Array}
 */
function _padToRnsPub(ed25519Pub) {
  const padded = new Uint8Array(64);
  padded.set(ed25519Pub, 32);
  return padded;
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function _bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Parse a hex string (with or without `0x`) into bytes. Lower/upper-case
 * tolerant; matches Python's `bytes.fromhex`.
 * @param {string} hex
 * @returns {Uint8Array}
 */
function _hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`invalid hex string (length ${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * @param {number} len
 * @returns {Uint8Array}
 */
function _randomBytes(len) {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}
