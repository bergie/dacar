/**
 * `DacarFileAdapter` — a `StorageAdapter` that writes the **canonical Python
 * `Store` loose-file layout** for the `dacar` namespace (work doc #9), while
 * delegating everything else (the node signing identity, RNS ratchets, and any
 * non-dacar namespace) to `@reticulum/node`'s `FileStorageAdapter`.
 *
 * Why a separate adapter? `@reticulum/core`'s `FileStorageAdapter` lays records
 * out as `<dir>/<namespace>/<key>.bin` (the KV contract the browser/test
 * `MemoryStorageAdapter` also models). Python's canonical `Store` instead
 * writes **loose files** at the store root — `config`, `clock.msgpack`,
 * `state.msgpack`, `aliases`, `ledger.msgpack`, `identities.msgpack`,
 * `outbox.msgpack` — with per-file modes (0600 secret / 0644 public). For the
 * JS and Python CLIs to share one store directory byte-for-byte, JS must write
 * the same filenames at the same paths with the same modes.
 *
 * The record *names* (the `key` passed to `get`/`set`) are the exact Python
 * filenames (set in `src/cli/store.js`); this adapter simply writes them at
 * `<dir>/<key>` with the matching mode, and lists them back via `keys`.
 *
 * The node's own signing **identity private key** stays library-native:
 * `FileStorageAdapter` writes/reads `<dir>/identity.key` (128-byte priv+pub),
 * which coexists with — and is distinct from — Python's 64-byte `<dir>/identity`.
 * A store therefore carries the identity of whichever CLI initialized it.
 *
 * Node-only (imports `node:fs` + `@reticulum/node`); the portable record
 * encode/decode lives in `src/cli/store.js` (browser-safe, no `fs`).
 */

import { existsSync } from "node:fs";
import { chmod, mkdir, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { FileStorageAdapter } from "@reticulum/node";

/** Namespace the `DacarStore` writes its records under. */
const DACAR_NS = "dacar";

/** Directory mode (Python `Store._DIR_MODE`). */
const DIR_MODE = 0o700;

/**
 * Per-record file modes, mirroring the canonical Python `Store`:
 *   - secret records (config, state, ledger, identities, outbox): 0600
 *   - public records (clock, aliases): 0644
 * Unknown dacar records default to 0600 (fail-closed).
 */
const FILE_MODES = {
  config: 0o600,
  "clock.msgpack": 0o644,
  "state.msgpack": 0o600,
  aliases: 0o644,
  "ledger.msgpack": 0o600,
  "identities.msgpack": 0o600,
  "outbox.msgpack": 0o600,
  "sent.msgpack": 0o600,
};

export class DacarFileAdapter {
  /**
   * @param {string} directory Absolute store directory (e.g. `~/.dacar`).
   */
  constructor(directory) {
    this.directory = directory;
    /** @type {import("@reticulum/node").FileStorageAdapter} */
    this._fallback = new FileStorageAdapter(directory);
    this._dirReady = false;
  }

  /**
   * Ensure the store directory exists with mode 0700 (Python `Store.init`
   * `os.chmod(path, DIR_MODE)`; umask-independent via explicit chmod).
   */
  async _ensureDir() {
    if (this._dirReady) return;
    await mkdir(this.directory, { recursive: true });
    await chmod(this.directory, DIR_MODE);
    this._dirReady = true;
  }

  /**
   * @param {string} namespace
   * @param {string} key
   * @returns {Promise<Uint8Array | null>}
   */
  async get(namespace, key) {
    if (namespace === DACAR_NS) {
      try {
        const buf = await readFile(join(this.directory, key));
        return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      } catch (e) {
        if (e.code === "ENOENT") return null;
        throw e;
      }
    }
    return this._fallback.get(namespace, key);
  }

  /**
   * @param {string} namespace
   * @param {string} key
   * @param {Uint8Array} value
   */
  async set(namespace, key, value) {
    if (namespace === DACAR_NS) {
      await this._ensureDir();
      const path = join(this.directory, key);
      await writeFile(path, value, { mode: 0o600 });
      // Force the exact mode (umask-independent), matching Python's os.chmod.
      await chmod(path, FILE_MODES[key] ?? 0o600);
      return;
    }
    return this._fallback.set(namespace, key, value);
  }

  /**
   * @param {string} namespace
   * @param {string} key
   */
  async delete(namespace, key) {
    if (namespace === DACAR_NS) {
      try {
        await unlink(join(this.directory, key));
      } catch (e) {
        if (e.code === "ENOENT") return;
        throw e;
      }
      return;
    }
    return this._fallback.delete(namespace, key);
  }

  /**
   * @param {string} namespace
   * @returns {Promise<string[]>}
   */
  async keys(namespace) {
    if (namespace === DACAR_NS) {
      if (!existsSync(this.directory)) return [];
      const entries = await readdir(this.directory);
      return entries.filter((f) => Object.prototype.hasOwnProperty.call(FILE_MODES, f));
    }
    return this._fallback.keys(namespace);
  }

  // -- identity + ratchets: delegate to FileStorageAdapter (library-native) -

  /** @param {Uint8Array} bytes */
  async saveKey(bytes) {
    return this._fallback.saveKey(bytes);
  }

  /** @returns {Promise<Uint8Array | null>} */
  async loadKey() {
    return this._fallback.loadKey();
  }

  /** @param {Uint8Array} hash @param {Uint8Array} bytes */
  async saveOwnedRatchets(hash, bytes) {
    return this._fallback.saveOwnedRatchets(hash, bytes);
  }

  /** @param {Uint8Array} hash @returns {Promise<Uint8Array | null>} */
  async loadOwnedRatchets(hash) {
    return this._fallback.loadOwnedRatchets(hash);
  }
}
