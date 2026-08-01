/**
 * Namespace Label Privacy (Dacar spec §3.3).
 *
 * To prevent label disclosure over public transports, Dacar never transmits or
 * stores Object or Relation strings in plaintext. Every string label is hashed
 * with **HMAC-SHA256**, keyed with the node's Privacy Salt, and strictly
 * truncated to the first 16 bytes.
 *
 * Objects are split by `:` into segments, each hashed individually. The
 * terminal suffix wildcard `*` is stripped *before* hashing and carried as a
 * boolean flag on the Tuple (§3.3).
 *
 * > WARNING (§3.3): an unset Privacy Salt defaults to 32 null bytes, which is
 * > *fail-open on privacy* — the hashes become trivially dictionary-attackable.
 *
 * Hashing uses the Web Crypto `HMAC`/`SHA-256` primitives, so all methods are
 * asynchronous and runtime-portable (browsers, Node, Deno, Bun).
 */

export const DELIMITER = ":";
export const WILDCARD = "*";

/** Privacy Salts are 32 bytes of cryptographically secure random data. */
export const SALT_SIZE = 32;
/** All label hashes (and RNS.Identity hashes) are 16 bytes. */
export const HASH_SIZE = 16;
/** The fail-open default salt when none is configured (§3.3 WARNING). */
export const DEFAULT_SALT = new Uint8Array(SALT_SIZE);
/** Maximum number of concurrently-configured Legacy Salts (§10.2). */
export const MAX_LEGACY_SALTS = 2;

/** Domain-separation tag used to derive a salt's identifying `id_tag` (§8.3). */
const SALT_ID_TAG = new TextEncoder().encode("dacar.salt.id");

const encoder = new TextEncoder();

/**
 * Split an object string into its colon-delimited segments.
 * @param {string} objectId
 * @returns {string[]}
 */
export function split(objectId) {
  return objectId.split(DELIMITER);
}

/**
 * Return `{ segments, wildcard }` for an object string.
 *
 * The terminal `*` is stripped and reported via the wildcard flag:
 *   - `"*"`          -> `{ segments: [], wildcard: true }`   (root wildcard)
 *   - `"sensor:*"`   -> `{ segments: ["sensor"], wildcard: true }`
 *   - `"sensor:wind"`-> `{ segments: ["sensor","wind"], wildcard: false }`
 *
 * A non-terminal `*` is treated as a literal segment.
 * @param {string} objectId
 * @returns {{ segments: string[], wildcard: boolean }}
 */
export function parseObject(objectId) {
  if (objectId === WILDCARD) return { segments: [], wildcard: true };
  const segments = split(objectId);
  let wildcard = false;
  if (segments.length > 0 && segments[segments.length - 1] === WILDCARD) {
    wildcard = true;
    segments.pop();
  }
  return { segments, wildcard };
}

/**
 * Truncate a 32-byte HMAC-SHA256 digest to the first 16 bytes (§3.3).
 * @param {Uint8Array} digest
 * @returns {Uint8Array}
 */
function truncate16(digest) {
  return digest.slice(0, HASH_SIZE);
}

export class NamespaceHasher {
  /**
   * @param {Uint8Array} [salt] 32-byte Privacy Salt (defaults to fail-open nulls).
   */
  constructor(salt = DEFAULT_SALT) {
    if (!(salt instanceof Uint8Array) || salt.length !== SALT_SIZE) {
      throw new RangeError(`salt must be ${SALT_SIZE} bytes`);
    }
    /** @readonly @type {Uint8Array} */
    this.salt = salt;
    /** Lazily-imported HMAC CryptoKey, shared across all sign calls. */
    this._keyPromise = null;
  }

  /** @returns {Promise<CryptoKey>} */
  _key() {
    if (!this._keyPromise) {
      this._keyPromise = crypto.subtle.importKey(
        "raw",
        this.salt,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
    }
    return this._keyPromise;
  }

  /**
   * HMAC-SHA256(salt, relation) truncated to 16 bytes (§3.3).
   * @param {string} relation
   * @returns {Promise<Uint8Array>}
   */
  async hashRelation(relation) {
    const key = await this._key();
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(relation)));
    return truncate16(mac);
  }

  /**
   * Return `{ hashes, wildcard }` for an object string (§3.3).
   * @param {string} objectId
   * @returns {Promise<{ hashes: Uint8Array[], wildcard: boolean }>}
   */
  async hashObject(objectId) {
    const { segments, wildcard } = parseObject(objectId);
    const key = await this._key();
    const hashes = await Promise.all(
      segments.map(async (seg) => {
        const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(seg)));
        return truncate16(mac);
      }),
    );
    return { hashes, wildcard };
  }

  /**
   * A 16-byte tag identifying this salt (§8.3 `salt_id_tag`):
   * `HMAC-SHA256(salt, b"dacar.salt.id")` truncated to 16 bytes.
   * @returns {Promise<Uint8Array>}
   */
  async idTag() {
    const key = await this._key();
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, SALT_ID_TAG));
    return truncate16(mac);
  }
}

/**
 * Does a Tuple's hashed Object cover a request's exact hashed Object? (§3.3)
 *
 * A match succeeds if the Tuple is wildcarded and its hashes are a *prefix* of
 * the request hashes, or if the two hash arrays are identical.
 * @param {Uint8Array[]} tupleHashes
 * @param {boolean} wildcard
 * @param {Uint8Array[]} requestHashes
 * @returns {boolean}
 */
export function covers(tupleHashes, wildcard, requestHashes) {
  if (wildcard) {
    if (tupleHashes.length > requestHashes.length) return false;
    for (let i = 0; i < tupleHashes.length; i++) {
      if (!bytesEqual(tupleHashes[i], requestHashes[i])) return false;
    }
    return true;
  }
  if (tupleHashes.length !== requestHashes.length) return false;
  for (let i = 0; i < tupleHashes.length; i++) {
    if (!bytesEqual(tupleHashes[i], requestHashes[i])) return false;
  }
  return true;
}

/**
 * Constant-time-ish byte comparison.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
