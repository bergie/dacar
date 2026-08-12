/**
 * Signed authorization Operations / Deltas (Dacar spec §5.2, §5.3).
 *
 * An Operation is a cryptographically signed instruction to Grant (Add) or
 * Revoke (Remove) a Tuple. Ed25519 signing/verification is delegated to the
 * `Identity` from `@reticulum/core` (Web Crypto), and transport serialization
 * uses its MessagePack implementation.
 *
 * Single-identity issuers carry exactly one signature; Threshold Group issuers
 * carry exactly `N` signatures from distinct members (§5.2).
 */

import { Identity, MsgPack, toHex } from "@reticulum/core";
import { MAX_HLC } from "./hlc.js";
import { Tuple } from "./tuple.js";

/** Ed25519 signatures are always 64 bytes. */
export const SIGNATURE_SIZE = 64;
/** HLC timestamps travel as 64-bit big-endian unsigned integers. */
export const HLC_BYTES = 8;

/**
 * The effect of an Operation on the CRDT.
 * @readonly
 * @enum {number}
 */
export const Action = {
  REVOKE: 0x00,
  GRANT: 0x01,
};

/**
 * @typedef {Object} OperationInit
 * @property {Tuple} tuple
 * @property {number} action One of {@link Action}.
 * @property {bigint} hlc
 * @property {Uint8Array[]} [signatures] 64-byte signatures (empty if unsigned).
 */

export class Operation {
  /** @param {OperationInit} init */
  constructor({ tuple, action, hlc, signatures = [] }) {
    if (action !== Action.GRANT && action !== Action.REVOKE) {
      throw new TypeError("action must be Action.GRANT or Action.REVOKE");
    }
    if (typeof hlc !== "bigint" || hlc < 0n || hlc > MAX_HLC) {
      throw new RangeError("hlc must be a bigint in [0, 2^64)");
    }
    if (!Array.isArray(signatures)) {
      throw new TypeError("signatures must be an array");
    }
    for (const sig of signatures) {
      if (!(sig instanceof Uint8Array) || sig.length !== SIGNATURE_SIZE) {
        throw new RangeError(`each signature must be ${SIGNATURE_SIZE} bytes`);
      }
    }
    this.tuple = tuple;
    this.action = action;
    this.hlc = hlc;
    /** @type {Uint8Array[]} */
    this.signatures = Object.freeze([...signatures]);
  }

  get issuer() {
    return this.tuple.issuer;
  }
  get grantee() {
    return this.tuple.grantee;
  }
  get relationHash() {
    return this.tuple.relationHash;
  }
  get objectHashes() {
    return this.tuple.objectHashes;
  }
  get wildcard() {
    return this.tuple.wildcard;
  }

  /** §5.2 signature pre-image. @returns {Uint8Array} */
  get preimage() {
    let len = 16 + 16 + 1 + HLC_BYTES + 16 + 1 + 1;
    for (const h of this.tuple.objectHashes) len += h.length;
    const out = new Uint8Array(len);
    let o = 0;
    out.set(this.tuple.issuer, o); o += 16;
    out.set(this.tuple.grantee, o); o += 16;
    out[o++] = this.action;
    new DataView(out.buffer).setBigUint64(o, this.hlc, false); // big-endian
    o += HLC_BYTES;
    out.set(this.tuple.relationHash, o); o += 16;
    out[o++] = this.tuple.wildcard ? 0x01 : 0x00;
    out[o++] = this.tuple.objectHashes.length;
    for (const h of this.tuple.objectHashes) {
      out.set(h, o);
      o += h.length;
    }
    return out;
  }

  /**
   * Return a copy signed with one or more `@reticulum/core` Identities holding
   * private keys. Each identity produces one signature, in argument order.
   * Pass one identity for a single-identity issuer, or `N` member identities for
   * a Threshold Group issuer (§5.2).
   * @param {...Identity} identities
   * @returns {Promise<Operation>}
   */
  async sign(...identities) {
    if (identities.length === 0) throw new Error("at least one signing identity is required");
    const preimage = this.preimage;
    const signatures = await Promise.all(identities.map((id) => id.sign(preimage)));
    return new Operation({ tuple: this.tuple, action: this.action, hlc: this.hlc, signatures });
  }

  /**
   * Coerce a public-key-like value into an `@reticulum/core` Identity.
   * @param {Identity | Uint8Array} value
   * @returns {Promise<Identity>}
   */
  static async _asIdentity(value) {
    return value instanceof Identity ? value : await Identity.fromPublicKey(value);
  }

  /**
   * Verify a single-identity Operation against one public key (§5.2).
   * @param {Identity | Uint8Array} identityOrPublicKey
   * @returns {Promise<boolean>}
   */
  async verify(identityOrPublicKey) {
    if (this.signatures.length !== 1) return false;
    return this.verifyThreshold([identityOrPublicKey], 1);
  }

  /**
   * Verify a Threshold Group Operation (§5.2, §4.1). Requires exactly
   * `threshold` signatures, each valid against a *distinct* member public key.
   * Duplicate signatures, or signatures verifying against the same public key
   * more than once, are rejected.
   * @param {(Identity | Uint8Array)[]} memberPublicKeys
   * @param {number} threshold
   * @returns {Promise<boolean>}
   */
  async verifyThreshold(memberPublicKeys, threshold) {
    if (!(Number.isInteger(threshold) && threshold >= 1) || this.signatures.length !== threshold) {
      return false;
    }
    if (memberPublicKeys.length < threshold) return false;
    const preimage = this.preimage;
    /** @type {{ id: Identity, key: Uint8Array }[]} */
    const members = [];
    for (const v of memberPublicKeys) {
      const id = await Operation._asIdentity(v);
      members.push({ id, key: await id.getPublicKey() });
    }
    const used = new Set(); // hex of used public keys
    for (const sig of this.signatures) {
      if (sig.length !== SIGNATURE_SIZE) return false;
      let matched = null;
      for (const m of members) {
        const hex = toHex(m.key);
        if (used.has(hex)) continue;
        if (await m.id.validate(sig, preimage)) {
          matched = hex;
          break;
        }
      }
      if (matched === null) return false;
      used.add(matched);
    }
    return used.size === threshold;
  }

  /**
   * Verify against a resolved `IssuerKeyset` (§11.2.4 bridge). A resolver maps
   * the Operation's 16-byte Issuer hash to a keyset; this confirms the
   * threshold signature against it.
   * @param {import("./verifier.js").IssuerKeyset} keyset
   * @returns {Promise<boolean>}
   */
  async verifyKeyset(keyset) {
    return this.verifyThreshold(keyset.memberPublicKeys, keyset.threshold);
  }

  /** §5.3 transport payload (the Operation must be signed first). @returns {Uint8Array} */
  toPayload() {
    if (this.signatures.length === 0) {
      throw new Error("Operation must be signed before payload serialization");
    }
    return MsgPack.encode([
      this.tuple.issuer,
      this.tuple.grantee,
      this.action,
      this.hlc,
      this.tuple.relationHash,
      [...this.tuple.objectHashes],
      this.tuple.wildcard,
      [...this.signatures],
    ]);
  }

  /**
   * Deserialize a §5.3 transport payload.
   * @param {Uint8Array} data
   * @returns {Operation}
   */
  static fromPayload(data) {
    const decoded = MsgPack.decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 8) {
      throw new Error("payload must be an 8-element MessagePack array");
    }
    const [issuer, grantee, action, hlc, relationHash, objectHashes, wildcard, signatures] = decoded;
    if (action !== Action.GRANT && action !== Action.REVOKE) {
      throw new Error(`unknown action byte ${action}`);
    }
    if (!Array.isArray(signatures) || signatures.length === 0) {
      throw new Error("signatures must be a non-empty array of 64-byte blobs");
    }
    return new Operation({
      tuple: new Tuple({
        relationHash: expectBytes(relationHash, 16, "relation_hash"),
        objectHashes: objectHashes.map((h) => expectBytes(h, 16, "object_hash")),
        wildcard: expectBool(wildcard, "wildcard"),
        grantee: expectBytes(grantee, 16, "grantee"),
        issuer: expectBytes(issuer, 16, "issuer"),
      }),
      action,
      hlc: BigInt(hlc),
      signatures: signatures.map((s) => expectBytes(s, SIGNATURE_SIZE, "signature")),
    });
  }
}

/**
 * @param {Uint8Array} value
 * @param {number} len
 * @param {string} name
 * @returns {Uint8Array}
 */
function expectBytes(value, len, name) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`${name} must be a ${len}-byte Uint8Array`);
  }
  return value;
}

/**
 * @param {boolean} value
 * @param {string} name
 * @returns {boolean}
 */
function expectBool(value, name) {
  if (typeof value !== "boolean") throw new Error(`${name} must be a boolean`);
  return value;
}

