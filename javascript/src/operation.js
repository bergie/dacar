/**
 * Signed authorization Operations / Deltas (Dacar spec §5.2, §5.3).
 *
 * An Operation is a cryptographically signed instruction to Grant (Add) or
 * Revoke (Remove) a Tuple. Ed25519 signing/verification is delegated to the
 * `Identity` from `@reticulum/core` (Web Crypto under the hood), and transport
 * serialization uses its MessagePack implementation.
 */

import { Identity, MsgPack } from "@reticulum/core";
import { MAX_HLC } from "./hlc.js";
import { HASH_SIZE, Tuple } from "./tuple.js";

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
  REVOKE: 0x00, // Remove the Tuple from the Add set.
  GRANT: 0x01, // Add the Tuple to the Add set.
};

const encoder = new TextEncoder();

/**
 * @typedef {Object} OperationInit
 * @property {Tuple} tuple
 * @property {number} action One of {@link Action}.
 * @property {bigint} hlc
 * @property {Uint8Array} [signature] 64-byte Ed25519 signature (empty if unsigned).
 */

export class Operation {
  /** @param {OperationInit} init */
  constructor({ tuple, action, hlc, signature = new Uint8Array(0) }) {
    if (action !== Action.GRANT && action !== Action.REVOKE) {
      throw new TypeError("action must be Action.GRANT or Action.REVOKE");
    }
    if (typeof hlc !== "bigint" || hlc < 0n || hlc > MAX_HLC) {
      throw new RangeError("hlc must be a bigint in [0, 2^64)");
    }
    if (
      !(signature instanceof Uint8Array) ||
      (signature.length !== 0 && signature.length !== SIGNATURE_SIZE)
    ) {
      throw new RangeError(`signature must be 0 or ${SIGNATURE_SIZE} bytes`);
    }
    this.tuple = tuple;
    this.action = action;
    this.hlc = hlc;
    this.signature = signature;
  }

  get object() {
    return this.tuple.object;
  }
  get relation() {
    return this.tuple.relation;
  }
  get grantee() {
    return this.tuple.grantee;
  }
  get issuer() {
    return this.tuple.issuer;
  }

  /** §5.2 signature pre-image. @returns {Uint8Array} */
  get preimage() {
    const relation = encoder.encode(this.relation);
    const object = encoder.encode(this.object);
    const hlcBytes = new Uint8Array(HLC_BYTES);
    new DataView(hlcBytes.buffer).setBigUint64(0, this.hlc, false); // big-endian
    const out = new Uint8Array(
      HASH_SIZE * 2 + 1 + HLC_BYTES + 1 + relation.length + object.length,
    );
    let o = 0;
    out.set(this.issuer, o);
    o += HASH_SIZE;
    out.set(this.grantee, o);
    o += HASH_SIZE;
    out[o++] = this.action;
    out.set(hlcBytes, o);
    o += HLC_BYTES;
    out[o++] = relation.length;
    out.set(relation, o);
    o += relation.length;
    out.set(object, o);
    return out;
  }

  /**
   * Return a copy signed with an `@reticulum/core` Identity holding a private key.
   * @param {Identity} identity
   * @returns {Promise<Operation>}
   */
  async sign(identity) {
    const signature = await identity.sign(this.preimage);
    return new Operation({ tuple: this.tuple, action: this.action, hlc: this.hlc, signature });
  }

  /**
   * Verify the signature. Accepts an Identity (with public key) or a raw
   * 64-byte public key (X25519[32] || Ed25519[32], as used by @reticulum/core).
   * @param {Identity | Uint8Array} identityOrPublicKey
   * @returns {Promise<boolean>}
   */
  async verify(identityOrPublicKey) {
    if (this.signature.length !== SIGNATURE_SIZE) return false;
    const identity =
      identityOrPublicKey instanceof Identity
        ? identityOrPublicKey
        : await Identity.fromPublicKey(identityOrPublicKey);
    return identity.validate(this.signature, this.preimage);
  }

  /** §5.3 transport payload (the Operation must be signed first). @returns {Uint8Array} */
  toPayload() {
    if (this.signature.length !== SIGNATURE_SIZE) {
      throw new Error("Operation must be signed before payload serialization");
    }
    return MsgPack.encode([
      this.issuer,
      this.grantee,
      this.action,
      this.hlc,
      this.relation,
      this.object,
      this.signature,
    ]);
  }

  /**
   * Deserialize a §5.3 transport payload.
   * @param {Uint8Array} data
   * @returns {Operation}
   */
  static fromPayload(data) {
    const decoded = MsgPack.decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 7) {
      throw new Error("payload must be a 7-element MessagePack array");
    }
    const [issuer, grantee, action, hlc, relation, object, signature] = decoded;
    if (action !== Action.GRANT && action !== Action.REVOKE) {
      throw new Error(`unknown action byte ${action}`);
    }
    // Normalize the HLC to bigint: decode yields Number for small values and
    // BigInt for large ones (see @reticulum/core MicroMsgPack).
    return new Operation({
      tuple: new Tuple({
        object,
        relation,
        grantee: expectBytes(grantee, HASH_SIZE),
        issuer: expectBytes(issuer, HASH_SIZE),
      }),
      action,
      hlc: BigInt(hlc),
      signature: expectBytes(signature, SIGNATURE_SIZE),
    });
  }
}

/**
 * @param {unknown} value
 * @param {number} len
 * @returns {Uint8Array}
 */
function expectBytes(value, len) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`expected a ${len}-byte Uint8Array`);
  }
  return value;
}
