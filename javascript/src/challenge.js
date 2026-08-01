/**
 * Strict Consistency Challenge / Freshness Receipts (§8).
 *
 * For destructive operations eventual consistency is dangerous. The node
 * performs a local pre-check, then challenges a configured Authoritative
 * Identity over an RNS link for a signed Freshness Receipt evaluated against
 * the server's absolute-latest CRDT state.
 *
 * The RNS transport is abstracted behind an async `transport` callable
 * (`challengePayload -> receiptPayload | null`), so the cryptographic and
 * verdict logic is testable without a live network. A transport that returns
 * null or throws is treated as a partition -> immediately DENIED.
 */

import { Identity } from "@reticulum/core";
import { MsgPack } from "@reticulum/core";
import { Config } from "./config.js";
import { Engine } from "./engine.js";
import { Clock } from "./hlc.js";
import { MAX_HLC } from "./hlc.js";
import { HASH_SIZE, bytesEqual } from "./tuple.js";

/** Cryptographically secure challenge nonces are 32 bytes. */
export const NONCE_SIZE = 32;
/** Ed25519 signatures are 64 bytes. */
const SIGNATURE_SIZE = 64;

/**
 * The binary verdict carried by a Freshness Receipt.
 * @readonly
 * @enum {number}
 */
export const Verdict = {
  DENY: 0x00,
  ALLOW: 0x01,
};

/**
 * @typedef {Uint8Array | import("@reticulum/core").Identity} PublicKeyLike
 */

/**
 * @param {PublicKeyLike} value
 * @returns {Promise<Identity>}
 */
async function asIdentity(value) {
  return value instanceof Identity ? value : await Identity.fromPublicKey(value);
}

/**
 * @typedef {Object} ChallengeInit
 * @property {string} object
 * @property {string} relation
 * @property {Uint8Array} grantee
 * @property {Uint8Array} nonce
 */

export class Challenge {
  /** @param {ChallengeInit} init */
  constructor({ object, relation, grantee, nonce }) {
    if (!(grantee instanceof Uint8Array) || grantee.length !== HASH_SIZE) {
      throw new TypeError(`grantee must be ${HASH_SIZE} bytes`);
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_SIZE) {
      throw new TypeError(`nonce must be ${NONCE_SIZE} bytes`);
    }
    this.object = object;
    this.relation = relation;
    this.grantee = grantee;
    this.nonce = nonce;
  }

  /**
   * Build a Challenge with a fresh (or supplied) cryptographically secure nonce.
   * @param {string} object
   * @param {string} relation
   * @param {Uint8Array} grantee
   * @param {Object} [opts]
   * @param {Uint8Array} [opts.nonce]
   * @returns {Challenge}
   */
  static generate(object, relation, grantee, { nonce } = {}) {
    return new Challenge({
      object,
      relation,
      grantee,
      nonce: nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_SIZE)),
    });
  }

  /** Serialize as `[object, relation, grantee(16), nonce(32)]`. @returns {Uint8Array} */
  toPayload() {
    return MsgPack.encode([this.object, this.relation, this.grantee, this.nonce]);
  }

  /** @param {Uint8Array} data @returns {Challenge} */
  static fromPayload(data) {
    const decoded = MsgPack.decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 4) {
      throw new Error("challenge payload must be a 4-element MessagePack array");
    }
    const [object, relation, grantee, nonce] = decoded;
    return new Challenge({ object, relation, grantee: expectBytes(grantee, HASH_SIZE), nonce: expectBytes(nonce, NONCE_SIZE) });
  }
}

/**
 * @typedef {Object} ReceiptInit
 * @property {number} verdict One of {@link Verdict}.
 * @property {bigint} serverHlc
 * @property {Uint8Array} nonce
 * @property {Uint8Array} [signature]
 */

export class Receipt {
  /** @param {ReceiptInit} init */
  constructor({ verdict, serverHlc, nonce, signature = new Uint8Array(0) }) {
    if (verdict !== Verdict.ALLOW && verdict !== Verdict.DENY) {
      throw new TypeError("verdict must be Verdict.ALLOW or Verdict.DENY");
    }
    if (typeof serverHlc !== "bigint" || serverHlc < 0n || serverHlc > MAX_HLC) {
      throw new RangeError("serverHlc must be a bigint in [0, 2^64)");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_SIZE) {
      throw new TypeError(`nonce must be ${NONCE_SIZE} bytes`);
    }
    if (!(signature instanceof Uint8Array) || (signature.length !== 0 && signature.length !== SIGNATURE_SIZE)) {
      throw new RangeError(`signature must be 0 or ${SIGNATURE_SIZE} bytes`);
    }
    this.verdict = verdict;
    this.serverHlc = serverHlc;
    this.nonce = nonce;
    this.signature = signature;
  }

  /** Unpadded concatenation of the fields preceding the signature (41 bytes). @returns {Uint8Array} */
  get preimage() {
    const hlcBytes = new Uint8Array(8);
    new DataView(hlcBytes.buffer).setBigUint64(0, this.serverHlc, false); // big-endian
    const out = new Uint8Array(1 + 8 + NONCE_SIZE);
    out[0] = this.verdict;
    out.set(hlcBytes, 1);
    out.set(this.nonce, 9);
    return out;
  }

  /** @param {Identity} identity @returns {Promise<Receipt>} */
  async sign(identity) {
    const signature = await identity.sign(this.preimage);
    return new Receipt({ verdict: this.verdict, serverHlc: this.serverHlc, nonce: this.nonce, signature });
  }

  /** @param {PublicKeyLike} identityOrPublicKey @returns {Promise<boolean>} */
  async verify(identityOrPublicKey) {
    if (this.signature.length !== SIGNATURE_SIZE) return false;
    const identity = await asIdentity(identityOrPublicKey);
    return identity.validate(this.signature, this.preimage);
  }

  /** @returns {Uint8Array} */
  toPayload() {
    if (this.signature.length !== SIGNATURE_SIZE) {
      throw new Error("Receipt must be signed before payload serialization");
    }
    return MsgPack.encode([this.verdict, this.serverHlc, this.nonce, this.signature]);
  }

  /** @param {Uint8Array} data @returns {Receipt} */
  static fromPayload(data) {
    const decoded = MsgPack.decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 4) {
      throw new Error("receipt payload must be a 4-element MessagePack array");
    }
    const [verdict, serverHlc, nonce, signature] = decoded;
    if (verdict !== Verdict.ALLOW && verdict !== Verdict.DENY) {
      throw new Error(`unknown verdict byte ${verdict}`);
    }
    return new Receipt({
      verdict,
      serverHlc: BigInt(serverHlc),
      nonce: expectBytes(nonce, NONCE_SIZE),
      signature: expectBytes(signature, SIGNATURE_SIZE),
    });
  }
}

/** @param {unknown} value @param {number} len @returns {Uint8Array} */
function expectBytes(value, len) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`expected a ${len}-byte Uint8Array`);
  }
  return value;
}

/**
 * The Authoritative Identity: evaluates requests and signs Freshness Receipts.
 */
export class AuthoritativeServer {
  /**
   * @param {Config} config
   * @param {import("./crdt.js").StateVector} state
   * @param {Identity} privateKey Identity holding the signing key.
   * @param {Object} [opts]
   * @param {Clock} [opts.clock]
   */
  constructor(config, state, privateKey, { clock } = {}) {
    this._engine = new Engine(config, state);
    this._state = state;
    this._privateKey = privateKey;
    this._clock = clock ?? new Clock();
  }

  /** @param {Uint8Array} challengePayload @returns {Promise<Uint8Array>} */
  async handle(challengePayload) {
    const challenge = Challenge.fromPayload(challengePayload);
    const allowed = this._engine.evaluate(challenge.object, challenge.relation, challenge.grantee);
    const verdict = allowed ? Verdict.ALLOW : Verdict.DENY;
    const receipt = await new Receipt({
      verdict,
      serverHlc: this._clock.now(),
      nonce: challenge.nonce,
    }).sign(this._privateKey);
    // NOTE (§8.4): when the server's DENY is due to upstream revocations not
    // yet known to the client, the server SHOULD also ship the revoked tuples
    // so the client can update its local CRDT. The wire format for that is not
    // defined by spec 1.0-RC3; applications extend the Receipt payload.
    return receipt.toPayload();
  }
}

/**
 * @callback Transport
 * @param {Uint8Array} challengePayload
 * @returns {Promise<Uint8Array | null>}
 */

/**
 * The requesting node: performs the local pre-check and the challenge exchange.
 */
export class ChallengeClient {
  /**
   * @param {Config} config
   * @param {import("./crdt.js").StateVector} state
   * @param {PublicKeyLike} authoritativePublicKey
   * @param {Transport} transport
   */
  constructor(config, state, authoritativePublicKey, transport) {
    if (config.authoritativeIdentity === undefined) {
      throw new Error("Strict Consistency requires an Authoritative Identity (§4.1)");
    }
    this._engine = new Engine(config, state);
    this._state = state;
    this._publicKey = authoritativePublicKey;
    this._transport = transport;
  }

  /**
   * Run the full §8 flow. Resolves true only on a verified server ALLOW.
   * @param {string} objectId
   * @param {string} relation
   * @param {Uint8Array} grantee
   * @returns {Promise<boolean>}
   */
  async authorize(objectId, relation, grantee) {
    // §8.1 Local pre-check.
    if (!this._engine.evaluate(objectId, relation, grantee)) return false;
    // §8.2 Challenge.
    const challenge = Challenge.generate(objectId, relation, grantee);
    let receiptPayload;
    try {
      receiptPayload = await this._transport(challenge.toPayload());
    } catch {
      return false; // §8.5 partition penalty
    }
    if (receiptPayload === null || receiptPayload === undefined) {
      return false; // §8.5 partition penalty
    }
    const receipt = Receipt.fromPayload(receiptPayload);
    // §8.4 Verify nonce match and signature.
    if (!bytesEqual(receipt.nonce, challenge.nonce)) return false;
    if (!(await receipt.verify(this._publicKey))) return false;
    return receipt.verdict === Verdict.ALLOW;
  }
}
