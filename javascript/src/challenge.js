/**
 * Strict Consistency Challenge / Freshness Receipts (§8).
 *
 * For destructive operations eventual consistency is dangerous. The node
 * performs a local pre-check, then challenges a configured Authoritative
 * Identity over an RNS link (App Name `dacar`, Aspects `auth`, `v1`) for a
 * signed verdict evaluated against the server's absolute-latest CRDT state.
 *
 * To preserve Namespace Label Privacy (§3.3), the Challenge payload carries
 * only *hashed* hypotheses — never plaintext. The client hashes the request
 * across its Primary Salt and all Legacy Salts (§10); the server matches each by
 * its `salt_id_tag` and evaluates directly in hash space.
 *
 * Canonical challenge wire format (§8.3):
 *
 *   [ nonce(32),
 *     [ [ salt_id_tag(16), grantee_hash(16), allow_relation_hash(16),
 *         deny_relation_hash(16), [object_segment_hashes] ],
 *       ... ] ]
 *
 * Each entry is fully self-contained for one salt and carries *both* the allow
 * and deny relation hashes so the Authority can apply the deny-beats-allow rule
 * (§7.3) without recovering plaintext.
 *
 * The RNS transport is abstracted behind an async `transport` callable
 * (`challengePayload -> receiptPayload | null`), so the cryptographic and
 * verdict logic is testable without a live network. A transport that returns
 * null or throws is a partition -> immediately DENIED (§8).
 */

import { Identity, MsgPack, toHex } from "@reticulum/core";
import { Config } from "./config.js";
import { Engine } from "./engine.js";
import { Clock, MAX_HLC } from "./hlc.js";
import { HASH_SIZE, bytesEqual } from "./namespace.js";

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
 * @typedef {Uint8Array | Identity} PublicKeyLike
 */

/**
 * @param {PublicKeyLike} value
 * @returns {Promise<Identity>}
 */
async function asIdentity(value) {
  return value instanceof Identity ? value : await Identity.fromPublicKey(value);
}

/** @param {Uint8Array} value @param {number} len @param {string} name @returns {Uint8Array} */
function expectBytes(value, len, name) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`${name} must be a ${len}-byte Uint8Array`);
  }
  return value;
}

/**
 * @typedef {Object} DecodedEntry
 * @property {Uint8Array} saltIdTag
 * @property {Uint8Array} granteeHash
 * @property {Uint8Array} allowRelationHash
 * @property {Uint8Array} denyRelationHash
 * @property {Uint8Array[]} objectHashes
 */

/**
 * @typedef {Object} DecodedChallenge
 * @property {Uint8Array} nonce
 * @property {Uint8Array} grantee
 * @property {DecodedEntry[]} entries
 */

export class Challenge {
  /**
   * @param {Object} init
   * @param {string} init.object Plaintext (held only on the client).
   * @param {string} init.relation Plaintext (held only on the client).
   * @param {Uint8Array} init.grantee 16-byte holder identity hash.
   * @param {Uint8Array} init.nonce 32-byte nonce.
   * @param {import("./namespace.js").NamespaceHasher[]} init.hashers Salts to hypothesize over.
   */
  constructor({ object, relation, grantee, nonce, hashers }) {
    if (!(grantee instanceof Uint8Array) || grantee.length !== HASH_SIZE) {
      throw new TypeError(`grantee must be ${HASH_SIZE} bytes`);
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_SIZE) {
      throw new TypeError(`nonce must be ${NONCE_SIZE} bytes`);
    }
    if (!Array.isArray(hashers) || hashers.length === 0) {
      throw new TypeError("at least one salt hasher is required");
    }
    this.object = object;
    this.relation = relation;
    this.grantee = grantee;
    this.nonce = nonce;
    this.hashers = [...hashers];
  }

  /**
   * Build a Challenge with a fresh (or supplied) cryptographically secure nonce.
   * @param {string} object
   * @param {string} relation
   * @param {Uint8Array} grantee
   * @param {import("./namespace.js").NamespaceHasher[]} hashers
   * @param {Object} [opts]
   * @param {Uint8Array} [opts.nonce]
   * @returns {Challenge}
   */
  static generate(object, relation, grantee, hashers, { nonce } = {}) {
    return new Challenge({
      object,
      relation,
      grantee,
      nonce: nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_SIZE)),
      hashers,
    });
  }

  /** Serialize the hashed multi-salt challenge (§8.3). @returns {Promise<Uint8Array>} */
  async toPayload() {
    const denyRelation = "-" + this.relation;
    const entries = await Promise.all(
      this.hashers.map(async (hasher) => {
        const [saltIdTag, allowRelationHash, denyRelationHash, { hashes }] = await Promise.all([
          hasher.idTag(),
          hasher.hashRelation(this.relation),
          hasher.hashRelation(denyRelation),
          hasher.hashObject(this.object),
        ]);
        return [
          saltIdTag,
          this.grantee,
          allowRelationHash,
          denyRelationHash,
          [...hashes],
        ];
      }),
    );
    return MsgPack.encode([this.nonce, entries]);
  }

  /**
   * Decode a challenge payload (§8.4). Plaintext is intentionally unrecoverable.
   * @param {Uint8Array} data
   * @returns {DecodedChallenge}
   */
  static fromPayload(data) {
    const decoded = MsgPack.decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 2) {
      throw new Error("challenge payload must be a 2-element MessagePack array");
    }
    const [nonce, entries] = decoded;
    const nonceBytes = expectBytes(nonce, NONCE_SIZE, "nonce");
    if (!Array.isArray(entries)) {
      throw new Error("challenge entries must be an array");
    }
    /** @type {DecodedEntry[]} */
    const result = [];
    /** @type {Uint8Array | null} */
    let grantee = null;
    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length !== 5) {
        throw new Error("each challenge entry must be a 5-element array");
      }
      const [saltIdTag, granteeHash, allowRh, denyRh, objectHashes] = entry;
      if (!Array.isArray(objectHashes)) throw new Error("object_segment_hashes must be an array");
      const gh = expectBytes(granteeHash, HASH_SIZE, "grantee_hash");
      if (grantee === null) grantee = gh;
      else if (!bytesEqual(grantee, gh)) throw new Error("all challenge entries must share one grantee");
      result.push({
        saltIdTag: expectBytes(saltIdTag, HASH_SIZE, "salt_id_tag"),
        granteeHash: gh,
        allowRelationHash: expectBytes(allowRh, HASH_SIZE, "allow_relation_hash"),
        denyRelationHash: expectBytes(denyRh, HASH_SIZE, "deny_relation_hash"),
        objectHashes: objectHashes.map((h) => expectBytes(h, HASH_SIZE, "object_hash")),
      });
    }
    if (grantee === null) throw new Error("challenge must carry at least one entry");
    return { nonce: nonceBytes, grantee, entries: result };
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
      nonce: expectBytes(nonce, NONCE_SIZE, "nonce"),
      signature: expectBytes(signature, SIGNATURE_SIZE, "signature"),
    });
  }
}

/**
 * Bind each decoded entry to a configured salt via its salt_id_tag (§8.4) and
 * build the synchronous hypothesis objects the engine consumes.
 * @param {import("./config.js").Config} config
 * @param {DecodedChallenge} decoded
 * @returns {Promise<import("./engine.js").Hypothesis[]>}
 */
async function buildHypotheses(config, decoded) {
  /** @type {Map<string, import("./namespace.js").NamespaceHasher>} */
  const byTag = new Map();
  for (const hasher of config.hashers) {
    byTag.set(toHex(await hasher.idTag()), hasher);
  }
  /** @type {import("./engine.js").Hypothesis[]} */
  const hyps = [];
  for (const entry of decoded.entries) {
    const hasher = byTag.get(toHex(entry.saltIdTag));
    if (!hasher) continue; // unknown salt -> hypothesis unusable, skip
    const [adminAllowHash, adminDenyHash] = await Promise.all([
      hasher.hashRelation("admin"),
      hasher.hashRelation("-admin"),
    ]);
    hyps.push({
      hasher,
      objectHashes: entry.objectHashes,
      allowRelationHash: entry.allowRelationHash,
      denyRelationHash: entry.denyRelationHash,
      adminAllowHash,
      adminDenyHash,
    });
  }
  return hyps;
}

/** The Authoritative Identity: evaluates requests and signs Freshness Receipts. */
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
    this._config = config;
    this._privateKey = privateKey;
    this._clock = clock ?? new Clock();
  }

  /** @param {Uint8Array} challengePayload @returns {Promise<Uint8Array>} */
  async handle(challengePayload) {
    const decoded = Challenge.fromPayload(challengePayload);
    const hypotheses = await buildHypotheses(this._config, decoded);
    const allowed = hypotheses.length > 0 && this._engine.evaluateHashes(decoded.grantee, hypotheses);
    const verdict = allowed ? Verdict.ALLOW : Verdict.DENY;
    const receipt = await new Receipt({
      verdict,
      serverHlc: this._clock.now(),
      nonce: decoded.nonce,
    }).sign(this._privateKey);
    return receipt.toPayload();
  }
}

/**
 * @callback Transport
 * @param {Uint8Array} challengePayload
 * @returns {Promise<Uint8Array | null> | Uint8Array | null}
 */

/** The requesting node: performs the local pre-check and the challenge exchange. */
export class ChallengeClient {
  /**
   * @param {Config} config
   * @param {import("./crdt.js").StateVector} state
   * @param {PublicKeyLike} authoritativePublicKey
   * @param {Transport} transport
   */
  constructor(config, state, authoritativePublicKey, transport) {
    if (config.authoritativeIdentity === undefined) {
      throw new Error("Strict Consistency requires an Authoritative Identity (§8)");
    }
    this._engine = new Engine(config, state);
    this._state = state;
    this._config = config;
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
    if (!(await this._engine.evaluate(objectId, relation, grantee))) return false;
    // §8.2/§8.3 Challenge across Primary + Legacy salts.
    const challenge = Challenge.generate(objectId, relation, grantee, this._config.hashers);
    let receiptPayload;
    try {
      receiptPayload = await Promise.resolve(this._transport(await challenge.toPayload()));
    } catch {
      return false; // partition penalty (§8)
    }
    if (receiptPayload === null || receiptPayload === undefined) return false; // partition (§8)
    const receipt = Receipt.fromPayload(receiptPayload);
    // §8.5 Verify nonce match and signature.
    if (!bytesEqual(receipt.nonce, challenge.nonce)) return false;
    if (!(await receipt.verify(this._publicKey))) return false;
    return receipt.verdict === Verdict.ALLOW;
  }
}
