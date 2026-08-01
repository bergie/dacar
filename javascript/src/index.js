/**
 * Dacar: Decentralized Access Control for Reticulum (JavaScript reference impl).
 *
 * A tuple-based, offline-first authorization policy plane built on an
 * LWW-Element-Set CRDT, designed for delay-tolerant mesh networks.
 *
 * Object and relation labels are stored only as salted HMAC-SHA256 hashes
 * (§3.3 Namespace Label Privacy), Threshold Groups may act as N-of-M Issuers
 * (§4.1), and the state is bounded by Time-Horizon Tombstone Pruning (§9).
 */

export const __version__ = "1.0.0-rc.6";
export const __specVersion__ = "1.0-RC6";

// HLC (§5.1)
export {
  PHYSICAL_BITS,
  LOGICAL_BITS,
  LOGICAL_MASK,
  MAX_PHYSICAL,
  MAX_LOGICAL,
  MAX_HLC,
  packHlc,
  unpackHlc,
  physicalNowMs,
  Clock,
} from "./hlc.js";

// Namespace Label Privacy (§3.3)
export {
  DELIMITER,
  WILDCARD,
  SALT_SIZE,
  HASH_SIZE,
  DEFAULT_SALT,
  MAX_LEGACY_SALTS,
  NamespaceHasher,
  covers,
  split,
  parseObject,
  bytesEqual,
} from "./namespace.js";

// Tuple (§3.1, §6.1)
export { MAX_SEGMENTS, Tuple } from "./tuple.js";

// Threshold Groups (§4.1)
export { ThresholdGroup, groupId } from "./threshold.js";

// Operations (§5.2, §5.3)
export { SIGNATURE_SIZE, HLC_BYTES, Action, Operation } from "./operation.js";

// Config (§4, §10) + state (§6, §9)
export { Config, DEFAULT_DELETION_HORIZON_DAYS } from "./config.js";
export { StateVector } from "./crdt.js";

// Engine (§7)
export {
  Engine,
  ADMIN_RELATION,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_VISITED,
} from "./engine.js";

// Challenge (§8)
export {
  NONCE_SIZE,
  Verdict,
  Challenge,
  Receipt,
  AuthoritativeServer,
  ChallengeClient,
} from "./challenge.js";
