/**
 * Dacar: Decentralized Access Control for Reticulum (JavaScript reference impl).
 *
 * A tuple-based, offline-first authorization policy plane built on an
 * LWW-Element-Set CRDT, designed for delay-tolerant mesh networks.
 */

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

export { DELIMITER, WILDCARD, split, match, permutations } from "./namespace.js";

export { HASH_SIZE, RELATION_MAX_LEN, Tuple, bytesEqual } from "./tuple.js";

export { SIGNATURE_SIZE, HLC_BYTES, Action, Operation } from "./operation.js";

export { Config } from "./config.js";
export { StateVector } from "./crdt.js";
export {
  Engine,
  ADMIN_RELATION,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_VISITED,
} from "./engine.js";
export {
  NONCE_SIZE,
  Verdict,
  Challenge,
  Receipt,
  AuthoritativeServer,
  ChallengeClient,
} from "./challenge.js";
