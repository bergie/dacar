/**
 * Hybrid Logical Clocks (Dacar spec §5.1).
 *
 * An HLC packs into a single 64-bit unsigned integer, transmitted big-endian:
 *   high 48 bits: physical time (Unix epoch, milliseconds)
 *   low 16 bits : logical counter
 *
 * Packed HLCs are represented as ECMAScript `bigint`, because
 * `physical_ms << 16` exceeds `Number.MAX_SAFE_INTEGER` for any realistic
 * timestamp.
 */

export const PHYSICAL_BITS = 48n;
export const LOGICAL_BITS = 16n;
/** @type {bigint} 0xFFFF */
export const LOGICAL_MASK = (1n << LOGICAL_BITS) - 1n;
/** @type {bigint} 2^48 - 1 */
export const MAX_PHYSICAL = (1n << PHYSICAL_BITS) - 1n;
/** @type {bigint} 2^16 - 1 */
export const MAX_LOGICAL = LOGICAL_MASK;
/** @type {bigint} 2^64 - 1 */
export const MAX_HLC = (1n << 64n) - 1n;

/**
 * Pack a physical timestamp (ms) and logical counter into a 64-bit HLC.
 * @param {number} physicalMs
 * @param {number} logical
 * @returns {bigint}
 */
export function packHlc(physicalMs, logical) {
  if (!Number.isInteger(physicalMs) || physicalMs < 0 || BigInt(physicalMs) > MAX_PHYSICAL) {
    throw new RangeError(`physicalMs must fit in 48 bits, got ${physicalMs}`);
  }
  if (!Number.isInteger(logical) || logical < 0 || BigInt(logical) > MAX_LOGICAL) {
    throw new RangeError(`logical must fit in 16 bits, got ${logical}`);
  }
  return (BigInt(physicalMs) << LOGICAL_BITS) | BigInt(logical);
}

/**
 * Unpack an HLC into its physical (ms) and logical parts (both safe Numbers).
 * @param {bigint} hlc
 * @returns {{ physicalMs: number, logical: number }}
 */
export function unpackHlc(hlc) {
  if (typeof hlc !== "bigint" || hlc < 0n || hlc > MAX_HLC) {
    throw new RangeError(`hlc must fit in 64 bits, got ${hlc}`);
  }
  return {
    physicalMs: Number(hlc >> LOGICAL_BITS),
    logical: Number(hlc & LOGICAL_MASK),
  };
}

/**
 * Current wall-clock time in milliseconds since the Unix epoch.
 * @returns {number}
 */
export function physicalNowMs() {
  return Date.now();
}

/**
 * A process-local HLC generator producing monotonically non-decreasing
 * timestamps, able to absorb remote HLCs observed during sync.
 */
export class Clock {
  #lastMs = 0;
  #logical = 0;

  /**
   * Get the last physical timestamp (ms).
   * @returns {number}
   */
  get lastMs() {
    return this.#lastMs;
  }

  /**
   * Get the current logical counter.
   * @returns {number}
   */
  get logical() {
    return this.#logical;
  }

  /**
   * Restore the clock from a snapshot (for store persistence).
   * @param {{ lastMs: number, logical: number }} snap
   */
  restore(snap) {
    if (!snap || typeof snap.lastMs !== "number" || typeof snap.logical !== "number") {
      throw new Error("restore requires an object with lastMs and logical");
    }
    this.#lastMs = snap.lastMs;
    this.#logical = snap.logical;
  }

  /** Obtain a snapshot for persistence. @returns {{ lastMs: number, logical: number }} */
  snapshot() {
    return { lastMs: this.#lastMs, logical: this.#logical };
  }

  /** Advance from a local event and return the new HLC. @returns {bigint} */
  now() {
    const phys = physicalNowMs();
    if (phys > this.#lastMs) {
      this.#lastMs = phys;
      this.#logical = 0;
    } else {
      this.#logical += 1;
    }
    return packHlc(this.#lastMs, this.#logical);
  }

  /**
   * Absorb a remote HLC observed during sync and return the new local HLC.
   * @param {bigint} remoteHlc
   * @returns {bigint}
   */
  observe(remoteHlc) {
    const { physicalMs: rphys, logical: rlog } = unpackHlc(remoteHlc);
    const phys = physicalNowMs();
    if (phys > this.#lastMs && phys > rphys) {
      this.#lastMs = phys;
      this.#logical = 0;
    } else if (rphys > this.#lastMs) {
      this.#lastMs = rphys;
      this.#logical = rlog + 1;
    } else if (this.#lastMs > rphys) {
      this.#logical += 1;
    } else {
      this.#logical = Math.max(this.#logical, rlog) + 1;
    }
    return packHlc(this.#lastMs, this.#logical);
  }
}
