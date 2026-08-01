/**
 * Segment-aware namespace matching (Dacar spec §3.3).
 *
 * Namespaces within an Object string are delimited by `:`. The suffix wildcard
 * `*` matches all subsequent segments and MUST be the terminal segment of a
 * tuple's Object string.
 */

export const DELIMITER = ":";
export const WILDCARD = "*";

/**
 * Split an object string into its segments.
 * @param {string} objectId
 * @returns {string[]}
 */
export function split(objectId) {
  return objectId.split(DELIMITER);
}

/**
 * Whether `requestedObject` is covered by `tupleObject`, per the §3.3
 * algorithm: compare segments sequentially; a `*` tuple segment matches
 * immediately; any pre-wildcard mismatch fails.
 * @param {string} tupleObject
 * @param {string} requestedObject
 * @returns {boolean}
 */
export function match(tupleObject, requestedObject) {
  const t = split(tupleObject);
  const r = split(requestedObject);
  for (let i = 0; i < t.length; i++) {
    if (t[i] === WILDCARD) return true;
    if (i >= r.length || t[i] !== r[i]) return false;
  }
  return t.length === r.length;
}

/**
 * The exact and suffix-wildcard patterns that cover `objectId`.
 * For `"a:b:c"` yields `["a:b:*", "a:*", "*", "a:b:c"]` (order not significant).
 * @param {string} objectId
 * @returns {string[]}
 */
export function permutations(objectId) {
  const segments = split(objectId);
  const patterns = [];
  for (let i = segments.length - 1; i >= 0; i--) {
    patterns.push([...segments.slice(0, i), WILDCARD].join(DELIMITER));
  }
  patterns.push(objectId);
  return patterns;
}
