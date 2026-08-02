/**
 * Optional RNS/RFed/LXMF-dependent transport adapters for Dacar (spec §8, §11).
 *
 * These wire the pure, transport-agnostic core — the §8 `Challenge`/
 * `AuthoritativeServer`/`ChallengeClient` and the §11 `DeltaReceiver` — to the
 * concrete Reticulum transports from `@reticulum/core`:
 *
 *   - {@link RnsIdentityResolver}      §3.1, §11.2.4  recall → verify key
 *   - {@link RnsChallengeServer} &c.   §8             Challenge over an RNS Link
 *   - {@link LxmfDeltaDelivery}        §11.2/§11.3    targeted LXMF + Paper Messages
 *   - {@link RfedDeltaSync}            §11.1          RFed many-to-many convergence
 *
 * Importing the pure core (`@reticulum/dacar`) does **not** import this
 * subpath: it is opt-in via `@reticulum/dacar/transport`. Every adapter depends
 * only on `@reticulum/core`, which the core already depends on, so the
 * transport layer adds no new dependency.
 */

export { RnsIdentityResolver } from "./rnsIdentity.js";

export {
  CHALLENGE_REQUEST_PATH,
  DEFAULT_CHALLENGE_TIMEOUT_MS,
  DEFAULT_ESTABLISH_TIMEOUT_MS,
  challengeRequestHandler,
  RnsChallengeServer,
  RnsLinkTransport,
  establishLink,
} from "./rnsChallenge.js";

export {
  LxmfDeltaDelivery,
  messageTitle,
  messageContent,
} from "./lxmfSync.js";

export { RfedDeltaSync } from "./rfedSync.js";
