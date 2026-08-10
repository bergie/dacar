/**
 * Smoketests for the portable CLI session helper `announceIdentity` (§11.2.4).
 *
 * `announceIdentity` must bind its `dacar.node` destination to the booted
 * Reticulum (as the destination's interface layer) so `announce()` can emit the
 * announce packet — the announce invariant that makes the node's identity
 * recallable by peers. Without binding, `announce()` throws
 * "Destination not bound to an RNS instance."
 *
 * Unlike the rfed/transport tests (which inject a `FakeRFedClient`), this
 * exercises the *real* RNS seam: a headless `Reticulum` (no interfaces, so
 * `broadcast` is a no-op) and a real `Identity`/`Destination`. This is the
 * regression coverage that would have caught the `Destination.create` argument-
 * ordering bug where `rns` was passed as `identity` and `interfaceLayer` was
 * left null.
 *
 * Mirrors Python's `tests/test_rfed_client_response.py` +
 * `dacar/cli/rns.py::announce_identity` (the canonical implementation).
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Identity, Reticulum, toHex } from "@reticulum/core";
import { APP_NAME } from "../src/naming.js";
import { announceIdentity } from "../src/cli/session.js";

describe("announceIdentity (§11.2.4 announce invariant)", () => {
  it("announces a dacar.node destination bound to the Reticulum without throwing", async () => {
    const rns = new Reticulum({});
    const identity = await Identity.generate();

    // Regression: with the buggy `Destination.create(name, Destination.IN,
    // identity, rns)` arg order, this threw "Destination not bound to an RNS
    // instance." It must now return the 16-byte dacar.node destination hash.
    const destHash = await announceIdentity(identity, rns);

    assert.ok(destHash instanceof Uint8Array, "destination hash is a Uint8Array");
    assert.equal(destHash.length, 16, "destination hash is 16 bytes");
  });

  it("the announced destination hash matches the canonical dacar.node derivation", async () => {
    const rns = new Reticulum({});
    const identity = await Identity.generate();
    const destHash = await announceIdentity(identity, rns);

    // Recompute SHA-256("dacar.node")[:10] ‖ identityHash, then [:16] —
    // matching @reticulum/core's Destination._computeHashes for a SINGLE IN.
    const nameHash = new Uint8Array(
      (await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${APP_NAME}.node`)))
        .slice(0, 10),
    );
    const combined = new Uint8Array(nameHash.length + identity.identityHash.length);
    combined.set(nameHash, 0);
    combined.set(identity.identityHash, nameHash.length);
    const expected = new Uint8Array(
      (await crypto.subtle.digest("SHA-256", combined)).slice(0, 16),
    );
    assert.equal(toHex(destHash), toHex(expected));
  });

  it("announces two distinct identities to distinct destination hashes", async () => {
    const rns = new Reticulum({});
    const a = await announceIdentity(await Identity.generate(), rns);
    const b = await announceIdentity(await Identity.generate(), rns);
    assert.notEqual(toHex(a), toHex(b));
  });

  it("throws a clear error when rns is not provided (caller misuse)", async () => {
    // announceIdentity(id, null) creates an *unbound* destination; announce()
    // must refuse rather than silently no-op — surfacing the missing Reticulum.
    const identity = await Identity.generate();
    await assert.rejects(
      () => announceIdentity(identity, null),
      /not bound to an RNS instance/i,
    );
  });
});
