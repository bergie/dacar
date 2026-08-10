/**
 * Smoketests for `discoverRfedNode` (work doc #6 — §11.1 autodiscovery).
 *
 * `dacar sync --discover` (and `grant --publish --discover`) listen for an
 * `rfed.node` announce on the live transport and resolve with that
 * announce's destination hash — the rfed node's canonical identifier — or
 * reject after a timeout if no rfed node announces.
 *
 * The rfed daemon (an external process; dacar ships only the client) announces
 * `rfed.node` + the `rfed.channel.*` services under one identity. A
 * `dacar.node` announce is a *different* thing (a dacar peer's signing
 * identity, §11.2.4) and must NOT satisfy rfed-node discovery. These tests
 * pin that contract: they dispatch real `Destination.IN`-created announces
 * (so `destinationHash`/`nameHash` match a live transport) and assert the
 * resolved hash is the announce's own `destinationHash` (no derivation).
 *
 * Exercises the real headless `Reticulum` transport (an `EventTarget`) by
 * dispatching synthetic `"announce"` CustomEvents, so the whole
 * listen → filter → resolve path is covered without a live network.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Destination, DestType, Identity, Reticulum } from "@reticulum/core";
import { APP_NAME } from "../src/naming.js";
import { discoverRfedNode } from "../src/cli/session.js";

describe("discoverRfedNode (§11.1 autodiscovery — rfed.node)", () => {
  it("resolves with the rfed.node announce's destination hash (no derivation)", async () => {
    const rns = new Reticulum({});
    const nodeIdentity = await Identity.generate();
    const nodeDest = await Destination.IN("rfed.node", DestType.SINGLE, nodeIdentity, rns);

    const p = discoverRfedNode({ rns, timeout: 2000 });
    setTimeout(
      () => rns.transport.dispatchEvent(
        new CustomEvent("announce", {
          detail: {
            destinationHash: nodeDest.destinationHash,
            identity: nodeIdentity,
            nameHash: nodeDest.nameHash,
          },
        }),
      ),
      50,
    );
    const got = await p;
    assert.equal(got.length, 16);
    // The announce's destinationHash IS the rfed node hash — returned directly.
    assert.deepEqual(got, nodeDest.destinationHash);
  });

  it("ignores rfed.channel.* and dacar.node announces, then resolves on rfed.node", async () => {
    const rns = new Reticulum({});
    const nodeIdentity = await Identity.generate();
    // The rfed node announces several destinations under one identity…
    const publishDest = await Destination.IN(
      "rfed.channel.publish", DestType.SINGLE, nodeIdentity, rns,
    );
    // …and a dacar peer announces dacar.node under a *different* identity.
    const dacarPeer = await Identity.generate();
    const dacarDest = await Destination.IN(`${APP_NAME}.node`, DestType.SINGLE, dacarPeer, rns);
    const nodeDest = await Destination.IN("rfed.node", DestType.SINGLE, nodeIdentity, rns);

    const p = discoverRfedNode({ rns, timeout: 2000 });
    // A non-rfed.node announce (rfed.channel.publish) must be filtered out…
    setTimeout(
      () => rns.transport.dispatchEvent(
        new CustomEvent("announce", {
          detail: {
            destinationHash: publishDest.destinationHash,
            identity: nodeIdentity,
            nameHash: publishDest.nameHash,
          },
        }),
      ),
      30,
    );
    // …and a dacar.node announce must also be filtered out…
    setTimeout(
      () => rns.transport.dispatchEvent(
        new CustomEvent("announce", {
          detail: {
            destinationHash: dacarDest.destinationHash,
            identity: dacarPeer,
            nameHash: dacarDest.nameHash,
          },
        }),
      ),
      60,
    );
    // …then the matching rfed.node announce resolves.
    setTimeout(
      () => rns.transport.dispatchEvent(
        new CustomEvent("announce", {
          detail: {
            destinationHash: nodeDest.destinationHash,
            identity: nodeIdentity,
            nameHash: nodeDest.nameHash,
          },
        }),
      ),
      90,
    );
    const got = await p;
    assert.deepEqual(got, nodeDest.destinationHash);
  });

  it("rejects after the timeout when no rfed.node announce arrives (does not hang)", async () => {
    const rns = new Reticulum({});
    const t0 = Date.now();
    await assert.rejects(
      () => discoverRfedNode({ rns, timeout: 300 }),
      /no rfed\.node announce received within 300ms/i,
    );
    // Resolves (via rejection) in ~300ms, not by hanging until killed.
    const elapsed = Date.now() - t0;
    assert.ok(elapsed >= 280 && elapsed < 1500, `timed out in ${elapsed}ms`);
  });

  it("removes its announce listener after resolving (no leak across runs)", async () => {
    const rns = new Reticulum({});
    const nodeIdentity = await Identity.generate();
    const nodeDest = await Destination.IN("rfed.node", DestType.SINGLE, nodeIdentity, rns);

    const dispatch = () => rns.transport.dispatchEvent(
      new CustomEvent("announce", {
        detail: {
          destinationHash: nodeDest.destinationHash,
          identity: nodeIdentity,
          nameHash: nodeDest.nameHash,
        },
      }),
    );

    const p = discoverRfedNode({ rns, timeout: 1000 });
    setTimeout(dispatch, 30);
    const got = await p;
    assert.deepEqual(got, nodeDest.destinationHash);
    // A second dispatch must not throw / double-resolve: the listener was removed.
    dispatch();
    // A new discovery call should start fresh (its own listener, own timeout).
    const p2 = discoverRfedNode({ rns, timeout: 200 });
    await assert.rejects(() => p2, /no rfed\.node announce received within 200ms/i);
  });

  it("throws when the transport has no announce event support", async () => {
    const rns = { transport: {} }; // no addEventListener
    await assert.rejects(
      () => discoverRfedNode({ rns, timeout: 50 }),
      /RNS transport not available for discovery/i,
    );
  });
});
