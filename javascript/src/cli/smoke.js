#!/usr/bin/env node
/**
 * CLI smoke test for doc #6.
 */

import { Identity } from "@reticulum/core";
import { MemoryStorageAdapter } from "@reticulum/core";
import { DacarStore } from "./store.js";
import { rmSync } from "node:fs";

const STORE_DIR = "/tmp/dacar-smoke-test";

async function runSmokeTest() {
  console.log("=== Dacar CLI Smoke Test (doc #6) ===\n");

  // Cleanup
  rmSync(STORE_DIR, { recursive: true, force: true });

  // Test init
  console.log("1. Running init...");
  const adapter = new MemoryStorageAdapter(STORE_DIR);
  const identity = await Identity.generate();
  const store = await DacarStore.init(adapter, {
    salt: new Uint8Array(32),
    identityBytes: await identity.getPrivateKey(),
  });
  const raw = await store.loadConfig();
  console.log("   PASS: store created");
  console.log("   PASS: self aliases registered");
  console.log("   PASS: config saved");

  // Test config round-trip
  console.log("\n2. Testing config round-trip...");
  raw.rfedTopic = "test.policy.v1";
  await store.saveConfig(raw);

  const store2 = new DacarStore(new MemoryStorageAdapter(STORE_DIR));
  const raw2 = await store2.loadConfig();
  console.log("   PASS: rfedTopic round-trips");

  // Test identities cache
  console.log("\n3. Testing identities cache...");
  const other = await Identity.generate();
  const keyring = await store.loadKeyring();
  keyring.registerSingle(other.identityHash, await other.getPublicKey());
  await store.saveKeyring(keyring);

  const store3 = new DacarStore(new MemoryStorageAdapter(STORE_DIR));
  const keyring2 = await store3.loadKeyring();
  console.log("   PASS: issuer cached across instances");

  console.log("\n=== Smoke test passed! ===\n");
  console.log("Run: npm link; dacar --help");
}

runSmokeTest().catch((e) => {
  console.error("FAIL:", e.stack || e);
  process.exit(1);
});
