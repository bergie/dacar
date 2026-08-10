#!/usr/bin/env node
/**
 * `dacar` — offline-first CLI for managing Dacar authorization grants (work doc #6).
 *
 * Node/Deno-only. Declared in `package.json` `bin` and **excluded from the
 * browser `exports` map** so it never bloats a browser bundle. Composes the
 * portable {@link module:cli/session} + {@link module:cli/store} helpers with
 * `@reticulum/node`'s interfaces and `FileStorageAdapter`.
 *
 * Mirrors Python's `dacar/cli/__init__.py` + `commands.py`. Offline commands
 * never start RNS; online commands (`grant --publish`, `sync`) boot RNS, announce
 * the node identity, publish/pull, then exit — the one-shot, daemon-free model.
 *
 * Usage:
 *   dacar init
 *   dacar grant <grantee> <relation> <object> [--publish]
 *   dacar sync
 *   dacar check <grantee> <relation> <object>
 *   dacar grants
 *   dacar revoke <grantee> <relation> <object> [--publish]
 *   dacar identity remember|forget|list ...
 *
 * Online flags: --node <hash>, --topic <topic>, --interface shared|auto|tcp,
 * --rns-dir <path> (default: ~/.reticulum or $DACAR_RNS_DIR).
 */

import { parseArgs } from "node:util";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import process from "node:process";

import { Identity, toHex } from "@reticulum/core";
import { MemoryStorageAdapter } from "@reticulum/core";
import { FileStorageAdapter } from "@reticulum/node";
import { RFedClient } from "@reticulum/core/src/rfed/client.js";
import { bootRns } from "./rns_boot.js";

import { Action, Operation, Tuple, Engine } from "../index.js";
import { DeltaReceiver } from "../delta.js";
import { RnsIdentityResolver } from "../transport/rnsIdentity.js";
import { RFED_TOPIC, APP_NAME } from "../naming.js";
import { NamespaceHasher, DEFAULT_SALT, SALT_SIZE, HASH_SIZE } from "../namespace.js";
import { Keyring, IssuerKeyset } from "../verifier.js";

import { DacarStore, SELF_ALIAS, AliasRegistry } from "./store.js";
import { announceIdentity, discoverRfedNode, ensureNodeIdentity, runPublish, runSync, registerAnnounceHandler } from "./session.js";

const SHORT_HASH = 7;

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

function err(msg) {
  process.stderr.write(msg + "\n");
}

function shortHash(hash, full = false) {
  const hex = toHex(hash);
  return full ? hex : hex.slice(0, SHORT_HASH) + "…";
}

function out(msg) {
  process.stdout.write(msg + "\n");
}

class CliError extends Error {}

// ---------------------------------------------------------------------------
// Store + RNS resolution
// ---------------------------------------------------------------------------

function defaultStorePath() {
  return process.env.DACAR_HOME || join(homedir(), ".dacar");
}

async function openStore(args) {
  const path = args.store || defaultStorePath();
  const adapter = new FileStorageAdapter(path);
  return new DacarStore(adapter, { identityBytes: args.identity ? await readFile(args.identity) : null });
}

function resolveIdentityHash(value, aliases) {
  const fromAlias = aliases.resolve(value);
  if (fromAlias) return fromAlias;
  const clean = value.toLowerCase().replace(/^0x/, "");
  const raw = hexToBytes(clean);
  if (raw.length !== 16) {
    throw new CliError(`unknown identity ${JSON.stringify(value)} (not a known alias or 16-byte hex hash)`);
  }
  return raw;
}

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function resolveRnsConfigDir(args) {
  const explicit = args.rnsDir ?? process.env.DACAR_RNS_DIR;
  if (explicit) return explicit;
  const user = join(homedir(), ".reticulum");
  try {
    await readFile(join(user, "config"));
    return user;
  } catch {
    // fall through to store-local default
  }
  const storePath = args.store || defaultStorePath();
  const dir = join(storePath, "rns");
  await mkdir(dir, { recursive: true });
  const cfgPath = join(dir, "config");
  try {
    await readFile(cfgPath);
  } catch {
    await writeFile(
      cfgPath,
      "[reticulum]\n  share_instance = Yes\n  enable_transport = False\n\n" +
        "[interfaces]\n  [[Default interface]]\n    type = AutoInterface\n    enabled = Yes\n",
    );
  }
  return dir;
}

// `bootRns` lives in `./rns_boot.js` (Node-only): it constructs, **connects**,
// and default-attaches the chosen mesh interface, and optionally raises the
// Reticulum log threshold + logs each announce for `--verbose`. See
// `src/cli/rns_boot.js` for why `connect()` + `isDefault=true` are
// non-optional (the `--discover` silent-timeout symptom).

async function resolveRfedNode(args, store, aliases, rns) {
  if (args.node) return resolveIdentityHash(args.node, aliases);
  const raw = await store.loadConfig();
  if (raw.rfedNode) return raw.rfedNode;
  if (args.discover && rns) return discoverRfedNode({ rns, timeout: 30000 });
  throw new CliError("no rfed node configured (use --node <hash>, --discover, or set [rfed] node in config)");
}

async function resolveTopic(args, store) {
  if (args.topic) return args.topic;
  const raw = await store.loadConfig();
  return raw.rfedTopic || RFED_TOPIC;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdInit(args) {
  const path = args.store || defaultStorePath();
  await mkdir(path, { recursive: true });
  const adapter = new FileStorageAdapter(path);
  const store = await DacarStore.init(adapter, {
    salt: args.salt ? hexToBytes(args.salt) : undefined,
    horizonDays: parseInt(args.horizon || "180", 10),
    identityBytes: args.identity ? await readFile(args.identity) : undefined,
  });
  const identity = await store.loadIdentity();
  const aliases = await store.loadAliases();
  err("✔ initialized store at " + path);
  err("  identity : " + shortHash(identity.identityHash, args.fullHashes));
  err("  anchor   : " + shortHash(identity.identityHash, args.fullHashes) + " (self)");
  return 0;
}

async function cmdConfigShow(args) {
  const store = await openStore(args);
  const raw = await store.loadConfig();
  const aliases = await store.loadAliases();
  err("store: " + (args.store || defaultStorePath()));
  err("[salt]");
  err("  primary   : " + (args.reveal ? toHex(raw.primarySalt) : "<masked (use --reveal)>"));
  err("[trust]");
  for (const a of raw.anchors) err("  anchor    : " + shortHash(a, args.fullHashes));
  err("[policy]");
  err("  deletion_horizon_days : " + raw.horizonDays);
  err("[rfed]");
  err("  topic : " + raw.rfedTopic);
  err("  node  : " + (raw.rfedNode ? shortHash(raw.rfedNode, args.fullHashes) : "(not set)"));
  return 0;
}

async function cmdGrant(args) {
  return _issue(args, Action.GRANT);
}

async function cmdRevoke(args) {
  return _issue(args, Action.REVOKE);
}

async function _issue(args, action) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const aliases = await store.loadAliases();
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  const grantee = resolveIdentityHash(args.grantee, aliases);
  const hasher = config.primaryHasher;
  const tuple = await Tuple.fromPlaintext({
    objectId: args.object, relation: args.relation, grantee, issuer: identity.identityHash, hasher,
  });

  const clock = await store.loadClock();
  const hlc = clock.now();
  await store.saveClock(clock);

  const op = await new Operation({ tuple, action, hlc }).sign(identity);
  const payload = op.toPayload();

  const state = await store.loadState(config);
  state.apply(op);
  await store.saveState(state);

  // Record plaintext ledger.
  const ledger = await store.loadLedger();
  ledger.set(toHex(tuple.key), { object: args.object, relation: args.relation, wildcard: args.object.endsWith("*") && args.object !== "*", firstSeen: Number(hlc >> 16n) });
  await store.saveLedger(ledger);

  out(payload.hex());
  err(`✔ ${action === Action.GRANT ? "granted" : "revoked"} ${shortHash(grantee, args.fullHashes)}  ${args.relation}  on  ${args.object}`);
  err(`  hlc     : 0x${hlc.toString(16)}`);
  err(`  payload : hex on stdout (${payload.length} bytes)`);

  if (args.publish) {
    await publishDelta(args, store, identity, payload);
  }
  return 0;
}

async function publishDelta(args, store, identity, payload) {
  const aliases = await store.loadAliases();
  const topic = await resolveTopic(args, store);
  const configDir = await resolveRnsConfigDir(args);
  const rns = await bootRns(configDir, args.interface || "shared", {
    verbose: !!args.verbose,
  });
  // RNS must be booted before resolveRfedNode: --discover listens for peer
  // announces on the live transport (mirrors Python's _publish_delta).
  const nodeHash = await resolveRfedNode(args, store, aliases, rns);
  await announceIdentity(identity, rns);
  // Proactively fetch the rfed node's identity: when --node is given (or
  // --discover derived it), the destination's announce may not yet be in
  // the recall store. Send a path? request and wait for the announce rather
  // than failing with "wait for its announce" (work doc #6).
  await ensureNodeIdentity(rns, nodeHash, {
    onRequest: () => err("  requesting rfed node identity…"),
  });

  // Durable issuer cache (doc #5): seed from observed dacar.node announces.
  const keyring = await store.loadKeyring();
  keyring.registerSingle(identity.identityHash, await identity.getPublicKey());
  await registerAnnounceHandler({ rns, keyring, onSave: (kr) => store.saveKeyring(kr) });

  const client = new RFedClient({ identity, rns });
  await runPublish({ deltaPayload: payload, nodeHash, topic, client });
  await store.saveKeyring(keyring);
  err(`  published to rfed channel ${JSON.stringify(topic)} via ${shortHash(nodeHash, args.fullHashes)}`);
}

async function cmdSync(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const aliases = await store.loadAliases();
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  // RNS must be booted before discover if we're autodiscovering
  const configDir = await resolveRnsConfigDir(args);
  const rns = await bootRns(configDir, args.interface || "shared", {
    verbose: !!args.verbose,
  });
  await announceIdentity(identity, rns);

  // Durable issuer cache (doc #5): load persisted keyring + announce handler.
  const keyring = await store.loadKeyring();
  keyring.registerSingle(identity.identityHash, await identity.getPublicKey());
  await registerAnnounceHandler({ rns, keyring, onSave: (kr) => store.saveKeyring(kr) });

  const nodeHash = await resolveRfedNode(args, store, aliases, rns);
  // Proactively fetch the rfed node's identity: when --node is given (or
  // --discover derived it), the destination's announce may not yet be in
  // the recall store. Send a path? request and wait for the announce rather
  // than failing with "wait for its announce" (work doc #6).
  await ensureNodeIdentity(rns, nodeHash, {
    onRequest: () => err("  requesting rfed node identity…"),
  });
  const topic = await resolveTopic(args, store);
  const state = await store.loadState(config);
  const resolver = new RnsIdentityResolver(keyring);
  const rx = new DeltaReceiver(state, resolver);

  const client = new RFedClient({ identity, rns });
  const applied = await runSync({ nodeHash, topic, client, receiver: rx });
  await store.saveState(state);
  await store.saveKeyring(keyring);

  err(`✔ synced: applied ${applied} delta(s) from rfed channel ${JSON.stringify(topic)}`);
  return 0;
}

async function cmdCheck(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const aliases = await store.loadAliases();
  const engine = new Engine(config, state);
  const grantee = resolveIdentityHash(args.grantee, aliases);
  const allowed = await engine.evaluate(args.object, args.relation, grantee);
  const mark = allowed ? "✔" : "✘";
  err(`${mark} ${allowed ? "ALLOW" : "DENY"} ${shortHash(grantee, args.fullHashes)}  ${args.relation}  ${args.object}`);
  return allowed ? 0 : 1;
}

async function cmdApply(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const keyring = await store.keyringForVerify();
  const rx = new DeltaReceiver(state, keyring);
  const data = args.payload === "-"
    ? new Uint8Array(await readStdin())
    : await readFile(args.payload);
  const applied = await rx.applyPayload(data);
  if (applied) {
    await store.saveState(state);
    err(`✔ applied 1 delta`);
    return 0;
  }
  err("✘ delta rejected (unknown issuer, bad signature, stale §9, or malformed)");
  return 1;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------------------
// identity remember / forget / list (work doc #5)
// ---------------------------------------------------------------------------

async function cmdIdentityRemember(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const issuerHash = resolveIdentityHash(args.hash, aliases);

  let pubKey;
  if (args.pubkey) {
    pubKey = hexToBytes(args.pubkey);
    if (pubKey.length !== 64) throw new CliError(`--pubkey must be 64 bytes (128 hex), got ${pubKey.length}`);
  } else if (args.file) {
    pubKey = await readFile(args.file);
    if (pubKey.length !== 64) throw new CliError(`pubkey file must contain 64 bytes, got ${pubKey.length}`);
  } else {
    // Boot RNS and try to recall.
    const configDir = await resolveRnsConfigDir(args);
    const rns = await bootRns(configDir, args.interface || "shared", {
      verbose: !!args.verbose,
    });
    const { Destination } = await import("@reticulum/core");
    const recalled = await Destination.recall(issuerHash, true);
    if (!recalled) {
      throw new CliError(
        `could not recall ${shortHash(issuerHash, args.fullHashes)} from RNS; use --pubkey <hex> or --file <path>`,
      );
    }
    pubKey = await recalled.getPublicKey();
  }

  const keyring = await store.loadKeyring();
  keyring.registerSingle(issuerHash, pubKey);
  await store.saveKeyring(keyring);
  err(`✔ remembered issuer ${shortHash(issuerHash, args.fullHashes)}`);
  err(`  pubkey : ${toHex(pubKey).slice(0, SHORT_HASH)}…`);
  err(`  cache  : ${keyring.size} entries`);
  return 0;
}

async function cmdIdentityForget(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const issuerHash = resolveIdentityHash(args.hash, aliases);

  if (!args.force) {
    // Refuse to purge an issuer with active grants in the live CRDT.
    const config = await store.loadConfigValidated();
    const state = await store.loadState(config);
    let active = 0;
    for (const tuple of state.activeTuples()) {
      if (toHex(tuple.issuer) === toHex(issuerHash)) active++;
    }
    if (active > 0) {
      throw new CliError(
        `issuer ${shortHash(issuerHash, args.fullHashes)} has ${active} active grant(s) in the live CRDT; ` +
          "forgetting it would make its revokes unverifiable (use --force to override)",
      );
    }
  }

  const keyring = await store.loadKeyring();
  if (!keyring.forget(issuerHash)) {
    throw new CliError(`issuer ${shortHash(issuerHash, args.fullHashes)} not in the cache`);
  }
  await store.saveKeyring(keyring);
  err(`✔ forgot issuer ${shortHash(issuerHash, args.fullHashes)}`);
  err(`  cache : ${keyring.size} entries`);
  return 0;
}

async function cmdIdentityList(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const keyring = await store.loadKeyring();
  err(`ISSUER IDENTITY CACHE (${keyring.size})`);
  if (keyring.size === 0) {
    err("(none — use `dacar identity remember <hash>` to seed)");
    return 0;
  }
  for (const [hashHex, keyset] of keyring.entries()) {
    const pub = keyset.memberPublicKeys[0];
    err(`  ${shortHash(hexToBytes(hashHex), args.fullHashes)}  pubkey=${toHex(pub).slice(0, SHORT_HASH)}…`);
  }
  return 0;
}

async function cmdGrants(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const aliases = await store.loadAliases();
  const ledger = await store.loadLedger();
  /** @type {any[]} */ const rows = [];
  for (const entry of state._entries.values()) {
    const active = entry.addTs !== null && (entry.removeTs === null || entry.addTs > entry.removeTs);
    if (args.revoked && active) continue;
    if (!args.all && !args.revoked && !active) continue;
    rows.push({ entry, active });
  }
  const label = args.revoked ? "REVOKED TOMBSTONES" : args.all ? "ALL TUPLES" : "ACTIVE GRANTS";
  err(`${label} (${rows.length})`);
  for (const { entry, active } of rows) {
    const t = entry.tuple;
    const row = ledger.get(toHex(t.key));
    const rel = row?.relation || `[${shortHash(t.relationHash, args.fullHashes)}]`;
    const obj = row?.object || "[hash]";
    err(
      `${shortHash(t.grantee, args.fullHashes)}  ${rel}  ${obj}  ← ${shortHash(t.issuer, args.fullHashes)}  ` +
        `${active ? "active" : "revoked"}`,
    );
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const SUBCOMMANDS = {
  init: { run: cmdInit, opts: { salt: "string", horizon: "string" }, online: false },
  "config": {
    sub: {
      show: { run: cmdConfigShow, opts: { reveal: "boolean" }, online: false },
    },
  },
  grant: {
    run: cmdGrant,
    opts: { publish: "boolean", node: "string", discover: "boolean", topic: "string", "rns-dir": "string", interface: "string" },
    positional: ["grantee", "relation", "object"],
    online: true,
  },
  revoke: {
    run: cmdRevoke,
    opts: { publish: "boolean", node: "string", discover: "boolean", topic: "string", "rns-dir": "string", interface: "string" },
    positional: ["grantee", "relation", "object"],
    online: true,
  },
  sync: {
    run: cmdSync,
    opts: { node: "string", discover: "boolean", topic: "string", "rns-dir": "string", interface: "string" },
    online: true,
  },
  apply: { run: cmdApply, opts: { binary: "boolean" }, positional: ["payload"], online: false },
  check: { run: cmdCheck, opts: {}, positional: ["grantee", "relation", "object"], online: false },
  grants: { run: cmdGrants, opts: { all: "boolean", revoked: "boolean" }, online: false },
  identity: {
    sub: {
      remember: {
        run: cmdIdentityRemember,
        opts: { pubkey: "string", file: "string", "rns-dir": "string", interface: "string", force: "boolean" },
        positional: ["hash"],
        online: true,
      },
      forget: { run: cmdIdentityForget, opts: { force: "boolean" }, positional: ["hash"], online: false },
      list: { run: cmdIdentityList, opts: {}, online: false },
    },
  },
};

function buildOptions(spec) {
  const opts = {};
  for (const [k, t] of Object.entries(spec.opts || {})) {
    opts[k] = { type: t };
  }
  // --verbose / -v is global: accepted by every (sub)command so it never
  // errors out, and threaded into bootRns to raise the Reticulum log
  // threshold + log interface/announce diagnostics.
  opts.verbose = { type: "boolean", short: "v" };
  if (spec.positional && spec.positional.length) {
    opts.store = { type: "string" };
    opts.identity = { type: "string" };
    opts["full-hashes"] = { type: "boolean" };
  }
  return opts;
}

async function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    err(`usage: dacar <command> [options]\n\ncommands: ${Object.keys(SUBCOMMANDS).join(", ")}\n\nGlobal options: --store <path>, --identity <hex|path>, --full-hashes, -v/--verbose`);
    return 0;
  }
  const argv = process.argv.slice(2);
  const [cmd, ...rest] = argv;
  const spec = SUBCOMMANDS[cmd];
  if (!spec) {
    err(`usage: dacar <command> [options]\ncommands: ${Object.keys(SUBCOMMANDS).join(", ")}`);
    return 1;
  }
  // Subcommand dispatch (config show, identity remember/forget/list).
  if (spec.sub) {
    const [sub, ...subrest] = rest;
    const subspec = spec.sub[sub];
    if (!subspec) {
      err(`usage: dacar ${cmd} <subcommand>\nsubcommands: ${Object.keys(spec.sub).join(", ")}`);
      return 1;
    }
    const { values, positionals } = parseArgs({
      args: subrest,
      options: buildOptions(subspec),
      allowPositionals: true,
    });
    values.fullHashes = values["full-hashes"];
    try {
      return await subspec.run({ ...values, _positionals: positionals, ...Object.fromEntries(positionals.map((v, i) => [subspec.positional?.[i] ?? `_p${i}`, v])) });
    } catch (e) {
      if (e instanceof CliError) { err("error: " + e.message); return 1; }
      throw e;
    }
  }
  // Top-level command.
  const { values, positionals } = parseArgs({
    args: rest,
    options: buildOptions(spec),
    allowPositionals: true,
  });
  values.fullHashes = values["full-hashes"];
  try {
    return await spec.run({ ...values, _positionals: positionals, ...Object.fromEntries(positionals.map((v, i) => [spec.positional?.[i] ?? `_p${i}`, v])) });
  } catch (e) {
    if (e instanceof CliError) { err("error: " + e.message); return 1; }
    throw e;
  }
}

main().then((code) => process.exit(code ?? 0)).catch((e) => {
  err("fatal: " + (e?.stack || e));
  process.exit(1);
});
