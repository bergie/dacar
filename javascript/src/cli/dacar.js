#!/usr/bin/env node
/**
 * `dacar` — offline-first CLI for managing Dacar authorization grants (work doc #6).
 *
 * Node/Deno-only. Declared in `package.json` `bin` and **excluded from the
 * browser `exports` map** so it never bloats a browser bundle. Composes the
 * portable {@link module:cli/session} + {@link module:cli/store} helpers with
 * `@reticulum/node`'s interfaces and `DacarFileAdapter` (Python-parity layout).
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
 *   dacar publish <file> [<file>...] | --outbox | --sent | --all   (docs #8/#11)
 *   dacar identity remember|forget|list ...
 *
 * Online flags: --node <hash>, --topic <topic>, --interface shared|auto|tcp,
 * --rns-dir <path> (default: ~/.reticulum or $DACAR_RNS_DIR).
 */

import { parseArgs } from "node:util";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import process from "node:process";

import { Identity, toHex } from "@reticulum/core";
import { MemoryStorageAdapter } from "@reticulum/core";
import { DacarFileAdapter } from "./fileStore.js";
import { RFedClient } from "@reticulum/rfed";
import { bootRns } from "./rns_boot.js";

import { Action, Operation, Tuple, Engine } from "../index.js";
import { DeltaReceiver } from "../delta.js";
import { RnsIdentityResolver } from "../transport/rnsIdentity.js";
import { RFED_TOPIC, APP_NAME } from "../naming.js";
import { NamespaceHasher, DEFAULT_SALT, SALT_SIZE, HASH_SIZE } from "../namespace.js";
import { Keyring, IssuerKeyset } from "../verifier.js";

import { DacarStore, SELF_ALIAS, AliasRegistry } from "./store.js";
import {
  announceIdentity, discoverRfedNode, ensureNodeIdentity, runPublishMany, runSync,
  registerAnnounceHandler, bootLxmfRouter, lxmfOutDestination, runLxmfPublish, runLxmfSync,
} from "./session.js";
import { LxmfDeltaDelivery, packPaperUris } from "../transport/lxmfSync.js";

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
  const adapter = new DacarFileAdapter(path);
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

/**
 * Normalize an issuer public key to the 64-byte RNS form (X25519 ‖ Ed25519)
 * used by `IssuerKeyset`. Accepts the canonical 32-byte Ed25519 public key
 * (Python parity) — padding the unused X25519 half with zeros — or a full
 * 64-byte RNS public key as-is.
 * @param {Uint8Array} pubKey 32-byte Ed25519 or 64-byte RNS public key.
 * @returns {Uint8Array}
 */
function asRnsPubKey(pubKey) {
  if (pubKey.length === 32) {
    const padded = new Uint8Array(64);
    padded.set(pubKey, 32);
    return padded;
  }
  if (pubKey.length === 64) return pubKey;
  throw new CliError(`pubkey must be 32 bytes (64 hex, Ed25519) or 64 bytes (128 hex, RNS), got ${pubKey.length}`);
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

/**
 * Resolve the LXMF proprietor (propagation node) from `--proprietor` or the
 * `[lxmf] proprietor` config (§11.2, work doc #14) — the store-and-forward
 * queue both send legs (outbound propagation) and the receive leg (sync)
 * talk to. Returns `null` when unconfigured.
 * @param {any} args
 * @param {DacarStore} store
 * @param {AliasRegistry} aliases
 * @returns {Promise<Uint8Array | null>}
 */
async function resolveLxmfProprietor(args, store, aliases) {
  if (args.proprietor) return resolveIdentityHash(args.proprietor, aliases);
  const raw = await store.loadConfig();
  return raw.lxmfProprietor ?? null;
}

/**
 * Resolve the recipient `lxmf.delivery` hash from `--lxmf <hash|alias>`.
 * @param {any} args
 * @param {DacarStore} store
 * @param {AliasRegistry} aliases
 * @returns {Promise<Uint8Array>}
 */
async function resolveLxmfTarget(args, store, aliases) {
  if (!args.lxmf) throw new CliError("no LXMF target given (use --lxmf <hash|alias>)");
  return resolveIdentityHash(args.lxmf, aliases);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdInit(args) {
  const path = args.store || defaultStorePath();
  await mkdir(path, { recursive: true });
  const adapter = new DacarFileAdapter(path);
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
  err("[lxmf]");
  err("  proprietor : " + (raw.lxmfProprietor ? shortHash(raw.lxmfProprietor, args.fullHashes) : "(not set)"));
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
  ledger.set(toHex(await tuple.hash()), { object: args.object, relation: args.relation, wildcard: args.object.endsWith("*") && args.object !== "*", firstSeen: Number(hlc >> 16n) });
  await store.saveLedger(ledger);

  out(toHex(payload));
  err(`✔ ${action === Action.GRANT ? "granted" : "revoked"} ${shortHash(grantee, args.fullHashes)}  ${args.relation}  on  ${args.object}`);
  err(`  hlc     : 0x${hlc.toString(16)}`);
  err(`  payload : hex on stdout (${payload.length} bytes)`);

  if (args.publish || args.lxmf) {
    // Durability (work doc #11): enqueue the signed payload to the outbox
    // *before* the risky network send, so it survives a crash or failed
    // transport and can be retried via `publish --outbox`. On send it moves
    // outbox → sent box (the durable replay log), so every issued Delta lands
    // in the durable log and can be re-sent to new peers.
    const ob = await store.loadOutbox();
    ob.push(payload);
    await store.saveOutbox(ob);
    let accepted;
    if (args.lxmf) {
      // --lxmf (§11.2, work doc #14): targeted delivery to one recipient via
      // the proprietor. With --publish *both* transports run (rfed broadcast
      // + targeted LXMF); alone, --lxmf is LXMF-only.
      accepted = await publishDeltaLxmf(args, store, identity, [payload]);
      await recordPublish(store, [payload], accepted, { recordToSent: true });
      if (args.publish) {
        accepted = await publishDelta(args, store, identity, [payload]);
        await recordPublish(store, [payload], accepted, { recordToSent: true });
      }
    } else {
      accepted = await publishDelta(args, store, identity, [payload]);
      await recordPublish(store, [payload], accepted, { recordToSent: true });
    }
    if (accepted[0]) {
      err("  (published + logged to sent box)");
    } else {
      err("  (send failed; retained in outbox for retry)");
    }
  } else {
    // Outbox (work doc #8): queue locally-issued deltas for `publish --outbox`.
    // (JS `grant` always applies locally — there is no `--no-apply` — so every
    // non-publish grant is a candidate for later batch publish.)
    const outbox = await store.loadOutbox();
    outbox.push(payload);
    await store.saveOutbox(outbox);
    err("  (queued in outbox: `dacar publish --outbox` to flush)");
  }
  return 0;
}

async function publishDelta(args, store, identity, payloads) {
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
  // Publish each Delta as its own compact inner-format message (§11.1.1) —
  // one §5.3 Operation per envelope, never a multi-delta batch (the publish
  // destination is fire-and-forget and capped by the ~500-byte path MTU).
  // RNS is a singleton, so boot + subscribe happen once for the whole batch.
  const accepted = await runPublishMany({
    deltaPayloads: payloads, nodeHash, topic, client, rns,
  });
  await store.saveKeyring(keyring);
  const total = payloads.length;
  const sent = accepted.filter((ok) => ok).length;
  if (sent < total) {
    err(`  ⚠ only ${sent}/${total} delta(s) accepted by the transport ` +
      "(fire-and-forget: node storage is not confirmed)");
  }
  err(`  sent ${sent}/${total} delta(s) to rfed channel ${JSON.stringify(topic)} via ${shortHash(nodeHash, args.fullHashes)}`);
  return accepted;
}

/**
 * Online LXMF delivery hook for the `--lxmf` paths (§11.2, work doc #14) —
 * the sibling of `publishDelta` and the seam tests patch with a fake router.
 *
 * Boots RNS once, announces the node identity (the announce invariant is
 * *load-bearing* for LXMF: receiving nodes recall the issuer from the
 * announce store, §11.2.4), seeds the durable keyring, then pushes the
 * Deltas to one recipient via the proprietor (PROPAGATED, store-and-forward;
 * `--direct` opts into opportunistic direct delivery). Multi-Delta sends
 * batch into as few messages as possible. Returns per-Delta acceptance flags
 * for `recordPublish` (work doc #11 — same outbox → sent lifecycle regardless
 * of transport).
 */
async function publishDeltaLxmf(args, store, identity, payloads) {
  const aliases = await store.loadAliases();
  const configDir = await resolveRnsConfigDir(args);
  const rns = await bootRns(configDir, args.interface || "shared", {
    verbose: !!args.verbose,
  });
  await announceIdentity(identity, rns);

  const keyring = await store.loadKeyring();
  keyring.registerSingle(identity.identityHash, await identity.getPublicKey());
  await registerAnnounceHandler({ rns, keyring, onSave: (kr) => store.saveKeyring(kr) });
  await store.saveKeyring(keyring);

  const target = await resolveLxmfTarget(args, store, aliases);
  const proprietor = await resolveLxmfProprietor(args, store, aliases);
  const router = await bootLxmfRouter({ identity, rns });
  const delivery = new LxmfDeltaDelivery();
  const { accepted, messages } = await runLxmfPublish({
    payloads,
    targetHash: target,
    proprietor,
    router,
    delivery,
    identity,
    direct: !!args.direct,
  });
  const total = payloads.length;
  const sent = accepted.filter((ok) => ok).length;
  const method = args.direct ? "direct link" : "proprietor";
  err(`  sent ${sent}/${total} delta(s) in ${messages} LXMF message(s) via ${method} to ${shortHash(target, args.fullHashes)}`);
  if (sent < total) {
    err("  ⚠ failed delta(s) retained in the outbox for retry (`dacar publish --outbox`)");
  }
  return accepted;
}

/**
 * Update the outbox + sent box after a publish attempt (work doc #11).
 *
 * - Remove every transport-accepted payload from the **outbox** (it has been
 *   sent, so it leaves the unsent queue).
 * - If `recordToSent`, append transport-accepted payloads to the **sent box**
 *   (the durable replay log), deduplicating by exact bytes. Re-sends from the
 *   sent box (`publish --sent`) are already present, so this is a no-op for them.
 *
 * Returns the number of accepted deltas. Pure store logic (no RNS) so it runs
 * even when `publishDelta` is patched in tests.
 * @param {import("./store.js").DacarStore} store
 * @param {Uint8Array[]} payloads
 * @param {boolean[]} accepted Per-delta transport acceptance.
 * @param {Object} opts
 * @param {boolean} opts.recordToSent
 * @returns {Promise<number>}
 */
async function recordPublish(store, payloads, accepted, { recordToSent }) {
  /** @type {Uint8Array[]} */
  const acceptedBytes = [];
  for (let i = 0; i < payloads.length; i++) {
    if (accepted[i]) acceptedBytes.push(new Uint8Array(payloads[i]));
  }
  if (!acceptedBytes.length) return 0;
  // Drain accepted deltas from the outbox (they've been sent).
  const outbox = await store.loadOutbox();
  if (outbox.length) {
    const accSet = new Set(acceptedBytes.map((p) => toHex(p)));
    const newOutbox = outbox.filter((p) => !accSet.has(toHex(p)));
    if (newOutbox.length !== outbox.length) {
      await store.saveOutbox(newOutbox);
    }
  }
  // Append to the sent box (dedup by exact bytes, preserve order).
  if (recordToSent) {
    const sent = await store.loadSent();
    const existing = new Set(sent.map((p) => toHex(p)));
    let changed = false;
    for (const p of acceptedBytes) {
      const h = toHex(p);
      if (!existing.has(h)) {
        sent.push(p);
        existing.add(h);
        changed = true;
      }
    }
    if (changed) await store.saveSent(sent);
  }
  return acceptedBytes.length;
}

async function cmdSync(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const aliases = await store.loadAliases();
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  // LXMF leg resolution (work doc #14): runs when a proprietor is configured
  // or forced with --lxmf (needs --proprietor / [lxmf] proprietor config);
  // --no-lxmf disables. Auto-when-configured resolves doc #4's open item.
  const lxmfProprietor = args["no-lxmf"]
    ? null
    : await resolveLxmfProprietor(args, store, aliases);
  if (args.lxmf && !lxmfProprietor) {
    throw new CliError(
      "--lxmf given but no proprietor configured " +
        "(use --proprietor <hash> or set [lxmf] proprietor in config)",
    );
  }

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

  // rfed leg. Optional when the LXMF leg is available (an LXMF-only
  // deployment has no rfed node); otherwise the unresolvable node is the
  // error it always was.
  let nodeHash = null;
  try {
    nodeHash = await resolveRfedNode(args, store, aliases, rns);
  } catch (e) {
    if (!lxmfProprietor) throw e;
    err("  (no rfed node configured — rfed leg skipped, LXMF only)");
  }

  const state = await store.loadState(config);
  const resolver = new RnsIdentityResolver(rns, keyring);
  const rx = new DeltaReceiver(state, resolver);

  let applied = 0;
  let topic = null;
  if (nodeHash) {
    // Proactively fetch the rfed node's identity: when --node is given (or
    // --discover derived it), the destination's announce may not yet be in
    // the recall store. Send a path? request and wait for the announce rather
    // than failing with "wait for its announce" (work doc #6).
    await ensureNodeIdentity(rns, nodeHash, {
      onRequest: () => err("  requesting rfed node identity…"),
    });
    topic = await resolveTopic(args, store);
    const client = new RFedClient({ identity, rns });
    applied = await runSync({ nodeHash, topic, client, receiver: rx, rns });
  }

  // LXMF leg (§11.2.3 wake → pull → decrypt → apply, work doc #14).
  if (lxmfProprietor) {
    const router = await bootLxmfRouter({ identity, rns });
    const delivery = new LxmfDeltaDelivery({ receiver: rx });
    let appliedLxmf = 0;
    try {
      appliedLxmf = await runLxmfSync({ identity, proprietor: lxmfProprietor, router, delivery });
    } catch (e) {
      err(`  ⚠ LXMF sync failed: ${e?.message ?? e}`);
    }
    applied += appliedLxmf;
    err(`  LXMF: ${appliedLxmf} delta(s) applied from proprietor`);
  }

  await store.saveState(state);
  await store.saveKeyring(keyring);

  err(
    "✔ synced: applied " + applied + " delta(s)" +
      (topic !== null ? ` from rfed channel ${JSON.stringify(topic)}` : "")
  );
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

/**
 * Read a payload file (or stdin) and auto-detect hex (mirrors Python's
 * `_read_payload_input`): an all-hex, even-length ASCII blob decodes to bytes.
 * `--binary` forces raw bytes.
 * @param {string} path
 * @param {boolean} forceBinary
 * @returns {Promise<Uint8Array>}
 */
async function readPayloadInput(path, forceBinary) {
  const data = path === "-" ? new Uint8Array(await readStdin()) : await readFile(path);
  return coercePayload(data, forceBinary);
}

/**
 * Auto-detect a hex payload: if *all* bytes are ASCII hex characters (after
 * trimming surrounding whitespace) and the length is even, decode to bytes;
 * otherwise return the raw bytes unchanged.
 * @param {Uint8Array | Buffer} data
 * @param {boolean} forceBinary
 * @returns {Uint8Array}
 */
function coercePayload(data, forceBinary) {
  const bytes = new Uint8Array(data);
  if (forceBinary || !bytes.length) return bytes;
  let s;
  try {
    s = Buffer.from(bytes).toString("ascii");
  } catch {
    return bytes; // not ASCII -> raw bytes
  }
  const trimmed = s.trim();
  if (!trimmed || trimmed.length % 2 !== 0) return bytes;
  if (!/^[0-9a-fA-F]+$/.test(trimmed)) return bytes;
  return hexToBytes(trimmed);
}

export { coercePayload, recordPublish };

// ---------------------------------------------------------------------------
// paper messages (§11.3, work doc #14)
// ---------------------------------------------------------------------------

/**
 * Select the Delta payload(s) a `paper export` packs (work doc #14).
 * `--payload` (hex string or file) takes precedence; then the store flags
 * `--outbox`/`--sent`/`--all`; the default is the newest outbox Delta, falling
 * back to the newest sent ("re-deliver this one grant to an air-gapped
 * node"). Deduplicated by exact bytes, first-seen order preserved.
 * @param {any} args
 * @param {DacarStore} store
 * @returns {Promise<Uint8Array[]>}
 */
async function paperSourcePayloads(args, store) {
  if (args.payload) {
    const data = await readPayloadInput(String(args.payload), !!args.binary);
    if (!data.length) throw new CliError(`empty payload: ${args.payload}`);
    return [data];
  }
  const outbox = (await store.loadOutbox()).map((p) => new Uint8Array(p));
  const sent = (await store.loadSent()).map((p) => new Uint8Array(p));
  let selected;
  if (args.all) selected = [...outbox, ...sent];
  else if (args.outbox) selected = outbox;
  else if (args.sent) selected = sent;
  else selected = (outbox.length ? outbox : sent).slice(-1);
  if (!selected.length) {
    throw new CliError("nothing to export (outbox/sent empty; use --payload <hex|file>)");
  }
  const seen = new Set();
  /** @type {Uint8Array[]} */
  const deduped = [];
  for (const p of selected) {
    const h = toHex(p);
    if (!seen.has(h)) {
      seen.add(h);
      deduped.push(p);
    }
  }
  return deduped;
}

/**
 * SHA-256 hex digest helper (WebCrypto — portable across Node/Deno/Bun).
 * @param {Uint8Array} data
 * @returns {Promise<string>}
 */
async function sha256Hex(data) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(digest));
}

/**
 * Build the advisory completeness manifest for a paper export (work doc #14).
 * Unsigned by design: a tampered manifest can at worst report false-missing,
 * never false-accept — every Delta passes per-element Ed25519 verify-on-ingest
 * regardless. Digests key on the exact signed bytes (Python-parity JSON).
 * @param {Uint8Array[]} payloads
 * @param {Uint8Array} target
 * @param {number} chunks
 */
async function paperManifest(payloads, target, chunks) {
  const digests = [];
  for (const p of payloads) digests.push(await sha256Hex(p));
  const setDigest = await sha256Hex(
    payloads.reduce((acc, p) => {
      const next = new Uint8Array(acc.length + p.length);
      next.set(acc); next.set(p, acc.length);
      return next;
    }, new Uint8Array(0)),
  );
  return {
    version: 1,
    target: toHex(target),
    chunks,
    delta_count: payloads.length,
    delta_digests: digests,
    set_digest: setDigest,
  };
}

/**
 * `dacar paper export` — pack Delta(s) as §11.3 Paper Message URI(s).
 *
 * Emits one `lxm://` URI per paper message (greedy batch packing up to the
 * paper MDU; a larger set spills to several URIs — unordered, independently
 * verifiable chunks). URIs go to stdout (one per line), `--file` collects them
 * into one artifact, or `--out-dir` writes `chunk-NNN.txt` per QR.
 * `--manifest` writes the advisory completeness JSON sidecar. QR rendering
 * itself is out of scope — any QR tool handles the URI.
 */
async function cmdPaperExport(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  const payloads = await paperSourcePayloads(args, store);
  const target = resolveIdentityHash(args.target, aliases);

  const configDir = await resolveRnsConfigDir(args);
  const rns = await bootRns(configDir, args.interface || "shared", {
    verbose: !!args.verbose,
  });
  const outboundDestination = await lxmfOutDestination(rns, target);
  const delivery = new LxmfDeltaDelivery();

  /** @type {string[]} */
  let uris;
  if (payloads.length === 1) {
    uris = [await delivery.makePaperUri(payloads[0], target, { sourceIdentity: identity, outboundDestination })];
  } else {
    try {
      uris = await packPaperUris(payloads, target, { sourceIdentity: identity, outboundDestination });
    } catch (e) {
      if (e instanceof TypeError) throw new CliError(`paper export: ${e.message}`);
      throw e;
    }
  }

  if (args["out-dir"]) {
    const outDir = String(args["out-dir"]);
    await mkdir(outDir, { recursive: true });
    for (let i = 0; i < uris.length; i++) {
      await writeFile(join(outDir, `chunk-${String(i + 1).padStart(3, "0")}.txt`), uris[i] + "\n");
    }
    err(`  wrote ${uris.length} chunk file(s) to ${outDir}`);
  } else if (args.file) {
    await writeFile(String(args.file), uris.join("\n") + "\n");
    err(`  wrote ${uris.length} URI(s) to ${args.file}`);
  } else {
    for (const uri of uris) out(uri);
  }

  const manifest = await paperManifest(payloads, target, uris.length);
  if (args.manifest) {
    await writeFile(String(args.manifest), JSON.stringify(manifest, null, 2) + "\n");
  }
  err(
    `✔ exported ${payloads.length} delta(s) as ${uris.length} paper message(s) to ` +
      shortHash(target, args.fullHashes) +
      (args.manifest ? ` (manifest: ${args.manifest})` : "")
  );
  return 0;
}

/**
 * `dacar paper import` — apply scanned Paper Message URI(s) (§11.3).
 *
 * Accepts `lxm://` URI strings, files containing newline-separated URIs (as
 * emitted by `paper export --file`/`--out-dir`), or `-` for stdin. Chunks are
 * unordered and idempotent (CRDT merge); every decrypted payload passes
 * verify-on-ingest exactly like any other transport. `--manifest` checks
 * advisory completeness. This node must own the delivery identity the export
 * targeted.
 */
async function cmdPaperImport(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  /** @type {string[]} */
  const uris = [];
  for (const item of args._positionals ?? []) {
    if (item === "-") {
      uris.push(...(await readStdin()).toString().split("\n"));
    } else if (String(item).toLowerCase().startsWith("lxm://")) {
      uris.push(String(item).trim());
    } else {
      uris.push(...(await readFile(String(item))).toString().split("\n"));
    }
  }
  const clean = uris.map((u) => u.trim()).filter((u) => u && !u.startsWith("#"));
  if (!clean.length) {
    throw new CliError("no lxm:// URIs given (pass URIs, files, or - for stdin)");
  }

  const configDir = await resolveRnsConfigDir(args);
  const rns = await bootRns(configDir, args.interface || "shared", {
    verbose: !!args.verbose,
  });
  const keyring = await store.loadKeyring();
  keyring.registerSingle(identity.identityHash, await identity.getPublicKey());
  const state = await store.loadState(config);
  const resolver = new RnsIdentityResolver(rns, keyring);
  const rx = new DeltaReceiver(state, resolver);

  // Record the exact bytes that applied so the manifest check can tell
  // applied from missing (verify-on-ingest is untouched — this only observes).
  /** @type {Uint8Array[]} */
  const appliedPayloads = [];
  const innerApply = rx.applyPayload.bind(rx);
  rx.applyPayload = async (/** @type {Uint8Array} */ payload, /** @type {any} */ opts) => {
    const ok = await innerApply(payload, opts);
    if (ok) appliedPayloads.push(new Uint8Array(payload));
    return ok;
  };

  const router = await bootLxmfRouter({ identity, rns });
  const delivery = new LxmfDeltaDelivery({ receiver: rx });
  // EventTarget dispatch is synchronous but the listener is async (crypto,
  // verify-on-ingest) — track in-flight work so the applied count is final
  // before the manifest check reports.
  /** @type {Set<Promise<void>>} */
  const inflight = new Set();
  /** @param {Event & { detail?: { message?: unknown } }} event */
  const onMessage = (event) => {
    const message = /** @type {any} */ (event).detail?.message;
    if (!message) return;
    const p = (async () => { await delivery.handleMessage(message); })();
    inflight.add(p);
    p.finally(() => inflight.delete(p));
  };
  router.addEventListener("message", onMessage);

  let ingested = 0;
  for (const uri of clean) {
    try {
      const result = await delivery.ingestPaperUri(uri);
      if (result) ingested += 1;
    } catch {
      err(`  ⚠ skipping invalid URI: ${uri.slice(0, 64)}…`);
    }
  }
  while (inflight.size) await Promise.all([...inflight]);
  router.removeEventListener("message", onMessage);

  if (appliedPayloads.length) await store.saveState(state);
  await store.saveKeyring(keyring);

  err(
    `✔ imported ${appliedPayloads.length} delta(s) from ${ingested}/${clean.length} paper message(s)`
  );

  if (args.manifest) {
    const manifest = JSON.parse((await readFile(String(args.manifest))).toString());
    const appliedDigests = new Set();
    for (const p of appliedPayloads) appliedDigests.add(await sha256Hex(p));
    const missing = (manifest.delta_digests ?? []).filter((/** @type {string} */ d) => !appliedDigests.has(d));
    if (missing.length) {
      err(
        `  ⚠ manifest: ${missing.length} of ${manifest.delta_count ?? "?"} ` +
          "delta(s) missing — scan/import the remaining chunk(s)"
      );
    } else {
      err("  manifest: complete — all exported delta(s) applied");
    }
  }
  return 0;
}

/**
 * `dacar publish` — push signed delta(s) to the rfed channel (§11.1, docs #8/#11).
 *
 * Two source families (mutually exclusive):
 *   - `dacar publish <file> [<file>...]` — publish previously-signed delta
 *     payload(s) (exact bytes, no re-sign). The **exact signed bytes** are
 *     published — no re-signing, no new HLC, no local state change — so the
 *     receiver's verify-on-ingest authenticates the *original* issuer. These
 *     are external payloads and are **not** added to the sent box (they are
 *     not this node's issuance).
 *   - `dacar publish [--outbox] [--sent] [--all]` — publish this node's own
 *     issuance from its durable stores (work doc #11):
 *     - `--outbox` flushes the unsent queue; each Delta **moves** to the sent
 *       box (the durable replay log) once the transport accepts it.
 *     - `--sent` re-sends every Delta in the sent box (idempotent: CRDT merge
 *       is a no-op for already-delivered deltas). The sent box is not modified.
 *     - `--all` is `--outbox` + `--sent` (everything this node has issued).
 *
 * With no source flag and no files, `--outbox` is implied (the common "flush
 * what I've issued" case). Bare `publish` on an empty outbox is a no-op (0).
 *
 * Each Delta is published as its **own** rfed message (one §5.3 Operation per
 * compact inner-format envelope, §11.1.1) — exactly like `grant --publish`.
 * All sources reuse the `grant --publish` machinery (`publishDelta`: boot RNS,
 * announce, subscribe, publish), then record accepted deltas via
 * `recordPublish` (sent box append + outbox drain).
 */
async function cmdPublish(args) {
  const store = await openStore(args);
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  const useAll = !!args.all;
  let useOutbox = !!args.outbox || useAll;
  let useSent = !!args.sent || useAll;
  const files = args._positionals ?? [];
  let fromStores = useOutbox || useSent;

  if (files.length && fromStores) {
    throw new CliError(
      "publish: use either <file>... or a source flag (--outbox/--sent/--all), not both",
    );
  }
  // With no files and no source flag, `--outbox` is implied (doc #11): the
  // common case is "flush what I've issued".
  if (!files.length && !fromStores) {
    useOutbox = true;
    fromStores = true;
  }

  /** @type {Uint8Array[]} */
  const toPublish = [];
  if (useOutbox) toPublish.push(...(await store.loadOutbox()));
  if (useSent) toPublish.push(...(await store.loadSent()));
  for (const path of files) {
    const data = await readPayloadInput(path, !!args.binary);
    if (!data.length) throw new CliError(`empty payload: ${path}`);
    toPublish.push(data);
  }

  if (!toPublish.length) {
    const which = [
      ["outbox", useOutbox],
      ["sent", useSent],
    ].filter(([, on]) => on).map(([n]) => n).join(" + ") || "outbox";
    err(`nothing to publish (${which} empty)`);
    return 0;
  }

  // Dedup the send list by exact bytes, preserving first-seen order (a delta
  // could appear in both the outbox and the sent box after a partial-failure
  // recovery; sending it once is sufficient — CRDT merge is idempotent).
  const seen = new Set();
  const deduped = [];
  for (const payload of toPublish) {
    const h = toHex(payload);
    if (!seen.has(h)) {
      seen.add(h);
      deduped.push(new Uint8Array(payload));
    }
  }

  // External file payloads are not this node's issuance -> not logged to the
  // sent box. Anything sourced from a store (outbox/sent/--all) is recorded.
  const recordToSent = files.length === 0;

  const labelParts = [];
  if (useOutbox) labelParts.push("outbox");
  if (useSent) labelParts.push("sent");
  if (files.length) labelParts.push(`${files.length} file(s)`);
  err(`  publishing ${deduped.length} delta(s) (${labelParts.join(" + ")})`);

  let accepted;
  if (args.lxmf) {
    // --lxmf <hash|alias> (§11.2, work doc #14): directed store-and-forward
    // delivery to one recipient via the proprietor instead of the rfed
    // broadcast — the bootstrap path (`publish --sent --lxmf new-node`).
    // The rfed leg is untouched: run `publish` without `--lxmf` for it.
    accepted = await publishDeltaLxmf(args, store, identity, deduped);
  } else {
    accepted = await publishDelta(args, store, identity, deduped);
  }
  const nSent = await recordPublish(store, deduped, accepted, { recordToSent });

  if (useOutbox && !files.length) {
    err(
      `  (${nSent} moved outbox → sent box; ` +
        "`dacar publish --sent` to re-send)",
    );
  } else if (useSent && !useOutbox && !files.length) {
    err("  (sent box re-sent; not modified — idempotent)");
  }
  return 0;
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
  } else if (args.file) {
    pubKey = new Uint8Array(await readFile(args.file));
  } else {
    // Boot RNS and try to recall.
    const configDir = await resolveRnsConfigDir(args);
    const rns = await bootRns(configDir, args.interface || "shared", {
      verbose: !!args.verbose,
    });
    const recalled = await rns.transport.recallIdentity(issuerHash, true);
    if (!recalled) {
      throw new CliError(
        `could not recall ${shortHash(issuerHash, args.fullHashes)} from RNS; use --pubkey <hex> or --file <path>`,
      );
    }
    pubKey = await recalled.getPublicKey();
  }

  pubKey = asRnsPubKey(pubKey);
  const keyring = await store.loadKeyring();
  keyring.registerSingle(issuerHash, pubKey);
  await store.saveKeyring(keyring);
  err(`✔ remembered issuer ${shortHash(issuerHash, args.fullHashes)}`);
  err(`  pubkey : ${toHex(pubKey.slice(32)).slice(0, SHORT_HASH)}…`);
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
    // On disk only the 32-byte Ed25519 half is stored (Python parity); in
    // memory it's padded to a 64-byte RNS key (zeros ‖ Ed25519). Show the
    // meaningful Ed25519 half.
    const ed25519 = pub.length === 64 ? pub.slice(32) : pub;
    err(`  ${shortHash(hexToBytes(hashHex), args.fullHashes)}  pubkey=${toHex(ed25519).slice(0, SHORT_HASH)}…`);
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
    const row = ledger.get(toHex(await t.hash()));
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
    opts: { publish: "boolean", lxmf: "string", direct: "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-dir": "string", interface: "string" },
    positional: ["grantee", "relation", "object"],
    online: true,
  },
  revoke: {
    run: cmdRevoke,
    opts: { publish: "boolean", lxmf: "string", direct: "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-dir": "string", interface: "string" },
    positional: ["grantee", "relation", "object"],
    online: true,
  },
  sync: {
    run: cmdSync,
    opts: { lxmf: "boolean", "no-lxmf": "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-dir": "string", interface: "string" },
    online: true,
  },
  publish: {
    run: cmdPublish,
    opts: { all: "boolean", outbox: "boolean", sent: "boolean", binary: "boolean", lxmf: "string", direct: "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-dir": "string", interface: "string" },
    // variable file list (0..N) accessed via args._positionals
    online: true,
  },
  paper: {
    sub: {
      export: {
        run: cmdPaperExport,
        opts: { payload: "string", outbox: "boolean", sent: "boolean", all: "boolean", file: "string", "out-dir": "string", manifest: "string", binary: "boolean", "rns-dir": "string", interface: "string" },
        positional: ["target"],
        online: true,
      },
      import: {
        run: cmdPaperImport,
        opts: { manifest: "string", "rns-dir": "string", interface: "string" },
        // variable URI/file list (1..N) accessed via args._positionals
        online: true,
      },
    },
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
  // --store / --identity / --full-hashes are global on every (sub)command
  // (they were previously gated on `positional`, which silently dropped them
  // for commands with no positionals — e.g. `sync`, `config show`, `grants`).
  opts.store = { type: "string" };
  opts.identity = { type: "string" };
  opts["full-hashes"] = { type: "boolean" };
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

// Only auto-run when invoked as the entry script (Node/Bun via `pathToFileURL`,
// Deno via `import.meta.main`), so the module can be imported in tests without
// triggering the CLI dispatch (mirrors how `./cli/store` + `./cli/session`
// are unit-tested).
const isMain = (() => {
  try {
    if (import.meta.main === true) return true; // Deno
  } catch { /* not Deno */ }
  try {
    if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
      return true; // Node / Bun
    }
  } catch { /* pathToFileURL unavailable */ }
  return false;
})();

if (isMain) {
  main().then((code) => process.exit(code ?? 0)).catch((e) => {
    err("fatal: " + (e?.stack || e));
    process.exit(1);
  });
}
