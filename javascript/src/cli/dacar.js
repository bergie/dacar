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
 *   dacar config show
 *   dacar salt new|set
 *   dacar anchor add|list
 *   dacar identity show|new|remember|forget|list
 *   dacar grant <grantee> [<relation> [<object>]] [--publish|--lxmf <target>]
 *   dacar revoke <grantee> [<relation> [<object>]] [--publish|--lxmf <target>]
 *   dacar sync
 *   dacar publish <file> [<file>...] | --outbox | --sent | --all   (docs #8/#11)
 *   dacar push <node> [<file>...] | --outbox | --sent | --all     (§11, doc #16 4a)
 *   dacar paper export|import
 *   dacar apply <payload>
 *   dacar check <grantee> <relation> <object>
 *   dacar grants [--all|--revoked] [--grantee] [--issuer] [--effective]
 *   dacar show <ref>
 *   dacar validate [--fix]
 *   dacar prune
 *   dacar alias add|remove|list|resolve
 *   dacar ledger annotate
 *
 * Online flags: --node <hash>, --topic <topic>, --interface shared|auto|tcp,
 * --rns-config <path> (default: ~/.reticulum or $DACAR_RNS_CONFIG),
 * --proprietor <hash>.
 *
 * Mirrors the canonical Python CLI's command surface and output conventions
 * (`dacar/cli/commands.py`): identities render as `<alias> (<hash>…)`, human
 * summaries go to stderr and payload/machine-readable data to stdout.
 */

import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
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
import { unpackHlc, physicalNowMs } from "../hlc.js";
import { RnsIdentityResolver } from "../transport/rnsIdentity.js";
import { RFED_TOPIC, APP_NAME } from "../naming.js";
import {
  NamespaceHasher, DEFAULT_SALT, SALT_SIZE, HASH_SIZE, MAX_LEGACY_SALTS,
  bytesEqual, covers,
} from "../namespace.js";
import { Keyring, IssuerKeyset } from "../verifier.js";

import { DacarStore, SELF_ALIAS, AliasRegistry } from "./store.js";
import {
  announceIdentity, discoverRfedNode, ensureNodeIdentity, runPublishMany, runSync,
  registerAnnounceHandler, bootLxmfRouter, lxmfOutDestination, runLxmfPublish, runLxmfSync,
} from "./session.js";
import { LxmfDeltaDelivery, packPaperUris } from "../transport/lxmfSync.js";
import { DEFAULT_PUSH_TIMEOUT_MS, pushDeltas as pushDeltasOverLink } from "../transport/rnsSync.js";

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

/**
 * Render an identity the way the Python CLI does (work doc #2 output
 * convention): `<alias> (<short-hash>…)`, or `? (<short-hash>…)` when the
 * hash has no alias.
 * @param {Uint8Array} hash
 * @param {import("./store.js").AliasRegistry} aliases
 * @param {boolean} [full]
 * @returns {string}
 */
function renderIdentity(hash, aliases, full = false) {
  const name = aliases.primaryName(hash);
  const sh = shortHash(hash, full);
  return name ? `${name} (${sh})` : `? (${sh})`;
}

/**
 * Render an HLC's physical component as a UTC `YYYY-MM-DD HH:MM` timestamp
 * (Python `_utc`), or `-` for a null timestamp.
 * @param {bigint | number | null} hlc
 * @returns {string}
 */
function utcFromHlc(hlc) {
  if (!hlc) return "-";
  const ms = Number(hlc >> 16n);
  return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
}

/** Render an HLC as the Python CLI does: `0x…` zero-padded to 16 hex digits. */
function hlcHex(hlc) {
  return `0x${hlc.toString(16).padStart(16, "0")}`;
}

/**
 * Render a relation: ledger plaintext when known, else the bracketed hash.
 * @param {Uint8Array} relationHash
 * @param {{ relation?: string | null } | undefined} ledgerRow
 * @param {boolean} [full]
 */
function renderRelation(relationHash, ledgerRow, full = false) {
  if (ledgerRow && ledgerRow.relation) return ledgerRow.relation;
  return `[${shortHash(relationHash, full)}]`;
}

/**
 * Render an object: ledger plaintext when known, else bracketed hashes.
 * @param {Uint8Array[]} objectHashes
 * @param {boolean} wildcard
 * @param {{ object?: string | null } | undefined} ledgerRow
 * @param {boolean} [full]
 */
function renderObject(objectHashes, wildcard, ledgerRow, full = false) {
  if (ledgerRow && ledgerRow.object) return ledgerRow.object;
  const n = objectHashes.length;
  if (n === 0) return wildcard ? "[*]" : "[∅]";
  const head = shortHash(objectHashes[0], full);
  const more = n > 1 ? ` · ${n} seg` : "";
  return `[${head}${more}]`;
}

class CliError extends Error {}

/** Cryptographically secure random bytes (Python `_generate_salt`). */
function randomBytes(len) {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Parse a `--salt`/`salt set` value that is either 64-hex or a path to a
 * 32-byte raw salt file (mirrors Python `_parse_salt_value`).
 * @param {string} value
 * @returns {Promise<Uint8Array>}
 */
async function saltFromValue(value) {
  const hexCandidate = value.toLowerCase().startsWith("0x") ? value.slice(2) : value;
  if (hexCandidate.length === SALT_SIZE * 2) {
    try {
      const salt = hexToBytes(hexCandidate);
      if (salt.length === SALT_SIZE) return salt;
    } catch {
      // fall through to file interpretation
    }
  }
  const data = new Uint8Array(await readFile(value));
  if (data.length !== SALT_SIZE) {
    throw new CliError(`salt file ${JSON.stringify(value)} must contain ${SALT_SIZE} bytes, got ${data.length}`);
  }
  return data;
}

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

/**
 * Resolve an alias or 16-byte (32-hex) hash to a 16-byte identity hash
 * (mirrors Python `resolve_identity`, including its error messages).
 * @param {string} value
 * @param {import("./store.js").AliasRegistry} aliases
 * @returns {Uint8Array}
 */
function resolveIdentityHash(value, aliases) {
  const fromAlias = aliases.resolve(value);
  if (fromAlias) return fromAlias;
  const clean = value.trim().toLowerCase().replace(/^0x/, "");
  let raw;
  try {
    raw = hexToBytes(clean);
  } catch {
    throw new CliError(`unknown identity ${JSON.stringify(value)} (not a known alias or 16-byte hex hash)`);
  }
  if (raw.length !== 16) {
    throw new CliError(`identity ${JSON.stringify(value)} is ${raw.length} bytes; expected 16 (32 hex)`);
  }
  return raw;
}

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`invalid hex string (length ${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
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
  // `--rns-config` is the Python-parity flag name; `--rns-dir` is the
  // historical JS name (both accepted). Same for the env vars.
  const explicit = args.rnsConfig ?? args.rnsDir ?? process.env.DACAR_RNS_CONFIG ?? process.env.DACAR_RNS_DIR;
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
  const existing = new DacarStore(new DacarFileAdapter(path));
  if (await existing.exists()) {
    throw new CliError(`store already initialized at ${path}`);
  }
  await mkdir(path, { recursive: true });
  const adapter = new DacarFileAdapter(path);
  /** @type {Uint8Array | undefined} */ let salt;
  const saltProvided = args.salt != null;
  if (saltProvided) {
    salt = await saltFromValue(String(args.salt));
    if (bytesEqual(salt, DEFAULT_SALT)) {
      err("WARNING: --salt is the default null salt (§3.3 fail-open on privacy).");
    }
  }
  const store = await DacarStore.init(adapter, {
    salt,
    horizonDays: parseInt(args.horizon || "180", 10),
    identityBytes: args.identity ? await readFile(args.identity) : undefined,
  });
  const identity = await store.loadIdentity();
  const aliases = await store.loadAliases();
  const raw = await store.loadConfig();
  err("✔ initialized store at " + path);
  err(`  identity : ${renderIdentity(identity.identityHash, aliases, args.fullHashes)}`);
  err(`  anchor   : ${renderIdentity(identity.identityHash, aliases, args.fullHashes)} (self)`);
  err(`  salt     : ${shortHash(raw.primarySalt, args.fullHashes)}` +
    (bytesEqual(raw.primarySalt, DEFAULT_SALT) ? " (default null — FAIL-OPEN)" : " (random)"));
  err(`  horizon  : ${raw.horizonDays} days`);
  if (bytesEqual(raw.primarySalt, DEFAULT_SALT)) {
    err("  WARNING: primary salt is the default null (§3.3 fail-open on privacy).");
  }
  if (!saltProvided) {
    err("  WARNING: a unique random salt was generated. Grants will be opaque across");
    err("           nodes unless they share the same salt (see README).");
  }
  return 0;
}

async function cmdConfigShow(args) {
  const store = await openStore(args);
  const raw = await store.loadConfig();
  const aliases = await store.loadAliases();
  const path = args.store || defaultStorePath();
  const full = args.fullHashes || args.reveal;
  err("store: " + path);
  err("[salt]");
  const isDefault = bytesEqual(raw.primarySalt, DEFAULT_SALT);
  err("  primary   : " + (args.reveal ? toHex(raw.primarySalt) : "<masked (use --reveal)>") +
    (isDefault ? "  ⚠ FAIL-OPEN (default null)" : ""));
  raw.legacySalts.forEach((legacy, i) => {
    err(`  legacy${i}   : ${args.reveal ? toHex(legacy) : "<masked>"}`);
  });
  err("[trust]");
  for (const a of raw.anchors) err("  anchor    : " + renderIdentity(a, aliases, full));
  if (raw.authoritative) {
    err("  authoritative : " + renderIdentity(raw.authoritative, aliases, full));
  }
  err("[policy]");
  err("  deletion_horizon_days : " + raw.horizonDays);
  err("[rfed]");
  err("  topic : " + raw.rfedTopic);
  err("  node  : " + (raw.rfedNode ? renderIdentity(raw.rfedNode, aliases, full) : "(not set)"));
  err("[lxmf]");
  err("  proprietor : " + (raw.lxmfProprietor ? renderIdentity(raw.lxmfProprietor, aliases, full) : "(not set)"));
  err(`[aliases] ${aliases.entries.length} entries (${join(path, "aliases")})`);
  if (isDefault) {
    err("WARNING: primary salt is the default null (§3.3 fail-open on privacy).");
  }
  return 0;
}

// -- salt (§3.3/§10.2) ------------------------------------------------------

async function cmdSaltNew(args) {
  const store = await openStore(args);
  const raw = await store.loadConfig();
  // §10.2 rotation: old primary → legacy0, old legacy0 → legacy1, drop old legacy1.
  const newPrimary = randomBytes(SALT_SIZE);
  const newLegacy = [raw.primarySalt, ...raw.legacySalts.slice(0, 1)].slice(0, MAX_LEGACY_SALTS);
  await store.saveConfig({ ...raw, primarySalt: newPrimary, legacySalts: newLegacy });
  err("✔ rotated primary salt (old primary → legacy0, §10.2)");
  err("  primary : " + shortHash(newPrimary, args.fullHashes) +
    (bytesEqual(newPrimary, DEFAULT_SALT) ? "  ⚠ FAIL-OPEN" : ""));
  for (let i = 0; i < newLegacy.length; i++) {
    err(`  legacy${i}: ${shortHash(newLegacy[i], args.fullHashes)}`);
  }
  return 0;
}

async function cmdSaltSet(args) {
  const store = await openStore(args);
  const raw = await store.loadConfig();
  /** @type {Uint8Array} */ let salt;
  if (args.hex != null) {
    try {
      salt = hexToBytes(String(args.hex));
    } catch {
      throw new CliError(`--hex is not valid hex: ${JSON.stringify(args.hex)}`);
    }
  } else if (args.file != null) {
    salt = new Uint8Array(await readFile(String(args.file)));
    if (salt.length !== SALT_SIZE) {
      throw new CliError(`salt file must contain ${SALT_SIZE} bytes, got ${salt.length}`);
    }
  } else {
    throw new CliError("salt set requires --hex <hex> or --file <path>");
  }
  if (salt.length !== SALT_SIZE) {
    throw new CliError(`salt must be ${SALT_SIZE} bytes, got ${salt.length}`);
  }
  await store.saveConfig({ ...raw, primarySalt: salt });
  err("✔ set primary salt to " + shortHash(salt, args.fullHashes) +
    (bytesEqual(salt, DEFAULT_SALT) ? "  ⚠ FAIL-OPEN (default null)" : ""));
  return 0;
}

// -- anchors (§4.2) ---------------------------------------------------------

async function cmdAnchorAdd(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const anchor = resolveIdentityHash(args.hash, aliases);
  const raw = await store.loadConfig();
  if (raw.anchors.some((a) => bytesEqual(a, anchor))) {
    throw new CliError(`anchor already present: ${renderIdentity(anchor, aliases, args.fullHashes)}`);
  }
  await store.saveConfig({ ...raw, anchors: [...raw.anchors, anchor] });
  err(`✔ added anchor ${renderIdentity(anchor, aliases, args.fullHashes)}`);
  return 0;
}

async function cmdAnchorList(args) {
  const store = await openStore(args);
  const raw = await store.loadConfig();
  const aliases = await store.loadAliases();
  if (!raw.anchors.length) {
    err("(no Root Trust Anchors configured)");
    return 0;
  }
  err(`ROOT TRUST ANCHORS (${raw.anchors.length})`);
  for (const a of raw.anchors) err("  " + renderIdentity(a, aliases, args.fullHashes));
  if (raw.authoritative) {
    err("authoritative: " + renderIdentity(raw.authoritative, aliases, args.fullHashes));
  }
  return 0;
}

// -- identity show / new ----------------------------------------------------

async function cmdIdentityShow(args) {
  const store = await openStore(args);
  const identity = await store.loadIdentity();
  if (!identity) {
    throw new CliError("no signing identity (run `dacar init` or `dacar identity new`)");
  }
  const aliases = await store.loadAliases();
  const path = args.store || defaultStorePath();
  err(`identity : ${renderIdentity(identity.identityHash, aliases, args.fullHashes)}`);
  err("  source  : " + (args.identity ? `--identity ${args.identity}` : join(path, "identity.key")));
  err(`  pubkey  : ${toHex((await identity.getPublicKey()).slice(32))}`);
  if (aliases.entries.length) {
    err("aliases  :");
    for (const entry of aliases.entries) {
      err(`  ${toHex(entry.hash)}  ${entry.names.join(" ")}` + (entry.note ? `  # ${entry.note}` : ""));
    }
  }
  return 0;
}

async function cmdIdentityNew(args) {
  const store = await openStore(args);
  const newIdentity = await Identity.generate();
  const { oldHash, newHash } = await store.rotateIdentity(newIdentity);
  const aliases = await store.loadAliases();
  const path = args.store || defaultStorePath();
  err("✔ generated new signing identity");
  err("  old : " + (oldHash ? shortHash(oldHash, args.fullHashes) : "(none)"));
  err(`  new : ${renderIdentity(newHash, aliases, args.fullHashes)}`);
  err(`  file: ${join(path, "identity.key")} (mode 0600)`);
  err("  NOTE: previous identity's signatures will no longer verify; " +
    "self-anchor rotated to the new identity.");
  return 0;
}

async function cmdGrant(args) {
  return _issue(args, Action.GRANT);
}

async function cmdRevoke(args) {
  return _issue(args, Action.REVOKE);
}

/**
 * Parse a `--copy-hashes` file: `relation_hash=<hex>`, `object_hashes=<hex>:<hex>`,
 * `wildcard=true|false` (mirrors Python `_parse_copy_hashes`).
 * @param {string} path
 * @returns {{ relationHash: Uint8Array, objectHashes: Uint8Array[], wildcard: boolean }}
 */
function parseCopyHashes(path) {
  let relationHash = null;
  const objectHashes = [];
  let wildcard = false;
  const text = readFileSync(path, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const eq = line.indexOf("=");
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();
    if (key === "relation_hash") {
      try {
        relationHash = hexToBytes(val);
      } catch {
        throw new CliError(`--copy-hashes file has an invalid relation_hash: ${val}`);
      }
    } else if (key === "object_hashes") {
      for (const part of val.split(":")) {
        if (!part) continue;
        try {
          objectHashes.push(hexToBytes(part));
        } catch {
          throw new CliError(`--copy-hashes file has an invalid object hash: ${part}`);
        }
      }
    } else if (key === "wildcard") {
      wildcard = ["true", "1", "yes"].includes(val.toLowerCase());
    }
  }
  if (!relationHash || relationHash.length !== HASH_SIZE) {
    throw new CliError("--copy-hashes file must define a 16-byte relation_hash");
  }
  return { relationHash, objectHashes, wildcard };
}

/**
 * Build the tuple to issue (mirrors Python `_build_tuple`): plaintext
 * `relation`/`object` (with an optional `--legacy` salt index) or the exact
 * pre-hashed fields from `--copy-hashes` (a salt-free revoke path).
 * @returns {Promise<{ tuple: Tuple, objectId: string | null, relation: string | null, wildcard: boolean | null }>}
 */
async function buildTuple(args, config, aliases, issuerHash) {
  const grantee = resolveIdentityHash(args.grantee, aliases);
  if (args["copy-hashes"]) {
    const { relationHash, objectHashes, wildcard } = parseCopyHashes(args["copy-hashes"]);
    const tuple = new Tuple({
      relationHash, objectHashes, wildcard, grantee, issuer: issuerHash,
    });
    return { tuple, objectId: null, relation: null, wildcard: null };
  }
  const relation = args.relation;
  const objectId = args.object;
  if (relation == null || objectId == null) {
    throw new CliError("grant/revoke requires <relation> and <object> (or --copy-hashes <file>)");
  }
  let hasher = config.primaryHasher;
  if (args.legacy != null) {
    const legacy = config.legacySalts;
    if (args.legacy < 0 || args.legacy >= legacy.length) {
      throw new CliError(
        `--legacy index ${args.legacy} out of range (have ${legacy.length} legacy salts)`,
      );
    }
    hasher = new NamespaceHasher(legacy[args.legacy]);
  }
  const wildcard = objectId.endsWith("*") && objectId !== "*";
  const tuple = await Tuple.fromPlaintext({
    objectId, relation, grantee, issuer: issuerHash, hasher,
  });
  return { tuple, objectId, relation, wildcard };
}

async function _issue(args, action) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const aliases = await store.loadAliases();
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init` or `dacar identity new`)");

  const { tuple, objectId, relation, wildcard } =
    await buildTuple(args, config, aliases, identity.identityHash);

  // Monotonic HLC, persisted across invocations.
  const clock = await store.loadClock();
  const hlc = clock.now();
  await store.saveClock(clock);

  const op = await new Operation({ tuple, action, hlc }).sign(identity);
  const payload = op.toPayload();

  let applied = false;
  if (!args["no-apply"]) {
    const state = await store.loadState(config);
    applied = state.apply(op);
    if (!applied) {
      throw new CliError("local apply rejected (§9 stale / §12 future-skew)");
    }
    await store.saveState(state);
  }

  // Record plaintext ledger for any locally-issued op with known plaintext.
  // §13.6: first_seen is the *physical* HLC timestamp (high 48 bits), not the
  // full 64-bit HLC — matching the Python CLI so ledger.msgpack stays
  // byte-identical across implementations (§13.11).
  if (objectId != null && relation != null) {
    const ledger = await store.loadLedger();
    const { physicalMs } = unpackHlc(hlc);
    ledger.set(toHex(await tuple.hash()), {
      object: objectId, relation, wildcard: !!wildcard, firstSeen: physicalMs,
    });
    await store.saveLedger(ledger);
  }

  // Emit the signed payload (hex on stdout by default).
  let where;
  if (args.out) {
    await writeFile(String(args.out), payload);
    where = `binary file ${args.out}`;
  } else if (args.binary) {
    process.stdout.write(payload);
    where = "binary on stdout";
  } else {
    out(toHex(payload));
    where = "hex on stdout";
  }

  const verb = action === Action.GRANT ? "granted" : "revoked";
  err(`✔ ${verb.padEnd(8)} ${renderIdentity(tuple.grantee, aliases, args.fullHashes)}  ` +
    `${relation ?? "[hash]"}  on  ${objectId ?? "[hash]"}`);
  err(`  grantee : ${renderIdentity(tuple.grantee, aliases, args.fullHashes)}`);
  err(`  issuer  : ${renderIdentity(tuple.issuer, aliases, args.fullHashes)}`);
  if (objectId != null) {
    const nseg = objectId === "*" ? 0 : objectId.split(":").filter((s) => s).length;
    err(`  object  : ${objectId}  (${nseg} segment${nseg !== 1 ? "s" : ""}` +
      `${wildcard ? ", wildcard" : ""})`);
  } else {
    err(`  object  : [copy-hashes, ${tuple.objectHashes.length} segment(s)` +
      `${tuple.wildcard ? ", wildcard" : ""}]`);
  }
  err(`  hlc     : ${hlcHex(hlc)}`);
  err(`  payload : ${where} (${payload.length} bytes)`);
  if (args["no-apply"]) {
    err("  (not applied locally: --no-apply)");
  } else if (applied) {
    err("  (applied locally)");
  }

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
    // `--no-apply` only governs local CRDT apply, not whether the delta was issued.
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
  const ledger = await store.loadLedger();
  const engine = new Engine(config, state);
  const grantee = resolveIdentityHash(args.grantee, aliases);
  const allowed = await engine.evaluate(args.object, args.relation, grantee);

  const mark = allowed ? "✔" : "✘";
  const verdict = allowed ? "ALLOW" : "DENY";
  err(`${mark} ${verdict.padEnd(5)} ${renderIdentity(grantee, aliases, args.fullHashes)}  ` +
    `${args.relation}  ${args.object}`);

  // Best-effort trace: find the matching active tuples across all salts.
  const matches = [];
  for await (const m of findMatchingTuples(config, state, args.relation, args.object, grantee)) {
    matches.push(m);
  }
  if (!matches.length) {
    err("  no matching active tuple");
  } else {
    for (const [kind, tuple] of matches) {
      const row = ledger.get(toHex(await tuple.hash()));
      const rel = renderRelation(tuple.relationHash, row, args.fullHashes);
      const obj = row && row.object ? row.object : "[hash]";
      const issuerLabel = renderIdentity(tuple.issuer, aliases, args.fullHashes);
      const anchor = config.isRootAnchor(tuple.issuer)
        ? "is a Root Trust Anchor"
        : "is NOT an anchor";
      const tag = kind === "deny" ? "deny" : "allow";
      err(`  ${tag.padEnd(5)} : ${issuerLabel} ${rel} ${obj}  (${anchor})`);
    }
  }
  return allowed ? 0 : 1;
}

/**
 * Yield `[kind, tuple, hasher]` for active tuples matching the request
 * (mirrors Python `_find_matching_tuples`).
 * @param {import("../config.js").Config} config
 * @param {import("../crdt.js").StateVector} state
 * @param {string} relation
 * @param {string} objectId
 * @param {Uint8Array} grantee
 */
async function* findMatchingTuples(config, state, relation, objectId, grantee) {
  for (const hasher of config.hashers) {
    const allowRh = await hasher.hashRelation(relation);
    const denyRh = await hasher.hashRelation("-" + relation);
    const { hashes: objHashes } = await hasher.hashObject(objectId);
    for (const tuple of state.activeTuples()) {
      if (!bytesEqual(tuple.grantee, grantee)) continue;
      if (bytesEqual(tuple.relationHash, denyRh) && covers(tuple.objectHashes, tuple.wildcard, objHashes)) {
        yield ["deny", tuple, hasher];
      } else if (bytesEqual(tuple.relationHash, allowRh) && covers(tuple.objectHashes, tuple.wildcard, objHashes)) {
        yield ["allow", tuple, hasher];
      }
    }
  }
}

async function cmdApply(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const keyring = await store.keyringForVerify();
  const rx = new DeltaReceiver(state, keyring);
  const data = await readPayloadInput(args.payload, !!args.binary);
  if (!data.length) throw new CliError("empty payload");

  // Try a single delta first; fall back to a batch.
  if (await rx.applyPayload(data)) {
    await store.saveState(state);
    err("✔ applied 1 delta");
    try {
      const op = Operation.fromPayload(data);
      const aliases = await store.loadAliases();
      const ledger = await store.loadLedger();
      const row = ledger.get(toHex(await op.tuple.hash()));
      err(`  ${renderIdentity(op.grantee, aliases, args.fullHashes)}  ` +
        `${renderRelation(op.relationHash, row, args.fullHashes)}  ` +
        `${renderObject(op.objectHashes, op.wildcard, row, args.fullHashes)}  ` +
        `← ${renderIdentity(op.issuer, aliases, args.fullHashes)}`);
    } catch {
      // best-effort detail line only
    }
    return 0;
  }

  const count = await rx.applyPayloads(data);
  if (count > 0) {
    await store.saveState(state);
    err(`✔ applied ${count} delta(s) (batch)`);
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

export {
  coercePayload, recordPublish,
  // Pure helpers (unit-testable seams, mirroring Python's commands.py surface).
  renderIdentity, renderRelation, renderObject, utcFromHlc, hlcHex,
  saltFromValue, prunePayloadList, findMatchingTuples, parseCopyHashes,
  // Command implementations (offline commands are directly testable).
  cmdInit, cmdConfigShow, cmdSaltNew, cmdSaltSet, cmdAnchorAdd, cmdAnchorList,
  cmdIdentityShow, cmdIdentityNew, cmdIdentityRemember, cmdIdentityForget,
  cmdIdentityList, cmdGrant, cmdRevoke, cmdSync, cmdPublish, cmdPush,
  cmdPaperExport, cmdPaperImport, cmdApply, cmdCheck, cmdGrants, cmdShow,
  cmdValidate, cmdPrune, cmdAliasAdd, cmdAliasRemove, cmdAliasList,
  cmdAliasResolve, cmdLedgerAnnotate,
};

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

async function cmdPush(args) {
  const store = await openStore(args);
  const identity = await store.loadIdentity();
  if (!identity) throw new CliError("no signing identity (run `dacar init`)");

  // The target node is positional[0]; payload files are positionals 1..N
  // (`positional` naming is unused for push — see the SUBCOMMANDS entry).
  const positionals = args._positionals ?? [];
  const nodeArg = positionals[0];
  if (!nodeArg) throw new CliError("push: no target node given (usage: dacar push <node> [...])");
  const aliases = await store.loadAliases();
  const target = resolveIdentityHash(nodeArg, aliases);
  const files = positionals.slice(1);

  const useAll = !!args.all;
  let useOutbox = !!args.outbox || useAll;
  let useSent = !!args.sent || useAll;
  let fromStores = useOutbox || useSent;

  if (files.length && fromStores) {
    throw new CliError(
      "push: use either <file>... or a source flag (--outbox/--sent/--all), not both",
    );
  }
  // With no files and no source flag, `--outbox` is implied (doc #11): the
  // common case is "flush what I've issued".
  if (!files.length && !fromStores) {
    useOutbox = true;
    fromStores = true;
  }

  /** @type {Uint8Array[]} */
  const toPush = [];
  if (useOutbox) toPush.push(...(await store.loadOutbox()));
  if (useSent) toPush.push(...(await store.loadSent()));
  for (const path of files) {
    const data = await readPayloadInput(path, !!args.binary);
    if (!data.length) throw new CliError(`empty payload: ${path}`);
    toPush.push(data);
  }

  if (!toPush.length) {
    const which = [
      ["outbox", useOutbox],
      ["sent", useSent],
    ].filter(([, on]) => on).map(([n]) => n).join(" + ") || "outbox";
    err(`nothing to push (${which} empty)`);
    return 0;
  }

  // Dedup the send list by exact bytes, preserving first-seen order (a delta
  // could appear in both the outbox and the sent box after a partial-failure
  // recovery; sending it once is sufficient — CRDT merge is idempotent).
  const seen = new Set();
  const deduped = [];
  for (const payload of toPush) {
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
  err(`  pushing ${deduped.length} delta(s) (${labelParts.join(" + ")}) to ` +
    `${shortHash(target, args.fullHashes)} via direct link`);

  const accepted = await pushDelta(args, store, identity, deduped, target);
  const nSent = await recordPublish(store, deduped, accepted, { recordToSent });

  const applied = accepted.filter((ok) => ok).length;
  if (applied < deduped.length) {
    err(`  ⚠ ${deduped.length - applied} delta(s) not accepted by the node ` +
      "(refused or link lost; retained for retry)");
  }
  if (useOutbox && !files.length) {
    err(`  (${nSent} moved outbox → sent box; ` +
      "`dacar push --sent <node>` to re-send)");
  } else if (useSent && !useOutbox && !files.length) {
    err("  (sent box re-sent; not modified — idempotent)");
  }
  return 0;
}

/**
 * Online direct-link push hook for `push` (§11, work doc #16 Phase 4a) — the
 * sibling of `publishDelta` and the seam tests patch with a fake.
 *
 * Boots RNS once, announces the node identity (the announce invariant —
 * without it the target drops every Delta as "unknown issuer"), seeds the
 * durable keyring, then hands the whole batch to the transport's
 * `pushDeltas` (one Link, one request per Delta). Returns per-Delta
 * acceptance flags for `recordPublish` (work doc #11 — same outbox → sent
 * lifecycle regardless of transport).
 */
async function pushDelta(args, store, identity, payloads, target) {
  const configDir = await resolveRnsConfigDir(args);
  const rns = await bootRns(configDir, args.interface || "shared", {
    verbose: !!args.verbose,
  });
  await announceIdentity(identity, rns);

  // Durable issuer cache (doc #5): same seeding as the other online legs.
  const keyring = await store.loadKeyring();
  keyring.registerSingle(identity.identityHash, await identity.getPublicKey());
  await registerAnnounceHandler({ rns, keyring, onSave: (kr) => store.saveKeyring(kr) });
  await store.saveKeyring(keyring);

  return pushDeltasOverLink(payloads, target, {
    rns,
    // --timeout is in seconds (Python parity); the transport speaks ms.
    timeoutMs: args.timeout ? Number(args.timeout) * 1000 : DEFAULT_PUSH_TIMEOUT_MS,
    onRequest: () => err("  requesting node path…"),
  });
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
  const path = args.store || defaultStorePath();

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
        `could not recall ${renderIdentity(issuerHash, aliases, args.fullHashes)} from RNS; ` +
          "use --pubkey <hex> or --file <path> to specify the key out-of-band",
      );
    }
    pubKey = await recalled.getPublicKey();
  }

  pubKey = asRnsPubKey(pubKey);
  const keyring = await store.loadKeyring();
  keyring.registerSingle(issuerHash, pubKey);
  await store.saveKeyring(keyring);
  err(`✔ remembered issuer ${renderIdentity(issuerHash, aliases, args.fullHashes)}`);
  err(`  pubkey : ${toHex(pubKey.slice(32))}`);
  err(`  cache  : ${join(path, "identities.msgpack")} (${keyring.size} entries)`);
  return 0;
}

async function cmdIdentityForget(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const issuerHash = resolveIdentityHash(args.hash, aliases);
  const path = args.store || defaultStorePath();

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
        `issuer ${renderIdentity(issuerHash, aliases, args.fullHashes)} has ${active} active grant(s) in the live CRDT; ` +
          "forgetting it would make its revokes unverifiable (use --force to override)",
      );
    }
  }

  const keyring = await store.loadKeyring();
  if (!keyring.forget(issuerHash)) {
    throw new CliError(`issuer ${renderIdentity(issuerHash, aliases, args.fullHashes)} not in the cache`);
  }
  await store.saveKeyring(keyring);
  err(`✔ forgot issuer ${renderIdentity(issuerHash, aliases, args.fullHashes)}`);
  err(`  cache : ${join(path, "identities.msgpack")} (${keyring.size} entries)`);
  return 0;
}

async function cmdIdentityList(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const keyring = await store.loadKeyring();
  const path = args.store || defaultStorePath();
  err(`ISSUER IDENTITY CACHE (${keyring.size})  ${join(path, "identities.msgpack")}`);
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
    err(`  ${renderIdentity(hexToBytes(hashHex), aliases, args.fullHashes)}  ` +
      `pubkey=${toHex(ed25519).slice(0, SHORT_HASH)}…`);
  }
  return 0;
}

async function cmdGrants(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const aliases = await store.loadAliases();
  const ledger = await store.loadLedger();
  const engine = args.effective ? new Engine(config, state) : null;
  const path = args.store || defaultStorePath();

  const rows = [];
  for (const entry of state._entries.values()) {
    const active = entry.addTs !== null && (entry.removeTs === null || entry.addTs > entry.removeTs);
    if (args.revoked && active) continue;
    if (!args.all && !args.revoked && !active) continue;
    if (args.grantee != null) {
      const wanted = resolveIdentityHash(String(args.grantee), aliases);
      if (!bytesEqual(entry.tuple.grantee, wanted)) continue;
    }
    if (args.issuer != null) {
      const wanted = resolveIdentityHash(String(args.issuer), aliases);
      if (!bytesEqual(entry.tuple.issuer, wanted)) continue;
    }
    rows.push({ entry, active });
  }

  const label = args.revoked ? "REVOKED TOMBSTONES" : args.all ? "ALL TUPLES" : "ACTIVE GRANTS";
  err(`${label} (${rows.length})${" ".repeat(16)}store: ${path}`);
  if (!rows.length) {
    err("(none)");
    return 0;
  }

  err("GRANTEE              RELATION   OBJECT           ISSUER               STATUS   TIMESTAMP");
  for (const { entry, active } of rows) {
    const t = entry.tuple;
    const row = ledger.get(toHex(await t.hash()));
    const grantee = renderIdentity(t.grantee, aliases, args.fullHashes);
    const relation = renderRelation(t.relationHash, row, args.fullHashes);
    const obj = renderObject(t.objectHashes, t.wildcard, row, args.fullHashes);
    const issuer = renderIdentity(t.issuer, aliases, args.fullHashes);
    const status = active ? "active" : "revoked";
    const ts = active ? utcFromHlc(entry.addTs) : utcFromHlc(entry.removeTs);
    let opaque = "";
    if (!(row && row.object)) opaque = " ◂ opaque";
    let effective = "";
    if (engine !== null && row && row.object) {
      // The issuer is "effective" iff its authority traces to a root anchor.
      // A root anchor is effective by definition (the genesis tuple is
      // implicit, §4.2); a delegated issuer is effective iff the engine
      // grants it admin on this object.
      const hasAuth = config.isRootAnchor(t.issuer) ||
        await engine.evaluate(row.object, "admin", t.issuer);
      effective = hasAuth ? " ✔" : " ⚠";
    }
    err(`${grantee.padEnd(20)} ${relation.padEnd(10)} ${obj.padEnd(16)} ` +
      `${issuer.padEnd(20)} ${status.padEnd(8)} ${ts}${opaque}${effective}`);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// show / validate / prune
// ---------------------------------------------------------------------------

async function cmdShow(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const aliases = await store.loadAliases();
  const ledger = await store.loadLedger();

  const ref = String(args.ref).trim();
  let shown = false;
  // Tuple-hash form (64 hex = the 32-byte §6.1 SHA-256 Tuple Hash).
  if (ref.length === 64) {
    let tupleHash = null;
    try {
      tupleHash = hexToBytes(ref);
    } catch {
      tupleHash = null;
    }
    if (tupleHash && tupleHash.length === 32) {
      for (const entry of state._entries.values()) {
        if (bytesEqual(await entry.tuple.hash(), tupleHash)) {
          await printTupleDetail(entry, aliases, ledger, args.fullHashes);
          shown = true;
          break;
        }
      }
    }
  }

  if (!shown) {
    // alias:relation:object form — search across issuers/salts.
    const parts = ref.split(":");
    if (parts.length < 2) {
      throw new CliError("show expects a 64-hex tuple hash or <alias>:<relation>:<object>");
    }
    const granteeAlias = parts[0];
    const relation = parts[1];
    const objectId = parts.length > 2 ? parts.slice(2).join(":") : "";
    const grantee = resolveIdentityHash(granteeAlias, aliases);
    for (const hasher of config.hashers) {
      const allowRh = await hasher.hashRelation(relation);
      const { hashes: objHashes } = await hasher.hashObject(objectId);
      for (const entry of state._entries.values()) {
        const t = entry.tuple;
        if (!bytesEqual(t.grantee, grantee)) continue;
        if (bytesEqual(t.relationHash, allowRh) && covers(t.objectHashes, t.wildcard, objHashes)) {
          await printTupleDetail(entry, aliases, ledger, args.fullHashes);
          shown = true;
        }
      }
    }
  }

  if (!shown) throw new CliError(`no tuple found for ${JSON.stringify(ref)}`);
  return 0;
}

/**
 * Print one state entry's full detail (Python `_print_tuple_detail`).
 * @param {{ tuple: import("../tuple.js").Tuple, addTs: bigint | null, removeTs: bigint | null }} entry
 */
async function printTupleDetail(entry, aliases, ledger, full) {
  const t = entry.tuple;
  const row = ledger.get(toHex(await t.hash()));
  const active = entry.addTs !== null && (entry.removeTs === null || entry.addTs > entry.removeTs);
  err(`tuple   : ${toHex(await t.hash())}`);
  err(`  status  : ${active ? "ACTIVE" : "REVOKED"}`);
  err(`  grantee : ${renderIdentity(t.grantee, aliases, full)}`);
  err(`  issuer  : ${renderIdentity(t.issuer, aliases, full)}`);
  err(`  relation: ${renderRelation(t.relationHash, row, full)}`);
  err(`  object  : ${renderObject(t.objectHashes, t.wildcard, row, full)}`);
  err(`  wildcard: ${t.wildcard}`);
  err(`  segments: ${t.objectHashes.length}`);
  err(`  added   : ${utcFromHlc(entry.addTs)}  (hlc ${entry.addTs ? hlcHex(entry.addTs) : "-"})`);
  err(`  removed : ${utcFromHlc(entry.removeTs)}  (hlc ${entry.removeTs ? hlcHex(entry.removeTs) : "-"})`);
}

async function cmdValidate(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const aliases = await store.loadAliases();
  const ledger = await store.loadLedger();
  const path = args.store || defaultStorePath();

  const suspicious = [];
  let checkedTuples = 0;

  // First check all ledger entries (corruption is often here).
  for (const [tupleHashHex, row] of ledger) {
    if (row.object) {
      // Objects use the `:` separator — a comma is ALWAYS invalid.
      if (row.object.includes(",")) {
        suspicious.push({
          source: "ledger",
          reason: `INVALID: object contains comma (objects use ':' separator): '${row.object}'`,
          tupleHash: tupleHashHex,
          hasStateTuple: state.has(toHex(await tupleHashBytes(tupleHashHex))),
        });
      } else if (row.object.length > 100) {
        suspicious.push({
          source: "ledger",
          reason: `object unusually long: ${row.object.length} chars`,
          tupleHash: tupleHashHex,
          objectPreview: row.object.slice(0, 80) + "...",
          hasStateTuple: state.has(toHex(await tupleHashBytes(tupleHashHex))),
        });
      }
    }
  }

  // Then check state tuples.
  for (const entry of state._entries.values()) {
    checkedTuples += 1;
    const t = entry.tuple;
    const tupleHashHex = toHex(await t.hash());
    if (suspicious.some((s) => s.tupleHash === tupleHashHex)) continue;

    const row = ledger.get(tupleHashHex);
    if (row && row.object) {
      if (row.object.includes(",")) {
        suspicious.push({
          source: "ledger",
          reason: `object contains commas: '${row.object}'`,
          tupleHash: tupleHashHex,
          grantee: renderIdentity(t.grantee, aliases, false),
          issuer: renderIdentity(t.issuer, aliases, false),
          ledgerObject: row.object,
          segmentCount: t.objectHashes.length,
        });
        continue;
      }
      if (row.object.length > 100) {
        suspicious.push({
          source: "ledger",
          reason: `object unusually long: ${row.object.length} chars`,
          tupleHash: tupleHashHex,
          grantee: renderIdentity(t.grantee, aliases, false),
          issuer: renderIdentity(t.issuer, aliases, false),
          ledgerObject: row.object.slice(0, 80) + "...",
        });
      }
    }

    // More than 10 segments is unusual (may indicate concatenation).
    if (t.objectHashes.length > 10) {
      suspicious.push({
        source: "state",
        reason: `unusual number of object segments: ${t.objectHashes.length}`,
        tupleHash: tupleHashHex,
        grantee: renderIdentity(t.grantee, aliases, false),
        issuer: renderIdentity(t.issuer, aliases, false),
        segmentHashes: t.objectHashes.slice(0, 5).map((h) => toHex(h).slice(0, 16)),
      });
    }

    // Real hashes are random-looking; a segment with many printable ASCII
    // bytes suggests plaintext ended up in the hash slots.
    for (const h of t.objectHashes) {
      let printable = 0;
      for (const b of h) {
        if (b >= 32 && b < 127) printable += 1;
      }
      if (printable > 8) {
        suspicious.push({
          source: "state",
          reason: `suspicious object segment hash (contains ${printable}/16 printable ASCII chars)`,
          tupleHash: tupleHashHex,
          grantee: renderIdentity(t.grantee, aliases, false),
          issuer: renderIdentity(t.issuer, aliases, false),
          suspiciousHash: toHex(h),
        });
        break;
      }
    }
  }

  err(`Checked ${checkedTuples} tuple(s) and ${ledger.size} ledger entries`);

  if (suspicious.length) {
    err(`Found ${suspicious.length} suspicious entry/entries:`);
    let i = 1;
    for (const item of suspicious) {
      err("");
      err(`[${i}] [${String(item.source).toUpperCase()}] ${item.reason}`);
      err(`    Tuple hash: ${item.tupleHash}`);
      if (item.grantee) err(`    Grantee: ${item.grantee}`);
      if (item.issuer) err(`    Issuer: ${item.issuer}`);
      if (item.ledgerObject) err(`    Ledger object: ${item.ledgerObject}`);
      if (item.objectPreview) err(`    Object preview: ${item.objectPreview}`);
      if (item.segmentCount != null) err(`    Segment count: ${item.segmentCount}`);
      if (item.hasStateTuple != null) err(`    Has matching state tuple: ${item.hasStateTuple}`);
      if (item.segmentHashes) err(`    First 5 segment hashes: ${item.segmentHashes.join(", ")}`);
      if (item.suspiciousHash) err(`    Suspicious hash: ${item.suspiciousHash}`);
      i += 1;
    }

    if (args.fix) {
      err("");
      err("⚠ --fix is not yet implemented");
      err("  To manually clean up corrupted state:");
      err(`  1. Back up your store directory: cp -r ${path} ${path}.backup`);
      err("  2. Delete the corrupted files:");
      err(`     rm ${join(path, "state.msgpack")}`);
      err(`     rm ${join(path, "ledger.msgpack")}`);
      err("  3. Re-sync from scratch: dacar sync");
      err("");
      err("  WARNING: This will remove all locally-issued grants that");
      err("           haven't been published to RFed or backed up.");
      return 1;
    }
    err("");
    err("To remove corrupted entries, run: dacar validate --fix");
    err("(This will require re-syncing from RFed to restore valid grants)");
    return 1;
  }
  err("✔ No corruption detected");
  return 0;
}

/** Parse a 64-hex ledger/state tuple-hash key into 32 bytes (or null). */
async function tupleHashBytes(hex) {
  try {
    const raw = hexToBytes(hex);
    return raw.length === 32 ? raw : new Uint8Array(0);
  } catch {
    return new Uint8Array(0);
  }
}

async function cmdPrune(args) {
  const store = await openStore(args);
  const config = await store.loadConfigValidated();
  const state = await store.loadState(config);
  const count = state.prune();
  await store.saveState(state);
  err(`✔ pruned ${count} resolved tombstone pair(s) (§9)`);
  // Also drop outbox entries older than the §9 horizon: such deltas are
  // intake-rejected by receivers (§9) so publishing them is pointless, and
  // this keeps the outbox bounded for long-lived offline nodes (work doc #8).
  const dropped = await pruneOutbox(store, state.deletionHorizonMs);
  if (dropped) {
    err(`  outbox: pruned ${dropped} stale delta(s) (older than horizon)`);
  }
  // And the sent box: stale entries would be intake-rejected on re-send, so
  // the durable replay log is bounded the same way (work doc #11).
  const sentDropped = await pruneSent(store, state.deletionHorizonMs);
  if (sentDropped) {
    err(`  sent: pruned ${sentDropped} stale delta(s) (older than horizon)`);
  }
  return 0;
}

/**
 * Split payloads by the §9 horizon (mirrors Python `_prune_payload_list`).
 * Returns `[kept, dropped]`; entries that fail to decode are kept.
 * @param {Uint8Array[]} payloads
 * @param {number} horizonMs
 * @param {number} [nowMs]
 * @returns {[Uint8Array[], number]}
 */
function prunePayloadList(payloads, horizonMs, nowMs) {
  const now = nowMs ?? physicalNowMs();
  const cutoff = now - horizonMs;
  /** @type {Uint8Array[]} */ const kept = [];
  let dropped = 0;
  for (const payload of payloads) {
    let physicalMs;
    try {
      physicalMs = unpackHlc(Operation.fromPayload(payload).hlc).physicalMs;
    } catch {
      kept.push(payload); // can't decode -> keep (don't destroy)
      continue;
    }
    if (physicalMs < cutoff) dropped += 1;
    else kept.push(payload);
  }
  return [kept, dropped];
}

/** @param {DacarStore} store @param {number} horizonMs @returns {Promise<number>} */
async function pruneOutbox(store, horizonMs) {
  const outbox = await store.loadOutbox();
  if (!outbox.length) return 0;
  const [kept, dropped] = prunePayloadList(outbox, horizonMs);
  if (dropped) await store.saveOutbox(kept);
  return dropped;
}

/** @param {DacarStore} store @param {number} horizonMs @returns {Promise<number>} */
async function pruneSent(store, horizonMs) {
  const sent = await store.loadSent();
  if (!sent.length) return 0;
  const [kept, dropped] = prunePayloadList(sent, horizonMs);
  if (dropped) await store.saveSent(kept);
  return dropped;
}

// ---------------------------------------------------------------------------
// aliases / ledger
// ---------------------------------------------------------------------------

async function cmdAliasAdd(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const hashBytes = resolveIdentityHash(args.hash, aliases);
  const existing = aliases.resolve(args.name);
  if (existing && !bytesEqual(existing, hashBytes)) {
    throw new CliError(
      `alias ${JSON.stringify(args.name)} already names a different hash (${shortHash(existing, args.fullHashes)})`,
    );
  }
  aliases.add(args.name, hashBytes, args.note);
  await store.saveAliases(aliases);
  err(`✔ alias ${JSON.stringify(args.name)} → ${renderIdentity(hashBytes, aliases, args.fullHashes)}`);
  return 0;
}

async function cmdAliasRemove(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  if (!aliases.remove(args.name)) {
    throw new CliError(`no alias named ${JSON.stringify(args.name)}`);
  }
  await store.saveAliases(aliases);
  err(`✔ removed alias ${JSON.stringify(args.name)}`);
  return 0;
}

async function cmdAliasList(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  if (!aliases.entries.length) {
    err("(no aliases)");
    return 0;
  }
  for (const entry of aliases.entries) {
    let line = `${toHex(entry.hash)}  ${entry.names.join(" ")}`;
    if (entry.note) line += `  # ${entry.note}`;
    err(line);
  }
  return 0;
}

async function cmdAliasResolve(args) {
  const store = await openStore(args);
  const aliases = await store.loadAliases();
  const h = aliases.resolve(args.name);
  if (!h) throw new CliError(`unknown alias ${JSON.stringify(args.name)}`);
  // Print the full hash to stdout (machine-readable).
  out(toHex(h));
  return 0;
}

async function cmdLedgerAnnotate(args) {
  const store = await openStore(args);
  let tupleHash;
  try {
    tupleHash = hexToBytes(args.tupleHash);
  } catch {
    throw new CliError(`tuple-hash must be hex, got ${JSON.stringify(args.tupleHash)}`);
  }
  if (tupleHash.length !== 32) {
    throw new CliError(`tuple-hash must be 32 bytes (64 hex), got ${tupleHash.length}`);
  }
  const ledger = await store.loadLedger();
  const key = toHex(tupleHash);
  const row = ledger.get(key) ?? { object: null, relation: null, wildcard: null, firstSeen: 0 };
  if (args.object != null) row.object = args.object;
  if (args.relation != null) row.relation = args.relation;
  ledger.set(key, row);
  await store.saveLedger(ledger);
  err(`✔ annotated tuple ${toHex(tupleHash).slice(0, SHORT_HASH)}…`);
  return 0;
}

/**
 * Run a command implementation with the CLI's error handling (`CliError` →
 * `error: …` on stderr + exit code 1) without going through `process.argv`
 * dispatch — the seam Python gets for free from `argparse` + `main`.
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function runCommand(fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof CliError) {
      err("error: " + e.message);
      return /** @type {T} */ (1);
    }
    throw e;
  }
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
  salt: {
    sub: {
      new: { run: cmdSaltNew, opts: {}, online: false },
      set: { run: cmdSaltSet, opts: { hex: "string", file: "string" }, online: false },
    },
  },
  anchor: {
    sub: {
      add: { run: cmdAnchorAdd, opts: {}, positional: ["hash"], online: false },
      list: { run: cmdAnchorList, opts: {}, online: false },
    },
  },
  grant: {
    run: cmdGrant,
    opts: { "no-apply": "boolean", out: "string", binary: "boolean", legacy: "string", "copy-hashes": "string", publish: "boolean", lxmf: "string", direct: "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-config": "string", "rns-dir": "string", interface: "string" },
    positional: ["grantee", "relation", "object"],
    online: true,
  },
  revoke: {
    run: cmdRevoke,
    opts: { "no-apply": "boolean", out: "string", binary: "boolean", legacy: "string", "copy-hashes": "string", publish: "boolean", lxmf: "string", direct: "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-config": "string", "rns-dir": "string", interface: "string" },
    positional: ["grantee", "relation", "object"],
    online: true,
  },
  sync: {
    run: cmdSync,
    opts: { lxmf: "boolean", "no-lxmf": "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-config": "string", "rns-dir": "string", interface: "string" },
    online: true,
  },
  publish: {
    run: cmdPublish,
    opts: { all: "boolean", outbox: "boolean", sent: "boolean", binary: "boolean", lxmf: "string", direct: "boolean", node: "string", discover: "boolean", topic: "string", proprietor: "string", "rns-config": "string", "rns-dir": "string", interface: "string" },
    // variable file list (0..N) accessed via args._positionals
    online: true,
  },
  push: {
    run: cmdPush,
    // The target node is positional[0]; the payload file list (0..N) is
    // positionals 1..N, read from args._positionals in cmdPush (a leading
    // fixed positional plus a variadic rest can't use the `positional` map).
    opts: { all: "boolean", outbox: "boolean", sent: "boolean", binary: "boolean", timeout: "string", "rns-config": "string", "rns-dir": "string", interface: "string" },
    online: true,
  },
  paper: {
    sub: {
      export: {
        run: cmdPaperExport,
        opts: { payload: "string", outbox: "boolean", sent: "boolean", all: "boolean", file: "string", "out-dir": "string", manifest: "string", binary: "boolean", "rns-config": "string", "rns-dir": "string", interface: "string" },
        positional: ["target"],
        online: true,
      },
      import: {
        run: cmdPaperImport,
        opts: { manifest: "string", "rns-config": "string", "rns-dir": "string", interface: "string" },
        // variable URI/file list (1..N) accessed via args._positionals
        online: true,
      },
    },
  },
  apply: { run: cmdApply, opts: { binary: "boolean" }, positional: ["payload"], online: false },
  check: { run: cmdCheck, opts: {}, positional: ["grantee", "relation", "object"], online: false },
  grants: { run: cmdGrants, opts: { all: "boolean", revoked: "boolean", grantee: "string", issuer: "string", effective: "boolean" }, online: false },
  show: { run: cmdShow, opts: {}, positional: ["ref"], online: false },
  validate: { run: cmdValidate, opts: { fix: "boolean" }, online: false },
  prune: { run: cmdPrune, opts: {}, online: false },
  alias: {
    sub: {
      add: { run: cmdAliasAdd, opts: { note: "string" }, positional: ["name", "hash"], online: false },
      remove: { run: cmdAliasRemove, opts: {}, positional: ["name"], online: false },
      list: { run: cmdAliasList, opts: {}, online: false },
      resolve: { run: cmdAliasResolve, opts: {}, positional: ["name"], online: false },
    },
  },
  ledger: {
    sub: {
      annotate: { run: cmdLedgerAnnotate, opts: { object: "string", relation: "string" }, positional: ["tupleHash"], online: false },
    },
  },
  identity: {
    sub: {
      show: { run: cmdIdentityShow, opts: {}, online: false },
      new: { run: cmdIdentityNew, opts: {}, online: false },
      remember: {
        run: cmdIdentityRemember,
        opts: { pubkey: "string", file: "string", "rns-config": "string", "rns-dir": "string", interface: "string", force: "boolean" },
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
    opts[k] = { type: t, ...(k === "out" ? { short: "o" } : {}) };
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
