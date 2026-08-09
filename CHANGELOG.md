# Changelog

All notable changes to Dacar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Python `RfedDeltaSync` transport adapter (§11.1) — wraps the RFed client
  and routes received Deltas through the shared `DeltaReceiver`
  verify-on-ingest seam, mirroring the JavaScript implementation. The RFed
  client subpackage (`dacar.rfed`) is now packaged and ships in the wheel.
- `dacar.rfed` smoketests (`tests/test_transport_rfed.py`): publish wraps the
  Delta under the `dacar/sync/delta` title; `listen`/`pull` route through
  verify-on-ingest and swallow malformed/forged payloads; `pull` unwraps a
  real EC-encrypted rfed `inner_blob` end-to-end.
- One-shot online commands (work doc #4, §11.1): `dacar grant --publish`
  pushes a signed Delta to the rfed channel; `dacar sync` pulls pending
  Deltas and applies them through verify-on-ingest. Both use the
  attach-or-spawn RNS model (shared instance → AutoInterface default →
  user config) — no daemon, matching `rnx`/`lxsend`/`lxmsg`.
- `[rfed]` config section (`topic`, `node`) on the store, with `topic`
  defaulting to `dacar.policy.v1` per §11.1. Displayed in `dacar config show`;
  preserved across salt/identity rotations.
- `dacar.cli.rns` helpers: `resolve_config_dir` (priority: `--rns-config` →
  `$DACAR_RNS_CONFIG` → `~/.reticulum` → `<store>/rns` with a default
  AutoInterface config), `boot`, and `announce_identity` (the announce
  invariant, §11.2.4 — both online commands announce the node identity on
  start so receivers can recall the issuer pubkey).
- Online command smoketests (`tests/test_cli_online.py`): `run_publish`/
  `run_sync` wiring with a fake RFedClient; two-node round-trip (A publishes
  → B syncs → `check` ALLOW; revoke propagates → DENY; forged Delta dropped);
  `grant --publish` applies locally then publishes; `[rfed]` config round-
  trips and survives salt/identity rotations; RNS config dir priority;
  `announce_identity` creates the `dacar.node` destination; cross-node Delta
  applies via RNS recall (announce invariant, §11.2.4).

## [1.0.0] - 2024-08-08

### Added
- Initial release of Dacar specification (v1.0-RC7)
- Python reference implementation
- JavaScript implementation for Node.js, Deno, Bun, and browsers
- Core authorization engine with tuple-based permissions
- LWW-Element-Set CRDT for eventually consistent state
- Namespace label privacy with salted HMAC-SHA256 hashing
- Hybrid Logical Clocks (HLC) for ordering
- Threshold groups (N-of-M) for multi-signature authority
- Recursive delegation evaluation with cycle detection
- Explicit deny support (deny beats allow)
- Time-horizon tombstone pruning for storage bounds
- Privacy salt rotation with legacy salt support
- Transport adapters:
  - RFed many-to-many convergence
  - LXMF targeted delivery to offline nodes
  - LXMF Paper Messages for air-gapped/optical (QR) transport
  - RNS Challenge for strict consistency on destructive operations
- Verify-on-ingest security boundary for all network deltas
- Ed25519 signature verification for operations
- MessagePack serialization for transport payloads
-  `dacar` command-line tool for offline-first grant management (work doc #2)
