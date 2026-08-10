# Changelog

All notable changes to Dacar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-08-09

### Added
- `--verbose` / `-v` flag for `dacar` online commands (`sync`, `grant
  --publish`, `revoke --publish`, `identity remember`). Raises the Reticulum
  log threshold to `DEBUG` and prints interface attach/online status plus each
  validated announce the transport sees (destination / name-hash / hops), so a
  failing `--discover` shows whether *any* announces are arriving and for which
  aspects. New Node-only `src/cli/rns_boot.js` (`bootRns` / `attachInterface`)
  hosts the boot + diagnostics; added smoketests `test/cli-rns-boot.test.js`.

### Fixed
- `dacar` online commands silently no-op'd then timed out: `bootRns`
  (`src/cli/dacar.js`) constructed interface objects (`LocalClientInterface`,
  `AutoInterface`, `TCPClientInterface`) and passed them to
  `rns.addInterface()` but never called `await iface.connect()`, and attached
  them *without* `isDefault = true`. With no connected streams, the
  interface's `_packetWriter` stayed `null`, so `TransportCore.broadcast()`
  silently skipped it — dacar's own announce and `path?` requests never went
  out, and peer announces (including the rfed node's `rfed.node` announce)
  never came in. The result was the `dacar sync --discover` "no rfed.node
  announce received within 30000ms" timeout even when an rfed node was
  actively announcing. `bootRns` now connects the chosen interface and
  attaches it as the default (mirroring `@reticulum/node`'s `rfed` CLI
  `attachInterface`), and `shared` falls back to `AutoInterface` when no rnsd
  is reachable so the node is still on the mesh.
- Scary `StateVector.fromPayload() is trusted-local-only…` warning during
  normal CLI use: the audible developer-footgun `console.warn` (meant to flag
  library misuse — deserializing attacker/network bytes) fired every time
  `dacar sync` / `grant` / `check` loaded the node's own persisted CRDT
  snapshot via `DacarStore.loadState()` — the legitimate, trusted-local use.
  `StateVector.fromPayload` now accepts `{ trusted: true }` to suppress the
  warning when the caller asserts it is loading its own store; `loadState`
  passes it. The JSDoc contract is unchanged; the default audible warning
  still fires for other callers. Added a crdt smoketest pinning both paths.
- Proactive rfed node identity fetch (work doc #6): when `--node <hash>`
  (or `--discover`) resolves to an rfed destination whose announce isn't in
  RNS's recall store yet, `dacar sync` / `dacar grant --publish` now send a
  `path?` request for that destination and wait (up to 15s) for the node's
  path-response announce to populate the recall store, instead of failing
  immediately with "rfed node identity unknown for <hash>; wait for its
  announce". New helpers: Python `dacar.cli.rns.ensure_node_identity` and JS
  `ensureNodeIdentity` (`src/cli/session.js`), wired into both `cmd_sync`/
  `cmd_publish` (Python) and `cmdSync`/`publishDelta` (JS). Added regression
  smoketests (`tests/test_cli_ensure_node_identity.py`,
  `test/cli-session-ensure-node.test.js`) exercising the recall/path-request/
  poll/timeout paths.

### Fixed
- Python `RFedClient` request-response decode (`dacar sync` / `grant
  --publish`): the `subscribe`, `unsubscribe`, and `pull` methods
  double-unpacked the RNS response with `msgpack.unpackb`, but RNS's
  `Link.request` already msgpack-unpacks the wire response and stores the
  resulting Python object on `RequestReceipt.response`. Calling
  `msgpack.unpackb` on that object raised
  `TypeError: a bytes-like object is required, not 'list'`, crashing
  `dacar sync --node <hash>` at the very first `subscribe`. The response is
  now decoded directly (mirroring the JavaScript reference). Added regression
  smoketests (`tests/test_rfed_client_response.py`) exercising the real
  `RFedClient` decode paths with a faked RNS Link.
- JavaScript `announceIdentity` (`dacar sync` / `grant --publish`): the
  `dacar.node` destination was created via `Destination.create(name,
  Destination.IN, identity, rns)`, but `Destination.IN` is a static *factory
  method* in `@reticulum/core`, not a Direction enum value (unlike Python
  RNS's `RNS.Destination.IN` constant). With `rns` landing in the `identity`
  slot and `interfaceLayer` left null, `announce()` threw
  `Destination not bound to an RNS instance.` It now uses the idiomatic
  `Destination.IN(name, DestType.SINGLE, identity, rns)` factory (mirroring
  `@reticulum/core`'s rfed/client.js), binding the destination to the booted
  Reticulum. Added regression smoketests (`test/cli-session-announce.test.js`)
  exercising the real headless `Reticulum` + `Identity`/`Destination` seam —
  the coverage gap (the CLI runners were only ever tested through fakes)
  that let both this and the Python double-unpack bug slip through.
- `--discover` autodiscovery (`dacar sync --discover` / `grant --publish
  --discover`) — **both runtimes**. Two layers were broken:
  - **JS `resolveRfedNode`** ignored the `discover` flag entirely (parsed
    but never consulted), always falling through to "no rfed node
    configured". It now mirrors Python's `_resolve_rfed_node` and calls the
    discovery helper when the flag is set (passing the booted `rns`).
    `publishDelta` was also reordered to boot RNS before resolving the node
    (required for discover mode, matching Python's `_publish_delta`).
  - **`discoverRfedNode` / `discover_rfed_node` listened for the wrong
    announce and derived a phantom hash.** Dacar syncs over rfed, and the rfed
    daemon (an external process; dacar ships only the client) announces
    `rfed.node` + the `rfed.channel.*` services under one identity. The code
    instead listened for `dacar.node` announces (a dacar peer's own signing
    identity, §11.2.4 — a different thing) and derived a hash for the
    non-existent destination `rfed.dacar.node`. Discovery therefore never
    produced a usable node hash. Both runtimes now filter for `rfed.node`
    announces (JS: by `detail.nameHash`; Python: by recomputing the
    `rfed.node` destination hash under the announced identity) and return the
    announce's own `destinationHash` directly — the rfed node's canonical
    identifier — with no derivation.
  - Additional JS bugs in the rewritten `discoverRfedNode`: the listener never
    called `resolve()` (only the timeout ever fired), the timeout *threw*
    instead of `reject()` (hanging the process forever on a no-peer timeout),
    it never returned the discovered hash, and referenced an undefined
    `HASH_SIZE`.
  - Additional Python bug in `discover_rfed_node`: `on_announce` never
    signaled its `Event`, so `found.wait()` blocked for the full timeout even
    when an announce arrived immediately; and it used `signal.SIGALRM`
    (main-thread-only, broken in nested CLI contexts). Replaced with
    `threading.Event.wait(timeout_s)` signaled by the announce callback.
  - Latent Python import bug: `discover_rfed_node` imported `CliError` from
    `dacar.cli.store` (where it doesn't exist); it's now imported from
    `dacar.cli.commands`.
  - The timeout error message now names what's missing: "no rfed.node
    announce received within Nms (ensure an rfed node is reachable and
    announcing)" instead of the vague "no rfed node discovered … (ensure
    peers are announcing on the rfed channel)".
  - Replaced the superficial derivation-only JS test with real
    `discoverRfedNode` coverage against a live headless transport
    (`test/cli-discovery.test.js`, 5 tests), and added Python parity
    (`tests/test_cli_discover_rfed_node.py`, 6 tests) — both dispatch real
    `rfed.node` / `rfed.channel.*` / `dacar.node` announces and assert the
    resolved hash is the announce's own destination hash.

## [1.1.0] - 2026-08-09

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
- Durable issuer identity cache (work doc #5): a dacar-owned persisted
  `Keyring` (`identities.msgpack`, mode `0600`) used as the
  `RnsIdentityResolver` fallback in `sync` and `grant --publish` — so issuers
  observed in a prior session (or seeded out-of-band) are resolvable without a
  live re-announce, closing the cross-runtime announce-persistence asymmetry
  (Python RNS persists all announces; reticulum-js persists only
  contacted/favorited). A `dacar.node` announce handler seeds the cache during
  the online window; `dacar identity remember/forget/list` commands seed, remove,
  and inspect the cache. `forget` refuses to purge an issuer that still has
  active grants in the live CRDT (would strand them — revokes become
  unverifiable); `--force` overrides.
- `Keyring` gained `forget()`, `entries()`, `__len__`, `__contains__` for cache
  management and listing.

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
