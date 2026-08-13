# Changelog

All notable changes to Dacar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-08-12

### Changed
- **Python & JavaScript**: RFed transport now remembers sender identities
  from received Deltas. When a Delta is received via RFed, the sender's
  public key (from the RTID prelude) is associated with the issuer hash
  (extracted from the Delta payload) using `RNS.Identity.remember()`
  (Python) or `Destination.remember()` (JavaScript). This populates the
  local identity cache so that future `RNS.Identity.recall()` calls succeed
  without needing a network announce. The change is best-effort (wrapped in
  try-except) and does not affect security — the real authentication still
  comes from the Delta's Ed25519 signature verification and trust anchor
  chain validation. This mirrors the existing behavior in the LXMF transport
  path and reduces network traffic for identity resolution.

## [1.2.1] - 2026-08-12

### Security
- **Python**: Strengthened Operation payload validation to reject malformed
  deltas that could corrupt state. The validation now explicitly checks each
  field's type before conversion using `_expect_bytes()` and `_expect_bool()`
  helpers that match the JavaScript implementation. Malformed payloads (e.g.,
  old-style batched deltas, wrong field types) now produce clear error
  messages identifying the specific field and issue (e.g., "issuer must be a
  16-byte binary blob, got list" or "object_hashes[0] must be 16 bytes, got str
  with length 9").
- **Python**: Added rejection logging to `DeltaReceiver.apply_payload()`.
  When `log_rejections=True` is set, rejected deltas are logged to stderr with
  detailed error messages. The `dacar sync` command now enables this logging
  by default to help users identify and debug invalid deltas received from
  RFed or other transports. This is critical for detecting when RFed storage
  contains old-style malformed payloads that should have been rejected.

### Added
- **Python**: New `dacar validate` command to check state integrity and detect
  corrupted tuples. The command checks for:
  - **Ledger corruption**: Object strings containing commas (ALWAYS invalid - objects use
    `:` separator, not `,`). This catches the corruption pattern from the bug report where
    objects were concatenated as `blog:publish,grib:request,sys:command`.
  - State corruption: Unusually many object segments or suspicious hash patterns.
  Provides guidance on how to clean up corrupted state. Run `dacar validate --fix` for
  cleanup instructions.

## [1.2.0] - 2026-08-11

### Added
- **`SPEC.md` §11.1.1 "Inner Format — Compact Dacar Envelope"**: documents
  the Dacar-specific RFed `inner_blob` (work doc #10). A §5.3 Delta is already
  self-addressed, self-timed, and self-signed, so wrapping it in a full LXMF
  message inside the RFed `inner_blob` only duplicates the
  destination/source/signature/timestamp and pushes a typical 170-byte Delta
  past the 500-byte RNS MTU (the `rfed.channel.publish` destination is
  fire-and-forget, no links/fragmentation). The compact envelope reuses the
  RTID prelude (`"RTID" ‖ sender_identity_pub(64) ‖ delta`) EC-encrypted to the
  derived channel identity; the Delta's own Ed25519 signature remains the sole
  authenticity check at verify-on-ingest (§11.2). Measured ~499 bytes on the
  wire for a typical Delta (multi-hop, with stamp). LXMF framing is retained
  for §11.2 targeted delivery and §11.3 Paper Messages — only the RFed
  broadcast channel uses the compact format.
- `SPEC.md` §13 "Local Node Store": a recommended file-based store layout
  (normative only for implementations that choose it) so that independently-
  developed CLIs can read and write the same store directory interchangeably.
  Documents the exact byte format of every record: INI `config`, snake_case
  `clock.msgpack`/`ledger.msgpack`/`identities.msgpack`, rnns-text `aliases`,
  the CRDT `state.msgpack` snapshot, the `outbox.msgpack` unsent queue, and
  the `sent.msgpack` durable replay log of published Deltas (work doc #11).
  The node signing identity private key is the sole intentional divergence
  (library-native format).

### Changed
- **Python RFed transport now publishes/receives Deltas in the compact
  Dacar inner format (§11.1.1, work doc #10)** instead of wrapping each Delta
  in a full LXMF message inside the RFed `inner_blob`. This fixes the
  `OSError: Packet size of 595 exceeds MTU of 500 bytes` failure on
  `dacar publish --all` (a 170-byte Delta now fits the 500-byte RNS MTU).
  `dacar.rfed.blob` gains `wrap_dacar_delta()` / `unwrap_dacar_delta()`
  (alongside the LXMF `wrap_channel_message` / `unwrap_channel_message`, kept
  for general RFed usage and LXMF/Paper-Message transport). `RFedClient` gains
  general raw-publish primitives — `send_publish()`, `channel()`,
  `stamp_cost()`, `listen_raw()` — so application-specific inner formats can be
  sent/received without assuming an LXMF envelope; `publish()`/`listen()`
  (LXMF path) are preserved for normal RFed usage. The `RfedDeltaSync`
  adapter now wraps/receives via the compact format and the obsolete
  `message_content` helper is removed. The JavaScript transport is migrated
  in the same change (see the JS entry below).
- **`dacar publish` now sends each Delta as its own rfed message** (one §5.3
  Operation per compact inner-format envelope, §11.1.1) instead of packing
  multiple Deltas into one msgpack batch. This is required by the ~500-byte
  RNS path MTU (the `rfed.channel.publish` destination is fire-and-forget,
  no link/fragmentation), and it also fixes a latent receive-side bug: every
  transport receiver applies Deltas one at a time via
  `DeltaReceiver.apply_payload` (single), so a multi-delta msgpack batch was
  silently dropped as malformed on receive. `publish --all` and multi-file
  `publish <f1> <f2>` now boot RNS + subscribe **once**, then publish each
  Delta via the shared `_publish_delta`/`run_publish_many` path (RNS is a
  singleton and cannot be re-booted per Delta). The now-dead
  `RfedDeltaSync.pack_payloads` alias is removed (`DeltaReceiver`'s
  `pack_payloads`/`apply_payloads` are retained for local `dacar apply <file>`
  batch import, §11.2).
- **Durable issuance log: outbox + sent box + re-send (work doc #11).** The
  outbox is split into two durable stores: the **outbox** (`outbox.msgpack`,
  the unsent queue — `grant`/`revoke` append here unless `--publish`) and the
  **sent box** (`sent.msgpack`, the durable replay log of every Delta this
  node has published, as exact signed bytes). A Delta moves **outbox → sent
  box** on send (deduplicating by payload bytes), so a dropped Delta is
  retryable and re-deliverable to peers that join later. Publish is
  fire-and-forget (no delivery confirmation), so the signed bytes must be
  retained — the sent box is that retention. `dacar publish` gains three
  explicit, orthogonal source flags: `--outbox` (flush the unsent queue,
  moving each to the sent box; the default when no flag is given), `--sent`
  (re-send every Delta in the sent box, idempotent — CRDT merge is a no-op
  for already-delivered deltas; the sent box is not modified), and `--all`
  (outbox + sent box). `grant --publish` / `revoke --publish` now enqueue to
  the outbox *before* sending (durability against a crash or failed
  transport) so the sent box is a complete issuance log. `dacar prune` bounds
  both the outbox and the sent box by the §9 horizon. External payloads
  published via `publish <file>` are not logged to the sent box (they are
  not this node's own issuance).
- **JavaScript port: durable issuance log + raw RFed transport (work doc #11,
  docs #8/#10).** The JS CLI now matches the Python reference for both the
  durable-log semantics and the compact-inner-format RFed transport, with
  store-level + wire-format interoperability verified cross-implementation
  (a Python-written `sent.msgpack` reads back in JS and vice versa; a
  Python-wrapped RFed `inner_blob` unwraps in JS and vice versa):
  - **Store**: `src/cli/store.js` gains `loadSent()` / `saveSent()` (the
    `sent.msgpack` durable replay log), mirroring `loadOutbox()` /
    `saveOutbox()`; `src/cli/fileStore.js` maps `sent.msgpack` to mode 0600.
    The format is byte-for-byte the Python record (msgpack array of bin
    payloads; corrupted/non-array → empty).
  - **Commands**: `src/cli/dacar.js` `cmdPublish` is rewritten for the
    `--outbox` / `--sent` / `--all` source flags (bare `publish` defaults to
    `--outbox`; empty is a no-op exit 0; `--all` = outbox + sent; files are
    exclusive with flags; dedup by exact bytes; external files are not logged
    to the sent box). A new pure-store `recordPublish(store, payloads,
    accepted, { recordToSent })` helper drains accepted deltas from the
    outbox and appends them to the sent box (dedup by bytes). `grant
    --publish` / `revoke --publish` enqueue to the outbox *before* sending
    (durability), then `recordPublish` moves outbox → sent on success.
  - **Transport**: `src/transport/rfedSync.js` is migrated off legacy
    LXMF-over-RFed onto `@reticulum/core`'s raw-publish primitives —
    `subscribeRaw()` (marks the channel for raw decode), `publishRaw()`
    (carries the Delta as the RTID-prelude application payload, no LXMF
    envelope), and `listen()` with `kind: "raw"` dispatch (the payload is
    the carried §5.3 Delta, routed through `DeltaReceiver.applyPayload`).
    `pull()` unwraps deferred `inner_blob`s via `unwrapRawChannelMessage`.
    `src/cli/session.js` gains `runPublishMany({ deltaPayloads, … })` (per-
    Delta transport acceptance, one Delta per message) with `runPublish` as a
    thin single-Delta wrapper. The obsolete LXMF-path `wrapChannelMessage` /
    `unwrapChannelMessage` / `LXMessage` imports are removed from `rfedSync.js`.
  - **Tests**: `test/transport-rfed.test.js` is rewritten for the raw API;
    `test/cli-publish.test.js` gains sent-box store tests + `recordPublish`
    tests (move-to-sent, partial-failure keeps unsent, idempotent re-send,
    external files not logged).
- `send_publish` now returns whether the transport accepted the outbound
  packet (`Packet.send()` result), and `dacar publish` reports the sent/total
  count honestly instead of implying node-side storage was confirmed.
- `dacar init` now warns when `--salt` is not provided, indicating that a unique
  random salt was generated and grants will be opaque across nodes unless they
  share the same salt (see README for salt sharing workflow).
- **Store format now matches the canonical Python `Store` byte-for-byte**
  (work doc #9): the JS CLI writes and reads the same `~/.dacar/` directory as
  the Python CLI. `config` is now INI (was msgpack array); `clock.msgpack` and
  `ledger.msgpack` use snake_case keys (`last_ms`, `first_seen`); `aliases` is
  rnns text (was msgpack); `identities.msgpack` stores 32-byte Ed25519 public
  keys (was 64-byte RNS keys); the ledger key is `sha256(preimage).hex()` (was
  the raw preimage hex); files are written as loose files at the store root
  (was `<dir>/dacar/<key>.bin`) with Python-matching modes (0600/0644).
- Bumped `@reticulum/core` and `@reticulum/node` to `^0.6.5` in both
  `package.json` (npm) and `jsr.json` (JSR `imports` map). This release of
  `@reticulum/core` exposes the raw-publish primitives (`subscribeRaw`,
  `publishRaw`, `wrapRawChannelMessage`, `unwrapRawChannelMessage`, `listen`
  with `kind: "raw"` dispatch) used by the JS RFed transport migration above.
- Migrated imports of `LXMessage`/`LXMRouter` to `@reticulum/core/src/lxmf/index.js`
  and of `RFedClient` plus the rfed helpers (`deliveryHashFor`, `deriveChannel`,
  `unwrapChannelMessage`, `wrapChannelMessage`) to `@reticulum/core/src/rfed/index.js`.
  `@reticulum/core` 0.6.x no longer re-exports these sizable, server-leaning
  modules from the package root; they are now imported by subpath on both npm
  and JSR. JSDoc `import("@reticulum/core")` type references to the moved
  symbols were updated accordingly.

### Fixed
- The JSR package `@reticulum/dacar` resolved `@reticulum/core` and
  `@reticulum/node` as **npm** dependencies (JSR reported `usesNpm: true` and
  the dependency graph showed `npm:@reticulum/core`) because `jsr.json` had no
  `imports` map, so JSR fell back to npm for the bare `@reticulum/*` specifiers
  in the source. Added an `imports` map (`jsr:@reticulum/core@^0.6.5`,
  `jsr:@reticulum/node@^0.6.5`) so JSR now resolves both from JSR. This also
  required moving the `RFedClient` deep import off
  `@reticulum/core/src/rfed/client.js` (not a JSR `exports` subpath) to the
  `./src/rfed/index.js` barrel.
- **`dacar sync`/`dacar publish` no longer time out with "rfed link to
  <derived-hash> not established"** when the rfed node's identity is known but
  no transport path to the specific `rfed.channel.*` destination is. RNS's
  `RNS.Link` (Python) and `@reticulum/core`'s `Link` (JS) do not proactively
  request a path before the first `LINKREQUEST`, so a request addressed to a
  destination with no known route is silently dropped by multi-hop peers and
  the link times out. Both clients now request a `path?` for the *specific*
  derived channel destination and wait for the node's path-response announce
  before linking/sending — mirroring rngit's `RNS.Transport.await_path` and the
  LXMF router's `_requestAndAwaitPath`:
  - **Python**: `RFedClient._ensure_path` (via `RNS.Transport.await_path`) is
    called by `_establish_link` (subscribe/unsubscribe/pull) and by `publish`
    before the fire-and-forget `Packet.send()`.
  - **JS**: `ensureRfedPath` in `src/cli/session.js` computes the derived
    `rfed.channel.*` destination hash and requests + awaits a path to it;
    `runPublish`/`runSync` (now taking an optional `rns`) call it for the
    `subscribe`+`publish`/`pull` destinations before delegating to `RFedClient`.
- **``dacar sync``/``grant --publish`` no longer fail to create an rfed
  subscription** (the node's subscription count did not increase). The Python
  ``RFedClient`` pre-msgpack-packed the ``/rfed/subscribe`` payload
  (``[channel_hash, pubkey, sig]``) into ``bytes`` before passing it to
  ``RNS.Link.request`` — but ``Link.request`` msgpack-encodes its ``data``
  argument itself, so the node received an opaque ``bin`` blob instead of an
  array, failed ``Array.isArray(data)`` in ``_verifySignedPayload``, and
  replied ``[false, null]``. ``run_sync``/``run_publish`` discarded that
  failure and proceeded to pull/publish anyway, so the topic had no subscription
  on the node and would not sync with peers. ``_signed_channel_payload`` now
  returns the **list** (matching the JS ``signedChannelPayload``), and
  ``run_sync``/``run_publish`` (Python) and ``runPublish``/``runSync`` (JS)
  now **raise** on a rejected subscribe instead of swallowing it, so this class
  of silent failure is caught. (JS was already encoding the payload correctly.)

## [1.1.2] - 2026-08-10

### Added
- Standalone `dacar publish` command (work doc #8, §11.1): publish a
  previously-signed Delta without re-signing it. `dacar publish <file>...`
  transmits the exact bytes of one (or several) signed payloads — a single
  Delta goes out raw, multiple are packed via `DeltaReceiver.pack_payloads`
  / `packPayloads` into one batch payload. `dacar publish --all` flushes a
  persisted outbox (`outbox.msgpack` / KV record, mode `0600`) of locally-issued,
  not-yet-published deltas: every `grant`/`revoke` that is **not** given
  `--publish` (and, in Python, `--no-apply`) enqueues the just-signed payload;
  `--all` packs the outbox into a batch, publishes it, then clears the outbox.
  `--all` on an empty outbox is a no-op (exit 0, no RNS boot). `prune` (§9)
  also drops outbox entries older than the deletion horizon — receivers
  intake-reject them anyway, so republishing is pointless. Input parsing mirrors
  `apply`: hex is auto-detected (whitespace-trimmed), `--binary` forces raw
  bytes, `-` reads stdin, multiple `<file>`s publish a batch. Implemented in
  both Python (canonical) and JavaScript, with smoketests
  (`tests/test_cli_publish.py`, `test/cli-publish.test.js`).
- Example `dacar` CLI commands for every step of the "Using Dacar" walkthrough
  in the top-level `README.md`.

### Fixed (JavaScript)
- `dacar` commands without positional arguments rejected `--store`,
  `--identity`, and `--full-hashes` with `Unknown option '--store'`. `buildOptions`
  (`src/cli/dacar.js`) gated those global flags behind `if (spec.positional &&
  spec.positional.length)`, so `init`, `sync`, `config show`, `grants`, and the
  new `publish` silently dropped them — `dacar init --store <dir>` crashed before
  writing any config, which in turn made `grant`/`revoke`/`sync` unreachable in a
  real run. The flags are now added unconditionally to every subcommand.
- `dacar grant`/`revoke` crashed with `toHex expects a Uint8Array` when recording
  the plaintext ledger: `ledger.set(toHex(tuple.key), …)` double-encoded the
  key — `Tuple.key` already returns the hex preimage string (the same key the
  CRDT maps entries by, `StateVector` line 128). The ledger now uses `tuple.key`
  directly, so `dacar grants`' plaintext lookup matches. (Latent — unreachable
  while `init --store` rejected `--store`.)
- `dacar grant`/`revoke` crashed with `payload.hex is not a function`:
  `out(payload.hex())` called a nonexistent method — `Uint8Array` exposes
  `toHex()`, not `hex()`. Now uses the shared `toHex()` helper, consistent with
  the rest of the CLI. (Latent — same `init --store` gating masked it.)

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
