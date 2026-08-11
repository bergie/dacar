# Dacar - Decentralized Access Control over Reticulum

Traditionally networked [Reticulum](https://reticulum.network) applications have handled authorization using allow lists of Reticulum identities provided either over CLI flags or a configuration file. This becomes cumbersome to manage in larger deployments or when rotating identities.

Dacar is a specification aiming to help with this, providing a way to grant and revoke permissions over the Reticulum network.

- **No central server.** Every node evaluates permissions locally using its own copy of the CRDT, even fully offline.
- **Trust flows downhill from a root.** A small set of Root Trust Anchors can delegate permissions to admins, who can delegate further, but every chain has to trace back to one of those anchors.
- **Transport-agnostic by design.** Permission changes are small signed deltas that can travel over RFed broadcast, LXMF store-and-forward (including to offline nodes), or even physical QR codes — whatever Reticulum path is available.
- **Syncs eventually, not instantly.** Nodes merge state whenever they connect, with no requirement for real-time connectivity.
- **Deny beats allow.** An explicit revocation always overrides a grant.
- **A safety valve for high-stakes actions.** For destructive operations, a node can open an RNS.Link to an authoritative identity for a live, signed verdict instead of trusting possibly-stale local state.
- **Built for constrained hardware.** Old, resolved history gets pruned on a schedule, and object/permission names are hashed rather than sent in plain text.

See [SPEC.md](SPEC.md) for the actual specification.

## Using Dacar

Dacar acts as a decentralized authorization firewall for your off-grid systems. It decouples who is allowed to do what from the network transport, allowing edge nodes to make secure access decisions while completely offline.

1. Generate & Share the Privacy Salt: All nodes in a Dacar deployment MUST share the same 32-byte Privacy Salt (§3.3). This salt is used to hash object and relation labels for privacy. Without a shared salt, grants become opaque/unusable (the CRDT still converges, but plaintext queries like `bob switch device:anchorLight` won't match the stored hashed entries).

   Generate the salt **once** on your admin machine, then distribute it out-of-band to every node:

   ```bash
   # Generate a cryptographically secure salt (run ONCE)
   openssl rand -hex 32 > dacar-salt.hex
   # or: python3 -c "import secrets; print(secrets.token_bytes(32).hex())" > dacar-salt.hex

   # View the salt (hex) for safekeeping:
   cat dacar-salt.hex
   ```

   Copy `dacar-salt.hex` to every node via your chosen transport (USB, QR code, LXMF, etc.) and use it when initializing:

   ```bash
   # On each node: initialize with the shared salt
   dacar init --salt dacar-salt.hex

   # Verify the salt is set:
   dacar config show --reveal
   ```

2. Bootstrap the Trust Anchor: Create a Root Trust Anchor, the public Reticulum identity of the master administrator(s). Copy this Trust Anchor to all devices where you want to utilize Dacar permissions.

   ```bash
   dacar init                    # bootstrap the node store + own identity (aliased `self`)
   dacar identity show           # print the node's identity hash (its root trust anchor)
   dacar anchor add 7f3a9c2b…    # trust a remote root anchor on an edge device
   ```

3. Map Identities: In your local applications, you associate external user accounts with their 16-byte Reticulum Identity hashes (for example, `lille-oe` is `bbf0ba6afee382db3c7681a4e8e74a84`)

   ```bash
   dacar alias add lille-oe bbf0ba6afee382db3c7681a4e8e74a84
   dacar alias add bob <bob-identity-hash>
   dacar alias list
   ```

4. Issue Grants: From your admin machine, you generate and cryptographically sign an Operation (a Delta) granting a specific identity a permission over an object (e.g., _Bob_ is allowed to `switch` the `device:anchorLight`).

   ```bash
   dacar grant bob switch device:anchorLight                          # sign + apply locally; hex payload on stdout
   dacar grant bob switch device:anchorLight --no-apply > delta.hex   # export a signed delta only
   dacar grant bob switch device:anchorLight --publish                # …or publish directly to the rfed channel
   ```

5. Sync the State: You transmit this signed payload to the edge device over any available transport—broadcast it via RFed, send it point-to-point via LXMF over VHF/LoRa, or physically scan it as a QR code. The device merges this delta into its local CRDT state.

   ```bash
   dacar publish delta.hex                              # publish a previously-exported signed delta later (work doc #8)
   dacar publish --all                                  # …or flush every pending locally-issued delta queued since the last `--publish`
   dacar apply delta.hex                                # ingest a received delta (verify-on-ingest)
   dacar sync                                           # pull pending deltas from the rfed channel
   ```

6. Enforce Locally: When _Bob_ attempts to switch on the light, the local application intercepts the request and queries the local Dacar Evaluation Engine. Dacar checks its internal state and immediately approves or denies the action based on cryptographic proof—without ever needing to phone home to a central server.

   ```bash
   dacar check bob switch device:anchorLight   # local Engine.evaluate → ALLOW/DENY
   dacar grants --effective                    # list grants with ✔/⚠ authority tracing
   ```

See the [Python](python/README.md) and [JavaScript](javascript/README.md) implementation READMEs for the full `dacar` command reference. In addition to CLI, all these operations can be done inside your application using the Dacar library.

## Status

Just getting started

## Implementations

This repository contains implementations of the Dacar spec for several programming languages.

### Python

Python implementation of Dacar, a Decentralized Access Control system for Reticulum.

### JavaScript

JavaScript implementation of Dacar, a Decentralized Access Control system for Reticulum. Runs in browsers and on servers (Node, Deno, Bun), built on `@reticulum/core`.

## Development

You can install dependencies for all implementations with:
```
make install
```

Run tests with:
```
make test
```

## License

EUPL-1.2

## Acknowledgements

Inspired by Google Zanzibar.

Both the spec and the implementations have received significant assistance from various Large Language Models, more particularly Gemini 3.1 Pro, Claude Sonnet 5, and GLM 5.
