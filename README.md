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
