# Changelog

All notable changes to Dacar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-RC7] - 2024-08-08

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
