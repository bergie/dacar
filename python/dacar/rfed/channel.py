"""Deterministic rfed channel derivation.

A channel is a deterministic :class:`RNS.Identity` derived from a plain-text
channel name. Any party that knows the name independently arrives at the same
identity hash ("channel hash") and keypair, so senders can encrypt to the
channel and subscribers can decrypt — with no server-side registration.

Algorithm (``RFed/SPEC.md`` §1)::

    seed          = SHA-256(channel_name)                 → 32 bytes
    x25519_priv   = seed
    ed25519_priv   = seed
    x25519_pub    = X25519_public_key(seed)               → 32 bytes
    ed25519_pub   = Ed25519_public_key(seed)              → 32 bytes
    bundle        = x25519_pub ‖ ed25519_pub              → 64 bytes
    channel_hash  = SHA-256(bundle)[0..16]                → 16 bytes

The channel's private-key bundle is ``seed ‖ seed`` (the same 32-byte
``SHA-256(name)`` scalar used for both X25519 and Ed25519), matching the Rust
reference's ``private_key_bundle = seed || seed`` and the canonical Python
``channel_hash.compute_channel_hash`` vectors.

This module uses :mod:`RNS` only for its cryptography primitives
(:func:`RNS.Identity.full_hash` / :func:`RNS.Identity.truncated_hash`), so it
works **without a running Reticulum** — only :class:`~RNS.Destination` creation
needs a live transport.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

import RNS

from dacar.rfed.constants import LXMF_DELIVERY_NAME

__all__ = ["derive_channel", "delivery_hash_for", "channel_path"]


def _identity_from_seed(seed: bytes) -> RNS.Identity:
    """Build a full RNS Identity (both private keys) from a 32-byte seed.

    The private-key bundle is ``seed ‖ seed`` (X25519 seed ‖ Ed25519 seed),
    matching the Rust/Python references.
    """
    if len(seed) != 32:
        raise ValueError("channel seed must be 32 bytes")
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(seed + seed)
    return identity


def derive_channel(name: str) -> Tuple[RNS.Identity, bytes]:
    """Derive a channel's deterministic Identity and 16-byte channel hash.

    Parameters
    ----------
    name:
        Dot-separated channel name (e.g. ``"dacar.policy.v1"`` or a
        ``"<hex>.<segments>"`` private channel).

    Returns
    -------
    (identity, channel_hash)
        ``identity`` is a full RNS Identity holding both private keys, so it can
        encrypt, decrypt, and derive its ``lxmf.delivery`` hash.
        ``channel_hash`` is the 16-byte channel identity hash used as the rfed
        routing label.
    """
    seed = hashlib.sha256(name.encode("utf-8")).digest()
    identity = _identity_from_seed(seed)
    # identity.hash is SHA-256(pub_bundle)[:16], already the channel hash.
    return identity, identity.hash


def delivery_hash_for(identity: RNS.Identity) -> bytes:
    """Compute the ``lxmf.delivery`` destination hash for an Identity.

    The 16-byte truncated ``SHA-256(name_hash("lxmf.delivery") ‖ identity_hash)``.

    For a channel message this is the LXMF ``destination_hash`` the sender signs
    over (the channel's delivery address), **not** the bare channel identity
    hash. Confusing the two is the classic rfed bug — see
    ``RFed/SPEC.md`` "CANONICAL WIRE FORMAT" invariants.
    """
    name_hash = RNS.Identity.full_hash(LXMF_DELIVERY_NAME.encode("utf-8"))
    name_hash = name_hash[: RNS.Identity.NAME_HASH_LENGTH // 8]  # first 10 bytes
    return RNS.Identity.truncated_hash(name_hash + identity.hash)


def channel_path(*segments: str) -> str:
    """Join channel-name segments with ``.`` (mirrors RNS aspect notation)."""
    return ".".join(segments)
