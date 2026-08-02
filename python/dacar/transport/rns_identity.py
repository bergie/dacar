"""RNS Identity-backed :data:`KeyResolver` (spec §3.1, §11.2.4).

By spec a Dacar single-identity Issuer Hash **is** a standard 16-byte
``RNS.Identity`` hash -- which RNS defines as ``SHA-256`` of the 64-byte RNS
public key (``X25519_encryption ‖ Ed25519_signing``), truncated to 16 bytes.
This resolver turns such a hash into the 32-byte Ed25519 signing public key
needed to verify an Operation's signature, by querying RNS's Identity *recall*
store -- the same store a live Reticulum populates from announce interception.

Dacar's verify-on-ingest (§11.2.4) therefore works on real network Deltas
without any out-of-band key exchange: an announced Identity is recalled by its
hash, and the Operation it claims to be from is signature-checked against that
Identity's signing key.

Threshold Groups (§4.1) cannot be resolved this way: their Group ID is a
composite hash (``SHA-256(sorted member hashes ‖ N)[:16]``), not an RNS
identity, so RNS has nothing to recall. They -- and any out-of-band single
identities -- are delegated to an optional *fallback* resolver (e.g. a
:class:`~dacar.verifier.Keyring` of pre-registered group keysets). Resolvers are
consulted RNS-first, then fallback, so announced identities always win.

Requires the ``rns`` package; import from the optional ``transport`` extra.
"""

from __future__ import annotations

from typing import Optional

import RNS

from dacar.verifier import IssuerKeyset, KeyResolver

__all__ = ["RnsIdentityResolver"]


class RnsIdentityResolver:
    """Resolves single-identity Issuer hashes via the RNS Identity recall store.

    Parameters
    ----------
    fallback:
        Optional resolver consulted when RNS has no Identity for a hash -- e.g.
        for Threshold Group IDs and out-of-band identities. RNS is consulted
        first, then the fallback.
    """

    def __init__(self, fallback: Optional[KeyResolver] = None) -> None:
        self._fallback = fallback

    def resolve(self, issuer_hash: bytes) -> Optional[IssuerKeyset]:
        """Resolve a 16-byte Issuer hash to an :class:`IssuerKeyset`, or ``None``."""
        identity = RNS.Identity.recall(bytes(issuer_hash), from_identity_hash=True)
        if identity is not None:
            sig_pub = getattr(identity, "sig_pub_bytes", None)
            if sig_pub is not None:
                return IssuerKeyset.single(sig_pub)
        if self._fallback is not None:
            return self._fallback(bytes(issuer_hash))
        return None

    def __call__(self, issuer_hash: bytes) -> Optional[IssuerKeyset]:
        """Use directly as a :data:`KeyResolver` callable."""
        return self.resolve(issuer_hash)
