"""Smoketests for the RNS Identity-backed KeyResolver (spec §3.1, §11.2.4).

A Dacar single-identity Issuer Hash is, by spec, a standard 16-byte RNS.Identity
hash. This resolver recalls such a hash from RNS's announce store and yields the
Identity's Ed25519 signing public key, so verify-on-ingest works on real network
Deltas with no out-of-band key exchange. We populate the recall store offline
via ``RNS.Identity.remember`` and exercise the full path: announce-able identity
-> signed Operation -> recall -> signature verify -> CRDT merge.

Requires the ``rns`` package (``dacar[transport]`` extra).
"""

from __future__ import annotations

import unittest

import RNS

from dacar import Action, DeltaReceiver, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.transport.rns_identity import RnsIdentityResolver
from tests._rns_fixture import ensure_headless

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
NOW = physical_now_ms()


def _op(issuer, signer=None):
    t = Tuple.from_plaintext(
        object_id="sensor:wind", relation="calibrate", grantee=GRANTEE,
        issuer=issuer, hasher=HASHER,
    )
    base = Operation(tuple=t, action=Action.GRANT, hlc=pack(NOW, 0))
    return base.sign(signer) if signer is not None else base


def _remember(identity):
    """Populate RNS's recall store for *identity* (as an announce would)."""
    RNS.Identity.remember(b"\x00" * 16, b"\x11" * 16, identity.get_public_key(), None)


class RnsIdentityResolverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.idn = RNS.Identity()
        self.issuer = self.idn.hash
        _remember(self.idn)

    # -- recall -> keyset --------------------------------------------------

    def test_resolve_returns_signing_public_key(self):
        keyset = RnsIdentityResolver().resolve(self.issuer)
        self.assertIsNotNone(keyset)
        self.assertEqual(keyset.threshold, 1)
        self.assertEqual(keyset.member_public_keys, (self.idn.sig_pub_bytes,))

    def test_resolve_callable_protocol(self):
        resolver = RnsIdentityResolver()
        self.assertEqual(resolver(self.issuer), resolver.resolve(self.issuer))

    def test_unknown_hash_returns_none_without_fallback(self):
        self.assertIsNone(RnsIdentityResolver().resolve(RNS.Identity().hash))

    # -- the real path: recall -> verify-on-ingest -> CRDT merge -----------

    def test_signed_delta_from_announced_identity_is_applied(self):
        op = _op(self.issuer, signer=self.idn.sig_prv)  # signed by the real RNS identity
        state = StateVector()
        rx = DeltaReceiver(state, RnsIdentityResolver())
        self.assertTrue(rx.apply_payload(op.to_payload(), now_ms=NOW))
        self.assertEqual(len(state), 1)

    def test_forged_signature_is_dropped(self):
        # Issuer hash recalls the real identity, but the op is signed by a
        # different key -> signature verification fails -> Delta dropped.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        op = _op(self.issuer, signer=Ed25519PrivateKey.generate())
        state = StateVector()
        rx = DeltaReceiver(state, RnsIdentityResolver())
        self.assertFalse(rx.apply_payload(op.to_payload(), now_ms=NOW))
        self.assertEqual(len(state), 0)

    # -- composition: RNS-first, then fallback ------------------------------

    def test_fallback_consulted_for_groups_and_unknowns(self):
        fallback = Keyring().register_single(b"\xaa" * HASH_SIZE, b"\xbb" * 32)
        resolver = RnsIdentityResolver(fallback=fallback)
        self.assertIsNotNone(resolver.resolve(b"\xaa" * HASH_SIZE))  # fallback single
        self.assertIsNone(resolver.resolve(RNS.Identity().hash))  # neither knows it

    def test_rns_takes_precedence_over_fallback(self):
        # Fallback would answer the issuer with a *wrong* key; RNS must win.
        fallback = Keyring().register_single(self.issuer, b"\xcc" * 32)
        keyset = RnsIdentityResolver(fallback=fallback).resolve(self.issuer)
        self.assertEqual(keyset.member_public_keys, (self.idn.sig_pub_bytes,))


if __name__ == "__main__":
    unittest.main()
