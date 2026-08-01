"""Smoketests for verify-on-ingest: Ed25519 authentication of Deltas (§11.2.4)."""

from __future__ import annotations

import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar import (
    Action,
    IssuerKeyset,
    Keyring,
    Operation,
    StateVector,
    Tuple,
    group_id,
    verify_operation,
)
from dacar.hlc import pack
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
HLC = pack(1_700_000_000_000, 0)


def _identity_hash(priv: Ed25519PrivateKey) -> bytes:
    """RNS-style identity hash: SHA-256(public key) truncated to 16 bytes."""
    return hashlib.sha256(priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]


def _tuple(issuer: bytes, *, object_id="sensor:wind", relation="calibrate"):
    return Operation(
        tuple=Tuple.from_plaintext(
            object_id=object_id, relation=relation, grantee=GRANTEE,
            issuer=issuer, hasher=HASHER,
        ),
        action=Action.GRANT, hlc=HLC,
    )


class IssuerKeysetTest(unittest.TestCase):
    def test_single_defaults_to_threshold_one(self) -> None:
        ks = IssuerKeyset.single(bytes(32))
        self.assertEqual(ks.threshold, 1)
        self.assertEqual(len(ks.member_public_keys), 1)

    def test_group_keeps_keys_and_threshold(self) -> None:
        ks = IssuerKeyset.group([bytes(32), b"\x01" * 32, b"\x02" * 32], 2)
        self.assertEqual(ks.threshold, 2)
        self.assertEqual(len(ks.member_public_keys), 3)

    def test_bad_key_length_rejected(self) -> None:
        with self.assertRaises(ValueError):
            IssuerKeyset.single(bytes(31))

    def test_threshold_below_one_rejected(self) -> None:
        with self.assertRaises(ValueError):
            IssuerKeyset((bytes(32),), 0)

    def test_fewer_keys_than_threshold_rejected(self) -> None:
        with self.assertRaises(ValueError):
            IssuerKeyset((bytes(32),), 2)


class KeyringTest(unittest.TestCase):
    def test_resolve_returns_registered_keyset(self) -> None:
        kr = Keyring().register_single(b"\xaa" * 16, bytes(32))
        ks = kr.resolve(b"\xaa" * 16)
        self.assertIsNotNone(ks)
        self.assertEqual(ks.threshold, 1)

    def test_resolve_unknown_returns_none(self) -> None:
        self.assertIsNone(Keyring().resolve(b"\xbb" * 16))

    def test_keyring_is_callable(self) -> None:
        kr = Keyring().register_single(b"\xaa" * 16, bytes(32))
        self.assertIs(kr(b"\xaa" * 16), kr.resolve(b"\xaa" * 16))
        self.assertIsNone(kr(b"\xff" * 16))


class VerifyOperationTest(unittest.TestCase):
    def test_single_valid_signature(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _tuple(issuer).sign(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        self.assertTrue(verify_operation(op, kr))

    def test_tampered_operation_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _tuple(issuer).sign(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        # Rebuild with a different HLC but keep the (now invalid) signature.
        tampered = Operation(tuple=op.tuple, action=Action.GRANT, hlc=pack(1, 1), signatures=op.signatures)
        self.assertFalse(verify_operation(tampered, kr))

    def test_unknown_issuer_rejected(self) -> None:
        priv = Ed25519PrivateKey.generate()
        op = _tuple(_identity_hash(priv)).sign(priv)
        # Empty keyring -> issuer unresolvable -> unverifiable.
        self.assertFalse(verify_operation(op, Keyring()))

    def test_forged_root_issuer_rejected(self) -> None:
        """Attacker claims issuer=ROOT but signs with their own key."""
        root = Ed25519PrivateKey.generate()
        root_hash = _identity_hash(root)
        attacker = Ed25519PrivateKey.generate()
        op = _tuple(root_hash).sign(attacker)  # signed by attacker, not root
        kr = Keyring().register_single(root_hash, root.public_key().public_bytes_raw())
        self.assertFalse(verify_operation(op, kr))

    def test_threshold_n_of_m_valid(self) -> None:
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes_raw() for k in keys]
        members = [_identity_hash(k) for k in keys]
        gid = group_id(members, 2)
        op = _tuple(gid).sign(keys[0], keys[1])
        kr = Keyring().register_group(gid, pubs, 2)
        self.assertTrue(verify_operation(op, kr))

    def test_threshold_below_n_rejected(self) -> None:
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes_raw() for k in keys]
        members = [_identity_hash(k) for k in keys]
        gid = group_id(members, 2)
        op = _tuple(gid).sign(keys[0])  # only 1 of 2 required
        kr = Keyring().register_group(gid, pubs, 2)
        self.assertFalse(verify_operation(op, kr))

    def test_threshold_non_member_rejected(self) -> None:
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes_raw() for k in keys]
        members = [_identity_hash(k) for k in keys]
        gid = group_id(members, 2)
        outsider = Ed25519PrivateKey.generate()
        op = _tuple(gid).sign(keys[0], outsider)
        kr = Keyring().register_group(gid, pubs, 2)
        self.assertFalse(verify_operation(op, kr))


class IngestTest(unittest.TestCase):
    def test_valid_single_applied(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _tuple(issuer).sign(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        state = StateVector()
        self.assertTrue(state.ingest(op, kr, now_ms=1_700_000_000_000))
        self.assertTrue(state.is_active(op.tuple.hash()))

    def test_forged_op_not_applied(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _tuple(issuer).sign(Ed25519PrivateKey.generate())  # wrong signer
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        state = StateVector()
        self.assertFalse(state.ingest(op, kr, now_ms=1_700_000_000_000))
        self.assertFalse(state.is_active(op.tuple.hash()))
        self.assertEqual(len(state), 0)

    def test_unknown_issuer_not_applied(self) -> None:
        priv = Ed25519PrivateKey.generate()
        op = _tuple(_identity_hash(priv)).sign(priv)
        state = StateVector()
        self.assertFalse(state.ingest(op, Keyring(), now_ms=1_700_000_000_000))
        self.assertEqual(len(state), 0)

    def test_valid_threshold_applied(self) -> None:
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes_raw() for k in keys]
        members = [_identity_hash(k) for k in keys]
        gid = group_id(members, 2)
        op = _tuple(gid).sign(keys[0], keys[2])
        kr = Keyring().register_group(gid, pubs, 2)
        state = StateVector()
        self.assertTrue(state.ingest(op, kr, now_ms=1_700_000_000_000))
        self.assertTrue(state.is_active(op.tuple.hash()))

    def test_apply_trusted_path_does_not_verify(self) -> None:
        """apply() trusts its caller: an unsigned op still applies."""
        op = _tuple(b"\xcc" * 16)
        state = StateVector()
        self.assertTrue(state.apply(op, now_ms=1_700_000_000_000))
        self.assertTrue(state.is_active(op.tuple.hash()))


if __name__ == "__main__":
    unittest.main()
