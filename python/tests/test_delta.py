"""Smoketests for the transport-agnostic Delta receive boundary (§11.2.4)."""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar import (
    Action,
    DeltaReceiver,
    Keyring,
    Operation,
    StateVector,
    Tuple,
    group_id,
)
from dacar.hlc import pack
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
HLC = pack(1_700_000_000_000, 0)


def _identity_hash(priv: Ed25519PrivateKey) -> bytes:
    """RNS-style identity hash: SHA-256(public key) truncated to 16 bytes."""
    import hashlib

    return hashlib.sha256(priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]


def _op(issuer: bytes, *, signers=()) -> Operation:
    t = Tuple.from_plaintext(
        object_id="sensor:wind", relation="calibrate", grantee=GRANTEE,
        issuer=issuer, hasher=HASHER,
    )
    base = Operation(tuple=t, action=Action.GRANT, hlc=HLC)
    return base.sign(*signers) if signers else base


class ApplyPayloadTest(unittest.TestCase):
    def test_valid_signed_delta_is_applied(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _op(issuer, signers=(priv,))
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertTrue(rx.apply_payload(op.to_payload(), now_ms=1_700_000_000_000))
        self.assertTrue(state.is_active(op.tuple.hash()))

    def test_forged_delta_is_dropped(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _op(issuer, signers=(Ed25519PrivateKey.generate(),))  # wrong signer
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertFalse(rx.apply_payload(op.to_payload(), now_ms=1_700_000_000_000))
        self.assertEqual(len(state), 0)

    def test_malformed_payload_is_swallowed(self) -> None:
        """A transport callback must never crash on arbitrary bytes."""
        state = StateVector()
        rx = DeltaReceiver(state, Keyring())
        self.assertFalse(rx.apply_payload(b"not a msgpack payload at all"))
        self.assertFalse(rx.apply_payload(b""))
        self.assertFalse(rx.apply_payload(b"\x00\x01\x02"))  # truncated
        self.assertEqual(len(state), 0)

    def test_unknown_issuer_is_dropped(self) -> None:
        priv = Ed25519PrivateKey.generate()
        op = _op(_identity_hash(priv), signers=(priv,))
        state = StateVector()
        rx = DeltaReceiver(state, Keyring())  # empty keyring
        self.assertFalse(rx.apply_payload(op.to_payload(), now_ms=1_700_000_000_000))
        self.assertEqual(len(state), 0)

    def test_valid_threshold_delta_is_applied(self) -> None:
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes_raw() for k in keys]
        members = [_identity_hash(k) for k in keys]
        gid = group_id(members, 2)
        op = _op(gid, signers=(keys[0], keys[1]))
        kr = Keyring().register_group(gid, pubs, 2)
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertTrue(rx.apply_payload(op.to_payload(), now_ms=1_700_000_000_000))
        self.assertTrue(state.is_active(op.tuple.hash()))


if __name__ == "__main__":
    unittest.main()
