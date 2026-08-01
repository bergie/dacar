"""Smoketests for signed Operations / Deltas (§5.2, §5.3)."""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.hlc import pack
from dacar.operation import Action, Operation
from dacar.tuple import Tuple

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
ISSUER = bytes(range(HASH_SIZE))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
HLC = pack(1_700_000_000_000, 9)


def _tuple(object_id="sensor:wind", relation="calibrate", issuer=ISSUER) -> Tuple:
    return Tuple.from_plaintext(
        object_id=object_id, relation=relation, grantee=GRANTEE, issuer=issuer, hasher=HASHER
    )


def _keypair():
    return Ed25519PrivateKey.generate()


def _identity_hash(priv) -> bytes:
    """RNS-style identity hash: SHA-256(public key) truncated to 16 bytes."""
    import hashlib

    return hashlib.sha256(priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]


class PreimageTest(unittest.TestCase):
    def test_layout_matches_spec(self) -> None:
        op = Operation(tuple=_tuple(), action=Action.REVOKE, hlc=pack(42, 7))
        obj_hashes, _wild = HASHER.hash_object("sensor:wind")
        expected = (
            ISSUER
            + GRANTEE
            + bytes([0x00])  # action REVOKE
            + pack(42, 7).to_bytes(8, "big")
            + HASHER.hash_relation("calibrate")
            + bytes([0x00])  # wildcard flag
            + bytes([len(obj_hashes)])
            + b"".join(obj_hashes)
        )
        self.assertEqual(op.preimage(), expected)

    def test_wildcard_flag_set(self) -> None:
        op = Operation(
            tuple=_tuple(object_id="sensor:*", relation="admin"), action=Action.GRANT, hlc=HLC
        )
        self.assertEqual(op.preimage()[41 + 16], 0x01)  # wildcard byte after rel hash


class SingleSignTest(unittest.TestCase):
    def test_sign_verify_roundtrip(self) -> None:
        priv = _keypair()
        pub = priv.public_key()
        op = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC).sign(priv)
        self.assertTrue(op.verify(pub))
        self.assertFalse(op.verify(_keypair().public_key()))

    def test_tamper_detection(self) -> None:
        priv = _keypair()
        pub = priv.public_key()
        op = Operation(tuple=_tuple(), action=Action.GRANT, hlc=pack(1, 0)).sign(priv)
        tampered = Operation(
            tuple=_tuple(), action=Action.GRANT, hlc=pack(2, 0), signatures=op.signatures
        )
        self.assertFalse(tampered.verify(pub))


class ThresholdSignTest(unittest.TestCase):
    def test_n_of_m_succeeds(self) -> None:
        keys = [_keypair() for _ in range(3)]
        pubs = [k.public_key() for k in keys]
        op = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC).sign(keys[0], keys[1])
        self.assertTrue(op.verify_threshold(pubs, 2))

    def test_wrong_count_rejected(self) -> None:
        keys = [_keypair() for _ in range(3)]
        pubs = [k.public_key() for k in keys]
        op = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC).sign(keys[0], keys[1], keys[2])
        # 3 signatures but threshold 2 -> wrong count.
        self.assertFalse(op.verify_threshold(pubs, 2))

    def test_duplicate_member_rejected(self) -> None:
        keys = [_keypair() for _ in range(3)]
        pubs = [k.public_key() for k in keys]
        # Same member signs twice -> only one distinct public key verifies.
        pre = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC).preimage()
        op = Operation(
            tuple=_tuple(), action=Action.GRANT, hlc=HLC,
            signatures=(keys[0].sign(pre), keys[0].sign(pre)),
        )
        self.assertFalse(op.verify_threshold(pubs, 2))

    def test_non_member_signature_rejected(self) -> None:
        keys = [_keypair() for _ in range(3)]
        pubs = [k.public_key() for k in keys]
        outsider = _keypair()
        pre = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC).preimage()
        op = Operation(
            tuple=_tuple(), action=Action.GRANT, hlc=HLC,
            signatures=(keys[0].sign(pre), outsider.sign(pre)),
        )
        # One valid member + one outsider -> only 1 distinct member verifies.
        self.assertFalse(op.verify_threshold(pubs, 2))


class PayloadTest(unittest.TestCase):
    def test_roundtrip(self) -> None:
        priv = _keypair()
        op = Operation(
            tuple=_tuple(object_id="sensor:wind:north", relation="read"),
            action=Action.GRANT, hlc=HLC,
        ).sign(priv)
        restored = Operation.from_payload(op.to_payload())
        self.assertEqual(restored, op)
        self.assertTrue(restored.verify(priv.public_key()))

    def test_threshold_payload_roundtrip(self) -> None:
        keys = [_keypair() for _ in range(3)]
        pubs = [k.public_key() for k in keys]
        op = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC).sign(keys[0], keys[1])
        restored = Operation.from_payload(op.to_payload())
        self.assertEqual(restored.signatures, op.signatures)
        self.assertTrue(restored.verify_threshold(pubs, 2))

    def test_unsigned_payload_rejected(self) -> None:
        op = Operation(tuple=_tuple(), action=Action.GRANT, hlc=HLC)
        with self.assertRaises(ValueError):
            op.to_payload()


if __name__ == "__main__":
    unittest.main()
