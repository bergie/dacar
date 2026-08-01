"""Smoketests for signed Operations / Deltas (§5.2, §5.3)."""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar.hlc import pack
from dacar.operation import Action, Operation
from dacar.tuple import HASH_SIZE, Tuple

ISSUER = bytes(range(HASH_SIZE))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))


def _identity() -> tuple[Ed25519PrivateKey, bytes]:
    """Return (private_key, public_key_bytes) for a fresh Ed25519 identity.

    Note: this is NOT how RNS.Identity derives its hash; here we only need a
    keypair whose public bytes can validate signatures for smoketest purposes.
    """
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_bytes


class OperationTest(unittest.TestCase):
    def test_sign_verify_roundtrip(self) -> None:
        private_key, pub = _identity()
        op = Operation(
            tuple=Tuple("sensor:wind", "calibrate", GRANTEE, ISSUER),
            action=Action.GRANT,
            hlc=pack(1_700_000_000_000, 0),
        ).sign(private_key)
        self.assertTrue(op.verify(pub))
        self.assertFalse(op.verify(Ed25519PrivateKey.generate().public_key()))

    def test_preimage_layout(self) -> None:
        op = Operation(
            tuple=Tuple("o", "rel", GRANTEE, ISSUER),
            action=Action.REVOKE,
            hlc=pack(42, 7),
        )
        expected = (
            ISSUER
            + GRANTEE
            + bytes([0x00])
            + pack(42, 7).to_bytes(8, "big")
            + bytes([3])
            + b"rel"
            + b"o"
        )
        self.assertEqual(op.preimage(), expected)

    def test_tamper_detection(self) -> None:
        private_key, pub = _identity()
        op = Operation(
            tuple=Tuple("o", "r", GRANTEE, ISSUER),
            action=Action.GRANT,
            hlc=pack(1, 0),
        ).sign(private_key)
        tampered = Operation(
            tuple=Tuple("o", "r", GRANTEE, ISSUER),
            action=Action.GRANT,
            hlc=pack(2, 0),  # different timestamp
            signature=op.signature,
        )
        self.assertFalse(tampered.verify(pub))

    def test_payload_roundtrip(self) -> None:
        private_key, pub = _identity()
        op = Operation(
            tuple=Tuple("sensor:wind:north", "calibrate", GRANTEE, ISSUER),
            action=Action.GRANT,
            hlc=pack(1_700_000_000_000, 9),
        ).sign(private_key)
        wire = op.to_payload()
        restored = Operation.from_payload(wire)
        self.assertEqual(restored, op)
        self.assertTrue(restored.verify(pub))

    def test_unsigned_payload_rejected(self) -> None:
        op = Operation(
            tuple=Tuple("o", "r", GRANTEE, ISSUER),
            action=Action.GRANT,
            hlc=pack(1, 0),
        )
        with self.assertRaises(ValueError):
            op.to_payload()


if __name__ == "__main__":
    unittest.main()
