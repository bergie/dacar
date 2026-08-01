"""Smoketests for the Strict Consistency Challenge (§8)."""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar.challenge import (
    AuthoritativeServer,
    Challenge,
    ChallengeClient,
    Receipt,
    Verdict,
)
from dacar.config import Config
from dacar.crdt import StateVector
from dacar.hlc import pack
from dacar.operation import Action, Operation
from dacar.tuple import HASH_SIZE, Tuple

ROOT = bytes(range(HASH_SIZE))
BOB = bytes(range(HASH_SIZE, HASH_SIZE * 2))
NONCE = bytes(range(32))


def _allow_state() -> StateVector:
    """A state in which BOB may calibrate sensor:wind, issued by ROOT."""
    state = StateVector()
    state.apply(
        Operation(
            tuple=Tuple("sensor:wind", "calibrate", BOB, ROOT),
            action=Action.GRANT,
            hlc=pack(1_700_000_000_000, 0),
        )
    )
    return state


def _config() -> Config:
    return Config(root_trust_anchors=frozenset({ROOT}), authoritative_identity=ROOT)


class ReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes_raw()

    def test_preimage_layout(self) -> None:
        receipt = Receipt(Verdict.ALLOW, pack(42, 1), NONCE)
        self.assertEqual(len(receipt.preimage()), 41)
        self.assertEqual(
            receipt.preimage(),
            bytes([0x01]) + pack(42, 1).to_bytes(8, "big") + NONCE,
        )

    def test_sign_verify_roundtrip(self) -> None:
        receipt = Receipt(Verdict.ALLOW, pack(1, 0), NONCE).sign(self.private_key)
        self.assertTrue(receipt.verify(self.public_bytes))

    def test_tamper_detection(self) -> None:
        receipt = Receipt(Verdict.ALLOW, pack(1, 0), NONCE).sign(self.private_key)
        bad = Receipt(Verdict.DENY, pack(1, 0), NONCE, receipt.signature)
        self.assertFalse(bad.verify(self.public_bytes))

    def test_payload_roundtrip(self) -> None:
        receipt = Receipt(Verdict.ALLOW, pack(7, 2), NONCE).sign(self.private_key)
        restored = Receipt.from_payload(receipt.to_payload())
        self.assertEqual(restored, receipt)
        self.assertTrue(restored.verify(self.public_bytes))


class ChallengeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes_raw()

    def test_challenge_nonce_roundtrip(self) -> None:
        ch = Challenge.generate("o", "r", BOB)
        self.assertEqual(len(ch.nonce), 32)
        restored = Challenge.from_payload(ch.to_payload())
        self.assertEqual(restored, ch)

    def test_fixed_nonce(self) -> None:
        ch = Challenge.generate("o", "r", BOB, nonce=NONCE)
        self.assertEqual(ch.nonce, NONCE)


class FlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes_raw()

    def _wire(self, client_state: StateVector, server_state: StateVector) -> ChallengeClient:
        server = AuthoritativeServer(_config(), server_state, self.private_key)
        return ChallengeClient(_config(), client_state, self.public_bytes, server.handle)

    def test_server_allows_and_client_proceeds(self) -> None:
        client = self._wire(_allow_state(), _allow_state())
        self.assertTrue(client.authorize("sensor:wind", "calibrate", BOB))

    def test_local_pre_check_denies_without_challenge(self) -> None:
        calls = []
        server = AuthoritativeServer(_config(), _allow_state(), self.private_key)

        def transport(payload: bytes):
            calls.append(payload)
            return server.handle(payload)

        # Empty client state -> local pre-check fails -> transport never used.
        client = ChallengeClient(_config(), StateVector(), self.public_bytes, transport)
        self.assertFalse(client.authorize("sensor:wind", "calibrate", BOB))
        self.assertEqual(calls, [])

    def test_server_deny_overrides_local_allow(self) -> None:
        # Client believes BOB is allowed; server (latest state) has revoked.
        revoked = _allow_state()
        revoked.apply(
            Operation(
                tuple=Tuple("sensor:wind", "calibrate", BOB, ROOT),
                action=Action.REVOKE,
                hlc=pack(1_700_000_000_000, 5),
            )
        )
        client = self._wire(_allow_state(), revoked)
        self.assertFalse(client.authorize("sensor:wind", "calibrate", BOB))

    def test_partition_penalty_timeout(self) -> None:
        client = ChallengeClient(
            _config(), _allow_state(), self.public_bytes, lambda _payload: None
        )
        self.assertFalse(client.authorize("sensor:wind", "calibrate", BOB))

    def test_transport_exception_is_partition(self) -> None:
        def boom(_payload: bytes):
            raise ConnectionError("link down")

        client = ChallengeClient(_config(), _allow_state(), self.public_bytes, boom)
        self.assertFalse(client.authorize("sensor:wind", "calibrate", BOB))

    def test_wrong_nonce_rejected(self) -> None:
        server = AuthoritativeServer(_config(), _allow_state(), self.private_key)

        def transport(payload: bytes) -> bytes:
            receipt = Receipt.from_payload(server.handle(payload))
            # Swap in a different nonce than the one we challenged with.
            return replace_receipt_nonce(receipt, bytes(range(1, 33))).to_payload()

        client = ChallengeClient(_config(), _allow_state(), self.public_bytes, transport)
        self.assertFalse(client.authorize("sensor:wind", "calibrate", BOB))

    def test_bad_signature_rejected(self) -> None:
        attacker = Ed25519PrivateKey.generate()
        server = AuthoritativeServer(_config(), _allow_state(), attacker)
        # Client trusts the *real* authoritative key, not the attacker's.
        client = ChallengeClient(
            _config(),
            _allow_state(),
            self.private_key.public_key(),
            server.handle,
        )
        self.assertFalse(client.authorize("sensor:wind", "calibrate", BOB))

    def test_authoritative_identity_required(self) -> None:
        cfg = Config(root_trust_anchors=frozenset({ROOT}))  # no authoritative id
        with self.assertRaises(ValueError):
            ChallengeClient(cfg, StateVector(), self.public_bytes, lambda _: None)


def replace_receipt_nonce(receipt: Receipt, nonce: bytes) -> Receipt:
    """Return a copy of ``receipt`` with a different (unsigned-over) nonce."""
    return Receipt(receipt.verdict, receipt.server_hlc, nonce, receipt.signature)


if __name__ == "__main__":
    unittest.main()
