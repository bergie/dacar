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
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.operation import Action, Operation
from dacar.tuple import Tuple

SALT = bytes(range(SALT_SIZE))
HASHER = NamespaceHasher(SALT)
ROOT = bytes(range(HASH_SIZE))
BOB = bytes(range(HASH_SIZE, HASH_SIZE * 2))
NONCE = bytes(range(32))


def _allow_state() -> StateVector:
    """A state in which BOB may calibrate sensor:wind, issued by ROOT."""
    state = StateVector()
    state.apply(
        Operation(
            tuple=Tuple.from_plaintext(
                object_id="sensor:wind", relation="calibrate",
                grantee=BOB, issuer=ROOT, hasher=HASHER,
            ),
            action=Action.GRANT,
            hlc=pack(1_700_000_000_000, 0),
        ),
        now_ms=1_700_000_000_000,
    )
    return state


def _config() -> Config:
    return Config(
        root_trust_anchors=frozenset({ROOT}),
        primary_salt=SALT,
        authoritative_identity=ROOT,
    )


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


class ChallengePayloadTest(unittest.TestCase):
    def test_roundtrip_preserves_nonce_and_grantee(self) -> None:
        ch = Challenge.generate("sensor:wind", "calibrate", BOB, [HASHER], nonce=NONCE)
        decoded = Challenge.from_payload(ch.to_payload())
        self.assertEqual(decoded.nonce, NONCE)
        self.assertEqual(decoded.grantee, BOB)
        self.assertEqual(len(decoded.entries), 1)
        entry = decoded.entries[0]
        self.assertEqual(entry.grantee_hash, BOB)
        self.assertEqual(entry.allow_relation_hash, HASHER.hash_relation("calibrate"))
        self.assertEqual(entry.deny_relation_hash, HASHER.hash_relation("-calibrate"))

    def test_payload_carries_no_plaintext(self) -> None:
        ch = Challenge.generate("sensor:wind", "calibrate", BOB, [HASHER], nonce=NONCE)
        payload = ch.to_payload()
        # The plaintext labels must not appear anywhere in the wire bytes.
        self.assertNotIn(b"sensor", payload)
        self.assertNotIn(b"wind", payload)
        self.assertNotIn(b"calibrate", payload)

    def test_multi_salt_emits_one_entry_per_salt(self) -> None:
        legacy = NamespaceHasher(bytes(reversed(range(SALT_SIZE))))
        ch = Challenge.generate("o", "r", BOB, [HASHER, legacy], nonce=NONCE)
        decoded = Challenge.from_payload(ch.to_payload())
        self.assertEqual(len(decoded.entries), 2)
        tags = {e.salt_id_tag for e in decoded.entries}
        self.assertEqual(tags, {HASHER.id_tag, legacy.id_tag})


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
                tuple=Tuple.from_plaintext(
                    object_id="sensor:wind", relation="calibrate",
                    grantee=BOB, issuer=ROOT, hasher=HASHER,
                ),
                action=Action.REVOKE,
                hlc=pack(1_700_000_000_000, 5),
            ),
            now_ms=1_700_000_000_000,
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
            swapped = Receipt(receipt.verdict, receipt.server_hlc, bytes(range(1, 33)), receipt.signature)
            return swapped.to_payload()

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
        cfg = Config(root_trust_anchors=frozenset({ROOT}), primary_salt=SALT)
        with self.assertRaises(ValueError):
            ChallengeClient(cfg, StateVector(), self.public_bytes, lambda _: None)


if __name__ == "__main__":
    unittest.main()
