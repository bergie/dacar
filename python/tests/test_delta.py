"""Smoketests for the transport-agnostic Delta receive boundary (§11.2.4)."""

from __future__ import annotations

import unittest
import warnings

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar import (
    Action,
    DeltaReceiver,
    Keyring,
    Operation,
    StateVector,
    Tuple,
    TrustedLocalOnlyWarning,
    group_id,
)
from dacar import serialization
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


class ApplyPayloadsTest(unittest.TestCase):
    """The authenticated batch path: the secure alternative to merge()."""

    def test_batch_of_valid_deltas_all_applied(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        op_a = _op(issuer, signers=(priv,))
        # second grant for a different object so they are distinct tuples
        op_b = Operation(
            tuple=Tuple.from_plaintext(
                object_id="sensor:temp", relation="read", grantee=GRANTEE,
                issuer=issuer, hasher=HASHER,
            ),
            action=Action.GRANT, hlc=HLC,
        ).sign(priv)
        batch = DeltaReceiver.pack_payloads([op_a.to_payload(), op_b.to_payload()])
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertEqual(rx.apply_payloads(batch, now_ms=1_700_000_000_000), 2)
        self.assertTrue(state.is_active(op_a.tuple.hash()))
        self.assertTrue(state.is_active(op_b.tuple.hash()))

    def test_forged_element_is_dropped_rest_applied(self) -> None:
        priv = Ed25519PrivateKey.generate()
        attacker = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        good = _op(issuer, signers=(priv,))
        forged = _op(issuer, signers=(attacker,))  # claims same issuer, wrong sig
        batch = DeltaReceiver.pack_payloads([good.to_payload(), forged.to_payload()])
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertEqual(rx.apply_payloads(batch, now_ms=1_700_000_000_000), 1)
        self.assertTrue(state.is_active(good.tuple.hash()))

    def test_unknown_issuer_element_is_dropped(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        op = _op(issuer, signers=(priv,))
        batch = DeltaReceiver.pack_payloads([op.to_payload()])
        state = StateVector()
        rx = DeltaReceiver(state, Keyring())  # empty keyring
        self.assertEqual(rx.apply_payloads(batch, now_ms=1_700_000_000_000), 0)
        self.assertEqual(len(state), 0)

    def test_malformed_outer_payload_is_swallowed(self) -> None:
        state = StateVector()
        rx = DeltaReceiver(state, Keyring())
        self.assertEqual(rx.apply_payloads(b"not msgpack"), 0)
        self.assertEqual(rx.apply_payloads(b""), 0)
        # a msgpack value that is not an array
        self.assertEqual(rx.apply_payloads(serialization.packb(42)), 0)
        self.assertEqual(rx.apply_payloads(serialization.packb("x")), 0)
        self.assertEqual(len(state), 0)

    def test_non_bin_elements_are_skipped_not_fatal(self) -> None:
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        good = _op(issuer, signers=(priv,))
        # array mixing a valid bin with non-bin junk
        batch = serialization.packb([good.to_payload(), "not-a-delta", 7])
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertEqual(rx.apply_payloads(batch, now_ms=1_700_000_000_000), 1)
        self.assertTrue(state.is_active(good.tuple.hash()))

    def test_future_skewed_element_rejected_per_s12(self) -> None:
        """A batch element is still subject to the §12 per-delta intake check."""
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        kr = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        future = Operation(
            tuple=Tuple.from_plaintext(
                object_id="sensor:wind", relation="calibrate", grantee=GRANTEE,
                issuer=issuer, hasher=HASHER,
            ),
            action=Action.GRANT, hlc=pack(1_700_000_000_000 + 400 * 24 * 3600 * 1000, 0),
        ).sign(priv)
        batch = DeltaReceiver.pack_payloads([future.to_payload()])
        state = StateVector()
        rx = DeltaReceiver(state, kr)
        self.assertEqual(rx.apply_payloads(batch, now_ms=1_700_000_000_000), 0)
        self.assertEqual(len(state), 0)


class TrustedLocalOnlyWarningTest(unittest.TestCase):
    """StateVector.from_payload() must audibly flag its trusted-local contract."""

    def test_from_payload_emits_trusted_local_warning(self) -> None:
        state = StateVector()
        state.apply(
            _op(_identity_hash(Ed25519PrivateKey.generate())), now_ms=1_700_000_000_000
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            StateVector.from_payload(state.to_payload())
        self.assertTrue(
            any(issubclass(w.category, TrustedLocalOnlyWarning) for w in caught)
        )

    def test_warning_can_be_filtered_for_genuine_snapshot_restore(self) -> None:
        state = StateVector()
        state.apply(
            _op(_identity_hash(Ed25519PrivateKey.generate())), now_ms=1_700_000_000_000
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            warnings.filterwarnings(
                "ignore", category=TrustedLocalOnlyWarning
            )
            StateVector.from_payload(state.to_payload())
        self.assertFalse(
            any(issubclass(w.category, TrustedLocalOnlyWarning) for w in caught)
        )


if __name__ == "__main__":
    unittest.main()
