"""
End-to-end test: RFed sync handles mixed valid/invalid deltas

Tests the scenario where RFed storage contains both old-style malformed
deltas (batched operations) and valid deltas. Verifies that:

1. Valid deltas are correctly applied to state
2. Invalid deltas are rejected (don't corrupt state)
3. Sync continues processing after rejections
4. Final state contains only valid grants

This simulates the real-world scenario where RFed may have accumulated
old-style payloads over time.
"""

from __future__ import annotations

import unittest

from dacar import Action, DeltaReceiver, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dacar import serialization
import hashlib

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes([2] * 16)  # lille-oe
HLC = pack(physical_now_ms(), 0)


def _op(object_id, issuer_priv, offset=0):
    """Create a signed operation for testing."""
    issuer_hash = hashlib.sha256(issuer_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]
    t = Tuple.from_plaintext(
        object_id=object_id, relation="execute", grantee=GRANTEE,
        issuer=issuer_hash, hasher=HASHER,
    )
    base = Operation(tuple=t, action=Action.GRANT, hlc=pack(HLC >> 16, offset))
    return base.sign(issuer_priv)


class E2EMixedValidInvalidDeltasTest(unittest.TestCase):
    """End-to-end test: sync with mixed valid/invalid deltas."""

    def test_valid_deltas_applied_invalid_rejected(self):
        """DeltaReceiver should apply valid deltas and reject invalid ones.

        This tests the exact scenario from the bug report:
        - Admin machine issued 3 valid grants
        - RFed storage also contained old-style malformed payloads
        - Client sync should result in clean state with only the 3 valid grants
        """
        # Setup identities
        admin_priv = Ed25519PrivateKey.generate()
        admin_hash = hashlib.sha256(admin_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Create 3 valid operations (the grants from admin machine)
        valid_deltas = [
            _op("blog:publish", admin_priv, 0).to_payload(),
            _op("grib:request", admin_priv, 1).to_payload(),
            _op("sys:command", admin_priv, 2).to_payload(),
        ]

        # Create invalid payloads (old-style batched operations)
        invalid_deltas = [
            # Batch of operations: [[op1_fields...], [op2_fields...]]
            serialization.packb([
                [b"a"*16, b"b"*16, 1, 12345, b"c"*16, [b"d"*16], False, [b"e"*64]],
                [b"f"*16, b"g"*16, 1, 12346, b"h"*16, [b"i"*16], False, [b"j"*64]],
            ]),
            # Wrong field types: issuer as array instead of bytes
            serialization.packb([[1]*16, b"b"*16, 1, 12347, b"c"*16, [b"d"*16], False, [b"e"*64]]),
        ]

        # Setup state and keyring
        state = StateVector()
        keyring = Keyring().register_single(admin_hash, admin_priv.public_key().public_bytes_raw())
        receiver = DeltaReceiver(state, keyring)

        # Simulate sync: process mixed valid/invalid deltas
        applied = 0
        rejected = 0

        for delta in invalid_deltas + valid_deltas:  # Process invalid first
            result = receiver.apply_payload(delta, now_ms=HLC >> 16)
            if result:
                applied += 1
            else:
                rejected += 1

        # Verify results
        self.assertEqual(applied, 3, f"Should apply 3 valid deltas, got {applied}")
        self.assertEqual(rejected, 2, f"Should reject 2 invalid deltas, got {rejected}")

        # Verify state has exactly 3 active grants
        active_tuples = list(state.active_tuples())
        self.assertEqual(len(active_tuples), 3, f"Should have 3 active tuples, got {len(active_tuples)}")

        # Verify each grant has correct properties
        for tup in active_tuples:
            self.assertEqual(tup.grantee, GRANTEE, "Grantee should match lille-oe")
            self.assertEqual(tup.issuer, admin_hash, "Issuer should match admin")
            self.assertEqual(tup.relation_hash, HASHER.hash_relation("execute"),
                           "Relation should be 'execute'")

            # Object should be one of the three we created
            obj_ids = ["blog:publish", "grib:request", "sys:command"]
            matches = 0
            for obj_id in obj_ids:
                obj_hashes, wildcard = HASHER.hash_object(obj_id)
                if tup.object_hashes == obj_hashes and tup.wildcard == wildcard:
                    matches += 1
            self.assertEqual(matches, 1, "Each tuple should match exactly one object ID")

    def test_continues_after_rejection(self):
        """Processing should continue after encountering invalid deltas."""
        admin_priv = Ed25519PrivateKey.generate()
        admin_hash = hashlib.sha256(admin_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Create valid operations
        valid_deltas = [
            _op("blog:publish", admin_priv, 0).to_payload(),
            _op("grib:request", admin_priv, 1).to_payload(),
        ]

        # Invalid payload at the start
        invalid_deltas = [
            serialization.packb([[1]*16, b"b"*16, 1, 12345, b"c"*16, [b"d"*16], False, [b"e"*64]]),
        ]

        state = StateVector()
        keyring = Keyring().register_single(admin_hash, admin_priv.public_key().public_bytes_raw())
        receiver = DeltaReceiver(state, keyring)

        # Process invalid first, then valid
        applied = 0
        for delta in invalid_deltas + valid_deltas:
            if receiver.apply_payload(delta, now_ms=HLC >> 16):
                applied += 1

        # Should still apply both valid deltas despite the invalid one
        self.assertEqual(applied, 2, f"Should apply 2 valid deltas, got {applied}")
        self.assertEqual(len(list(state.active_tuples())), 2, "Should have 2 active tuples")

    def test_logging_with_rejections(self):
        """Verify that apply_payload with log_rejections=True logs rejections."""
        admin_priv = Ed25519PrivateKey.generate()
        admin_hash = hashlib.sha256(admin_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Create a valid and an invalid operation
        valid_delta = _op("blog:publish", admin_priv).to_payload()
        invalid_delta = serialization.packb([[1]*16, b"b"*16, 1, 12345, b"c"*16, [b"d"*16], False, [b"e"*64]])

        state = StateVector()
        keyring = Keyring().register_single(admin_hash, admin_priv.public_key().public_bytes_raw())
        receiver = DeltaReceiver(state, keyring)

        # Apply invalid delta with logging
        import sys
        from io import StringIO
        old_stderr = sys.stderr
        sys.stderr = StringIO()

        try:
            result = receiver.apply_payload(invalid_delta, log_rejections=True, now_ms=HLC >> 16)
            stderr_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr

        # Should be rejected and logged
        self.assertFalse(result, "Invalid delta should be rejected")
        self.assertIn("rejected malformed delta", stderr_output,
                      "Should log rejection to stderr")
        self.assertIn("issuer must be a 16-byte binary blob", stderr_output,
                      "Should include specific error message")

        # Valid delta should succeed without logging
        old_stderr = sys.stderr
        sys.stderr = StringIO()

        try:
            result2 = receiver.apply_payload(valid_delta, log_rejections=True, now_ms=HLC >> 16)
            stderr_output2 = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr

        self.assertTrue(result2, "Valid delta should be applied")
        self.assertEqual(stderr_output2, "", "Valid delta should not log anything")

    def test_batch_payloads_with_invalid_elements(self):
        """DeltaReceiver.apply_payloads should handle batch with invalid elements."""
        admin_priv = Ed25519PrivateKey.generate()
        admin_hash = hashlib.sha256(admin_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        valid_deltas = [
            _op("blog:publish", admin_priv, 0).to_payload(),
            _op("grib:request", admin_priv, 1).to_payload(),
        ]
        invalid_delta = serialization.packb([[1]*16, b"b"*16, 1, 12345, b"c"*16, [b"d"*16], False, [b"e"*64]])

        # Create batch: [valid1, invalid, valid2]
        batch_payloads = DeltaReceiver.pack_payloads([valid_deltas[0], invalid_delta, valid_deltas[1]])

        state = StateVector()
        keyring = Keyring().register_single(admin_hash, admin_priv.public_key().public_bytes_raw())
        receiver = DeltaReceiver(state, keyring)

        # Apply batch - should only apply the valid ones
        applied = receiver.apply_payloads(batch_payloads, now_ms=HLC >> 16)

        self.assertEqual(applied, 2, f"Should apply 2 valid deltas in batch, got {applied}")
        self.assertEqual(len(list(state.active_tuples())), 2, "Should have 2 active tuples")


if __name__ == "__main__":
    unittest.main(verbosity=2)