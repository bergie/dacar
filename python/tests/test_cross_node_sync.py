"""
Test cross-version sync: verify deltas from one node work on another

Simulates the scenario where:
1. Node A publishes grants (current version)
2. Node B syncs (current version)
3. Deltas should be accepted

Tests:
- Signature verification across nodes
- Keyring integration with RNS-style resolution
- Timestamp compatibility
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import hashlib

from dacar import Action, Keyring, Operation, StateVector, Tuple, DeltaReceiver
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes([2] * 16)
HLC = pack(physical_now_ms(), 0)


class CrossNodeSyncTest(unittest.TestCase):
    """Test that deltas from one node can be synced to another."""

    def test_delta_from_node_a_accepted_by_node_b(self):
        """Simulate: Node A publishes, Node B syncs.

        This tests the exact scenario where both nodes use the current code.
        """
        # Node A's setup
        node_a_priv = Ed25519PrivateKey.generate()
        node_a_hash = hashlib.sha256(node_a_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Node B's setup
        node_b_priv = Ed25519PrivateKey.generate()
        node_b_hash = hashlib.sha256(node_b_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Node A creates and signs a grant
        tup = Tuple.from_plaintext(
            object_id="blog:publish", relation="execute",
            grantee=GRANTEE, issuer=node_a_hash, hasher=HASHER
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=HLC).sign(node_a_priv)
        delta = op.to_payload()

        # Node B's state and keyring
        state_b = StateVector()
        keyring_b = Keyring()
        
        # CRITICAL: Node B needs Node A's public key in the keyring
        # This is what RNS identity resolution provides
        keyring_b.register_single(node_a_hash, node_a_priv.public_key().public_bytes_raw())

        # Node B creates a resolver (simulating RnsIdentityResolver fallback)
        def resolver(issuer_hash: bytes):
            return keyring_b.resolve(issuer_hash)

        receiver_b = DeltaReceiver(state_b, resolver)

        # Node B receives and applies the delta
        result = receiver_b.apply_payload(delta, now_ms=HLC >> 16)

        # Verify it was accepted
        self.assertTrue(result, "Delta from Node A should be accepted by Node B")

        # Verify state has the grant
        active = list(state_b.active_tuples())
        self.assertEqual(len(active), 1, "Node B should have 1 active grant")

        # Verify the grant properties
        tup_b = active[0]
        self.assertEqual(tup_b.grantee, GRANTEE, "Grantee should match")
        self.assertEqual(tup_b.issuer, node_a_hash, "Issuer should be Node A")

    def test_delta_rejected_when_issuer_not_in_keyring(self):
        """Delta should be rejected when issuer unknown.

        This simulates the sync failure when Node B doesn't have Node A's key.
        """
        # Node A's setup
        node_a_priv = Ed25519PrivateKey.generate()
        node_a_hash = hashlib.sha256(node_a_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Node A creates a grant
        tup = Tuple.from_plaintext(
            object_id="blog:publish", relation="execute",
            grantee=GRANTEE, issuer=node_a_hash, hasher=HASHER
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=HLC).sign(node_a_priv)
        delta = op.to_payload()

        # Node B's state with EMPTY keyring (no issuer keys)
        state_b = StateVector()
        keyring_b = Keyring()  # Empty!
        receiver_b = DeltaReceiver(state_b, keyring_b)

        # Node B tries to apply the delta
        import sys
        from io import StringIO
        old_stderr = sys.stderr
        sys.stderr = StringIO()

        try:
            result = receiver_b.apply_payload(delta, log_rejections=True, now_ms=HLC >> 16)
            stderr_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr

        # Verify it was rejected
        self.assertFalse(result, "Delta should be rejected (unknown issuer)")

        # Verify the rejection was logged
        self.assertIn("rejected delta: unknown issuer", stderr_output,
                      "Should log 'unknown issuer'")
        self.assertIn(node_a_hash.hex()[:16], stderr_output,
                      "Should include the issuer hash")

        # Verify state is empty
        self.assertEqual(len(list(state_b.active_tuples())), 0, "State should be empty")

    def test_multiple_deltas_from_same_issuer_all_accepted(self):
        """Multiple deltas from the same issuer should all be accepted.

        Simulates Node A publishing 3 grants, Node B syncing all at once.
        """
        # Node A's setup
        node_a_priv = Ed25519PrivateKey.generate()
        node_a_hash = hashlib.sha256(node_a_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Node A creates 3 grants
        objects = ["blog:publish", "grib:request", "sys:command"]
        deltas = []
        for i, obj_id in enumerate(objects):
            tup = Tuple.from_plaintext(
                object_id=obj_id, relation="execute",
                grantee=GRANTEE, issuer=node_a_hash, hasher=HASHER
            )
            op = Operation(tuple=tup, action=Action.GRANT, hlc=pack(HLC >> 16, i)).sign(node_a_priv)
            deltas.append(op.to_payload())

        # Node B's setup with Node A's key in keyring
        state_b = StateVector()
        keyring_b = Keyring().register_single(node_a_hash, node_a_priv.public_key().public_bytes_raw())
        receiver_b = DeltaReceiver(state_b, keyring_b)

        # Node B receives all deltas
        applied = 0
        for delta in deltas:
            if receiver_b.apply_payload(delta, now_ms=HLC >> 16):
                applied += 1

        # Verify all 3 were accepted
        self.assertEqual(applied, 3, "All 3 deltas should be accepted")

        # Verify state has 3 grants
        active = list(state_b.active_tuples())
        self.assertEqual(len(active), 3, "Node B should have 3 active grants")

        # Verify each grant has a different object
        object_hashes_seen = set()
        for tup in active:
            object_hashes_seen.add(tup.object_hashes)
        self.assertEqual(len(object_hashes_seen), 3, "Each grant should have different object hashes")

    def test_wrong_signature_rejected(self):
        """Delta with wrong signature should be rejected.

        Simulates a malicious or corrupted delta claiming to be from Node A
        but signed by someone else.
        """
        # Node A's identity (claimed issuer)
        node_a_priv = Ed25519PrivateKey.generate()
        node_a_hash = hashlib.sha256(node_a_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Attacker's key (actually signs)
        attacker_priv = Ed25519PrivateKey.generate()

        # Create a grant claiming to be from Node A but signed by attacker
        tup = Tuple.from_plaintext(
            object_id="blog:publish", relation="execute",
            grantee=GRANTEE, issuer=node_a_hash, hasher=HASHER
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=HLC).sign(attacker_priv)
        delta = op.to_payload()

        # Node B's setup with Node A's real key
        state_b = StateVector()
        keyring_b = Keyring().register_single(node_a_hash, node_a_priv.public_key().public_bytes_raw())
        receiver_b = DeltaReceiver(state_b, keyring_b)

        # Node B tries to apply the delta
        import sys
        from io import StringIO
        old_stderr = sys.stderr
        sys.stderr = StringIO()

        try:
            result = receiver_b.apply_payload(delta, log_rejections=True, now_ms=HLC >> 16)
            stderr_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr

        # Verify it was rejected
        self.assertFalse(result, "Delta with wrong signature should be rejected")

        # Verify the rejection was logged
        self.assertIn("rejected delta: signature verification failed", stderr_output,
                      "Should log signature verification failure")

        # Verify state is empty
        self.assertEqual(len(list(state_b.active_tuples())), 0, "State should be empty")

    def test_stale_timestamp_rejected(self):
        """Delta with timestamp older than deletion horizon is rejected.

        This is the §9 intake rejection mechanism.
        """
        node_a_priv = Ed25519PrivateKey.generate()
        node_a_hash = hashlib.sha256(node_a_priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]

        # Create a grant with a timestamp 200 days in the past
        old_hlc = pack(physical_now_ms() - (200 * 24 * 3600 * 1000), 0)

        tup = Tuple.from_plaintext(
            object_id="blog:publish", relation="execute",
            grantee=GRANTEE, issuer=node_a_hash, hasher=HASHER
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=old_hlc).sign(node_a_priv)
        delta = op.to_payload()

        # Node B's setup
        state_b = StateVector()  # Default horizon is 180 days
        keyring_b = Keyring().register_single(node_a_hash, node_a_priv.public_key().public_bytes_raw())
        receiver_b = DeltaReceiver(state_b, keyring_b)

        # Node B tries to apply the old delta
        import sys
        from io import StringIO
        old_stderr = sys.stderr
        sys.stderr = StringIO()

        try:
            result = receiver_b.apply_payload(delta, log_rejections=True, now_ms=physical_now_ms())
            stderr_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr

        # Verify it was rejected
        self.assertFalse(result, "Stale delta should be rejected")

        # Verify the rejection reason mentions stale timestamp
        self.assertIn("rejected delta: timestamp is stale", stderr_output,
                      "Should log timestamp is stale")

        # Verify state is empty
        self.assertEqual(len(list(state_b.active_tuples())), 0, "State should be empty")


if __name__ == "__main__":
    unittest.main(verbosity=2)