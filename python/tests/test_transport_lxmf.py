"""Smoketests for §11.2 LXMF delivery + §11.3 Paper Messages (spec §11.2/§11.3).

The Dacar-specific logic is the title filter + content↔Delta seam; the LXMF
machinery (encrypt/decrypt, ratchets, propagation) is exercised upstream and is
not re-tested here. A *headless* RNS.Reticulum (transport disabled, no
interfaces) lets us build real LXMF messages offline for deterministic
wrap/unwrap, verify-on-ingest, and paper-export checks -- no live network.

Requires the ``lxmf`` package (``dacar[transport]`` extra).
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

import LXMF
import RNS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests._rns_fixture import ensure_headless

from dacar import Action, DeltaReceiver, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.transport.lxmf_sync import (
    LxmfDeltaDelivery,
    decode_batch,
    encode_batch,
    lxmf_message_content,
    lxmf_message_title,
    pack_chunks,
    pack_paper_messages,
)

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
# Dated "now" so the §9 stale-horizon intake check (wall-clock default) accepts it.
HLC = pack(physical_now_ms(), 0)


def _identity_hash(priv: Ed25519PrivateKey) -> bytes:
    import hashlib

    return hashlib.sha256(priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]


def _op(issuer: bytes, signers=(), object_id: str = "sensor:wind"):
    t = Tuple.from_plaintext(
        object_id=object_id, relation="calibrate", grantee=GRANTEE,
        issuer=issuer, hasher=HASHER,
    )
    base = Operation(tuple=t, action=Action.GRANT, hlc=HLC)
    return base.sign(*signers) if signers else base


class _FakeMsg:
    """Duck-typed LXMF message (title/content only) for the malformed test."""

    def __init__(self, title_str, content_bytes):
        self._title = title_str
        self.content = content_bytes

    def title_as_string(self):
        return self._title


class LxmfDeltaDeliveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def _dst_src(self):
        dst = RNS.Destination(
            RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "dacar", "sync", "delta"
        )
        src = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "dacar", "node"
        )
        return dst, src

    # -- §11.2 send: wrap round-trips through the LXMF wire format -----------

    def test_make_message_roundtrips_delta(self):
        dst, src = self._dst_src()
        delta = b"\x01\x02\x03-emit-delta-bytes-"
        msg = LxmfDeltaDelivery(receiver=None).make_message(delta, dst, src)
        msg.pack()
        rt = LXMF.LXMessage.unpack_from_bytes(msg.packed)
        self.assertEqual(lxmf_message_title(rt), LxmfDeltaDelivery.TITLE)
        self.assertEqual(lxmf_message_content(rt), delta)

    # -- §11.2 receive: title filter + verify-on-ingest through DeltaReceiver -

    def test_handle_delivery_applies_signed_delta(self):
        dst, src = self._dst_src()
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        delta = _op(issuer, signers=(priv,)).to_payload()
        keyring = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        state = StateVector()
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, keyring))

        msg = delivery.make_message(delta, dst, src)
        msg.pack()
        self.assertTrue(delivery.handle_delivery(LXMF.LXMessage.unpack_from_bytes(msg.packed)))
        self.assertEqual(len(state), 1)

    def test_handle_delivery_ignores_non_dacar_title(self):
        dst, src = self._dst_src()
        state = StateVector()
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, Keyring()))
        msg = LXMF.LXMessage(dst, src, content=b"hello-there", title="chat/hello")
        msg.pack()
        self.assertFalse(delivery.handle_delivery(LXMF.LXMessage.unpack_from_bytes(msg.packed)))
        self.assertEqual(len(state), 0)

    def test_handle_delivery_swallows_malformed_content(self):
        """A transport callback must never crash on arbitrary content."""
        state = StateVector()
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, Keyring()))
        self.assertFalse(delivery.handle_delivery(_FakeMsg(LxmfDeltaDelivery.TITLE, b"not msgpack")))
        self.assertFalse(delivery.handle_delivery(_FakeMsg(LxmfDeltaDelivery.TITLE, b"")))
        self.assertEqual(len(state), 0)

    # -- §11.3 Paper Messages: encrypted QR-encodable export -----------------

    def test_make_paper_message_is_encrypted(self):
        dst, src = self._dst_src()
        priv = Ed25519PrivateKey.generate()
        delta = _op(_identity_hash(priv), signers=(priv,)).to_payload()
        msg = LxmfDeltaDelivery(receiver=None).make_paper_message(delta, dst, src)
        self.assertEqual(msg.representation, LXMF.LXMessage.PAPER)
        packed = LxmfDeltaDelivery.paper_bytes(msg)
        self.assertGreater(len(packed), 0)
        self.assertNotIn(delta, packed)  # encrypted -- no plaintext Delta leak

    def test_paper_bytes_rejects_non_paper_message(self):
        dst, src = self._dst_src()
        plain = LxmfDeltaDelivery(receiver=None).make_message(b"delta", dst, src)
        with self.assertRaises(ValueError):
            LxmfDeltaDelivery.paper_bytes(plain)


class BatchEnvelopeTest(unittest.TestCase):
    """The §11.2 batch envelope (title dacar/sync/batch, work doc #14)."""

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def _dst_src(self):
        dst = RNS.Destination(
            RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery"
        )
        src = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
        )
        return dst, src

    def test_batch_codec_roundtrip(self):
        payloads = [bytes([i]) * (1 + i * 37) for i in range(16)]
        encoded = encode_batch(payloads)
        self.assertEqual(decode_batch(encoded), payloads)
        # bin on the wire (not str arrays)
        self.assertTrue(0x90 <= encoded[0] <= 0x9F or encoded[0] == 0xDC)

    def test_decode_batch_strict(self):
        import msgpack

        for bad in (b"", b"not-msgpack", msgpack.packb("str"), msgpack.packb([]),
                    msgpack.packb([b"a", 1]), msgpack.packb({b"a": 1})):
            with self.assertRaises(ValueError):
                decode_batch(bad)

    def test_pack_chunks_greedy_and_ordered(self):
        payloads = [bytes([i]) * 100 for i in range(50)]
        limit = 500
        chunks = pack_chunks(payloads, limit)
        flat = [p for c in chunks for p in c]
        self.assertEqual(flat, payloads)  # order preserved, none lost
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(len(encode_batch(c)), limit)
        # Greedy: every chunk except the last is maximal (adding the next
        # payload would overflow).
        for i in range(len(chunks) - 1):
            nxt = payloads[len([p for c in chunks[:i + 1] for p in c])]
            self.assertGreater(len(encode_batch(chunks[i] + [nxt])), limit)

    def test_batch_message_roundtrips_through_lxmf_wire(self):
        dst, src = self._dst_src()
        payloads = [b"delta-a", b"delta-b", b"delta-c"]
        msg = LxmfDeltaDelivery(receiver=None).make_batch_message(payloads, dst, src)
        msg.pack()
        rt = LXMF.LXMessage.unpack_from_bytes(msg.packed)
        self.assertEqual(lxmf_message_title(rt), "dacar/sync/batch")
        self.assertEqual(decode_batch(lxmf_message_content(rt)), payloads)

    def test_handle_delivery_batch_applies_elementwise(self):
        """A batch with one forged element still applies the good ones."""
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        good = _op(issuer, signers=(priv,)).to_payload()
        forged = _op(bytes(HASH_SIZE), signers=(priv,)).to_payload()  # wrong issuer sig
        state = StateVector()
        keyring = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, keyring))

        msg = delivery.make_batch_message([good, forged], *self._dst_src())
        msg.pack()
        self.assertTrue(delivery.handle_delivery(LXMF.LXMessage.unpack_from_bytes(msg.packed)))
        self.assertEqual(len(state), 1)  # good applied, forged dropped

    def test_handle_delivery_batch_applies_every_element(self):
        """No any() short-circuit: every valid element of a batch applies."""
        priv = Ed25519PrivateKey.generate()
        issuer = _identity_hash(priv)
        payloads = [
            _op(issuer, signers=(priv,), object_id=f"sensor:{i}").to_payload()
            for i in range(3)
        ]
        state = StateVector()
        keyring = Keyring().register_single(issuer, priv.public_key().public_bytes_raw())
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, keyring))
        self.assertTrue(
            delivery.handle_delivery(_FakeMsg("dacar/sync/batch", encode_batch(payloads)))
        )
        self.assertEqual(len(state), 3)

    def test_handle_delivery_all_forged_batch_is_false(self):
        priv = Ed25519PrivateKey.generate()
        forged = _op(bytes(HASH_SIZE), signers=(priv,)).to_payload()
        state = StateVector()
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, Keyring()))
        self.assertFalse(
            delivery.handle_delivery(_FakeMsg("dacar/sync/batch", encode_batch([forged])))
        )
        self.assertEqual(len(state), 0)

    def test_handle_delivery_malformed_batch_dropped_whole(self):
        import msgpack

        state = StateVector()
        delivery = LxmfDeltaDelivery(receiver=DeltaReceiver(state, Keyring()))
        for bad in (b"garbage", b"", msgpack.packb([1, 2, 3])):
            self.assertFalse(delivery.handle_delivery(_FakeMsg("dacar/sync/batch", bad)))
        self.assertEqual(len(state), 0)


class PaperBatchTest(unittest.TestCase):
    """§11.3 multi-Delta paper messages (work doc #14)."""

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def _dst_src(self):
        dst = RNS.Destination(
            RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery"
        )
        src = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
        )
        return dst, src

    def test_paper_batch_within_mdu_and_chunked(self):
        dst, src = self._dst_src()
        payloads = [bytes([i]) * 170 for i in range(40)]  # 40 typical deltas
        messages = pack_paper_messages(payloads, dst, src)
        self.assertGreater(len(messages), 1)  # spills to multiple QRs
        for m in messages:
            self.assertLessEqual(len(m.paper_packed), LXMF.LXMessage.PAPER_MDU)
            self.assertTrue(m.as_uri().startswith("lxm://"))
        # Every payload appears in exactly one chunk (order + coverage)
        flat = [p for m in messages for p in m.dacar_batch_payloads]
        self.assertEqual(flat, payloads)

    def test_single_oversized_payload_propagates_type_error(self):
        dst, src = self._dst_src()
        huge = [b"x" * (LXMF.LXMessage.PAPER_MDU + 512)]
        with self.assertRaises(TypeError):
            pack_paper_messages(huge, dst, src)


class CorePurityTest(unittest.TestCase):
    def test_core_import_does_not_pull_transport_or_rns(self):
        """`import dacar` must stay free of the transport/rns/lxmf stack."""
        out = subprocess.check_output(
            [sys.executable, "-c",
             "import sys, dacar; "
             "leaked=[m for m in ('dacar.transport','RNS','LXMF') if m in sys.modules]; "
             "assert not leaked, leaked; "
             "print('PURE')"],
            text=True,
        )
        self.assertIn("PURE", out)


if __name__ == "__main__":
    unittest.main()
