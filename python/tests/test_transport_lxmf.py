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
import shutil
import subprocess
import sys
import tempfile
import unittest

import LXMF
import RNS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar import Action, DeltaReceiver, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.transport.lxmf_sync import LxmfDeltaDelivery, lxmf_message_content, lxmf_message_title

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
# Dated "now" so the §9 stale-horizon intake check (wall-clock default) accepts it.
HLC = pack(physical_now_ms(), 0)


def _identity_hash(priv: Ed25519PrivateKey) -> bytes:
    import hashlib

    return hashlib.sha256(priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]


def _op(issuer: bytes, signers=()):
    t = Tuple.from_plaintext(
        object_id="sensor:wind", relation="calibrate", grantee=GRANTEE,
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


def _reticulum_off():
    """A headless RNS.Reticulum that binds no interfaces."""
    cfg = tempfile.mkdtemp(prefix="dacar-rns-")
    with open(os.path.join(cfg, "config"), "w") as f:
        f.write("[reticulum]\nenable_transport = False\nshare_instance = No\n\n[interfaces]\n")
    RNS.Reticulum(cfg)
    return cfg


class LxmfDeltaDeliveryTest(unittest.TestCase):
    cfg_dir = None

    @classmethod
    def setUpClass(cls):
        cls.cfg_dir = _reticulum_off()

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
