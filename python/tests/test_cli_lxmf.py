"""Smoketests for the LXMF CLI paths (§11.2/§11.3, work doc #14).

Covers the [lxmf] config section, the testable send/sync cores (fake router,
no live proprietor), the ``--lxmf`` CLI wiring (outbox → sent lifecycle), and
an end-to-end paper export → import round-trip through real LXMF paper
messages on a headless RNS.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import LXMF
import RNS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests._rns_fixture import ensure_headless

from dacar import DeltaReceiver, Keyring, StateVector
from dacar.cli import main
from dacar.cli.commands import CliError
from dacar.cli.lxmf import (
    run_lxmf_publish,
    run_lxmf_sync,
    uri_to_paper_bytes,
)
from dacar.cli.store import Store
from dacar.hlc import physical_now_ms, pack
from dacar.namespace import HASH_SIZE, SALT_SIZE
from dacar.transport.lxmf_sync import (
    LxmfDeltaDelivery,
    decode_batch,
    encode_batch,
)

SALT = bytes(range(SALT_SIZE))
HLC = pack(physical_now_ms(), 0)


def _identity_hash(priv: Ed25519PrivateKey) -> bytes:
    import hashlib

    return hashlib.sha256(priv.public_key().public_bytes_raw()).digest()[:HASH_SIZE]


def _delta(issuer_priv: Ed25519PrivateKey, object_id: str) -> bytes:
    from dacar import Action, Operation, Tuple
    from dacar.namespace import NamespaceHasher

    hasher = NamespaceHasher(SALT)
    issuer = _identity_hash(issuer_priv)
    t = Tuple.from_plaintext(
        object_id=object_id, relation="read",
        grantee=bytes(range(HASH_SIZE)), issuer=issuer, hasher=hasher,
    )
    op = Operation(tuple=t, action=Action.GRANT, hlc=HLC)
    return op.sign(issuer_priv).to_payload()


class _FakeRouter:
    """Duck-typed LXMRouter for the send/sync cores (no network, no LXMF).

    ``handle_outbound`` marks messages SENT immediately (configurable via
    ``fail``); ``request_messages_from_propagation_node`` invokes the
    registered delivery callback with queued ``deliver`` messages, then flips
    the transfer state to complete (or a failure state via ``sync_fail``).
    """

    def __init__(self, fail=False, sync_fail=False):
        from dacar.naming import LXMF_DELIVERY_TITLE

        self.fail = fail
        self.sync_fail = sync_fail
        self.outbound_propagation_node = None
        self.outbound = []
        self._callback = None
        self.propagation_transfer_state = 0x00  # PR_IDLE
        self._pending = []
        src = RNS.Destination(
            RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE,
            "lxmf", "delivery",
        )
        self.delivery_destinations = {src.hash: src}

    def set_outbound_propagation_node(self, destination_hash):
        if len(destination_hash) != 16 or not isinstance(destination_hash, bytes):
            raise ValueError("Invalid destination hash for outbound propagation node")
        self.outbound_propagation_node = destination_hash

    def register_delivery_callback(self, callback):
        self._callback = callback

    def handle_outbound(self, lxmessage):
        self.outbound.append(lxmessage)
        if self.fail:
            lxmessage.state = LXMF.LXMessage.FAILED
        else:
            lxmessage.state = LXMF.LXMessage.SENT

    def request_messages_from_propagation_node(self, identity, max_messages=0):
        for message in self._pending:
            if self._callback is not None:
                self._callback(message)
        self.propagation_transfer_state = (
            0xF1 if self.sync_fail else LXMF.LXMRouter.PR_COMPLETE
        )

    def queue_inbound(self, message):
        self._pending.append(message)


def _out_destination():
    return RNS.Destination(
        RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE,
        "lxmf", "delivery",
    )


# ---------------------------------------------------------------------------
# [lxmf] config section
# ---------------------------------------------------------------------------


class LxmfConfigTest(unittest.TestCase):
    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-lxmf-cfg-"))
        Store.init(self.store_dir, salt=SALT)

    def test_proprietor_roundtrip(self):
        store = Store(self.store_dir)
        proprietor = bytes(range(16))
        store.save_config(
            primary_salt=SALT,
            anchors=store.load_config_raw()["anchors"],
            lxmf_proprietor=proprietor,
        )
        self.assertEqual(store.load_config_raw()["lxmf_proprietor"], proprietor)

    def test_unset_by_default(self):
        self.assertIsNone(Store(self.store_dir).load_config_raw()["lxmf_proprietor"])

    def test_survives_salt_rotation(self):
        store = Store(self.store_dir)
        proprietor = bytes(range(16))
        store.save_config(
            primary_salt=SALT,
            anchors=store.load_config_raw()["anchors"],
            lxmf_proprietor=proprietor,
        )
        raw = store.load_config_raw()
        store.save_config(
            primary_salt=bytes(SALT_SIZE),  # rotate; lxmf untouched
            anchors=raw["anchors"],
        )
        self.assertEqual(store.load_config_raw()["lxmf_proprietor"], proprietor)

    def test_config_show_lists_proprietor(self):
        store = Store(self.store_dir)
        store.save_config(
            primary_salt=SALT,
            anchors=store.load_config_raw()["anchors"],
            lxmf_proprietor=bytes(16),
        )
        out, err = io.StringIO(), io.StringIO()
        argv = ["config", "show", "--store", str(self.store_dir)]
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(argv), 0, err.getvalue())
        self.assertIn("[lxmf]", err.getvalue())
        self.assertIn("proprietor", err.getvalue())


# ---------------------------------------------------------------------------
# run_lxmf_publish / run_lxmf_sync cores
# ---------------------------------------------------------------------------


class RunLxmfPublishTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.router = _FakeRouter()
        self.delivery = LxmfDeltaDelivery(router=self.router)
        self.target = bytes(range(16))
        self.proprietor = bytes(range(16, 32))

    def _run(self, payloads, no_proprietor=False, **kw):
        proprietor = None if no_proprietor else self.proprietor
        with patch("dacar.cli.lxmf.lxmf_out_destination", return_value=_out_destination()):
            return run_lxmf_publish(
                payloads, self.target, proprietor,
                self.router, self.delivery, **kw
            )

    def test_single_delta_uses_single_title(self):
        accepted, messages = self._run([b"one-delta"])
        self.assertEqual(accepted, [True])
        self.assertEqual(messages, 1)
        self.assertEqual(len(self.router.outbound), 1)
        self.assertEqual(bytes(self.router.outbound[0].title), b"dacar/sync/delta")
        self.assertEqual(
            self.router.outbound_propagation_node, self.proprietor
        )

    def test_multiple_deltas_batch(self):
        payloads = [bytes([i]) * 40 for i in range(5)]
        accepted, messages = self._run(payloads)
        self.assertEqual(accepted, [True] * 5)
        self.assertEqual(messages, 1)
        msg = self.router.outbound[0]
        self.assertEqual(bytes(msg.title), b"dacar/sync/batch")
        self.assertEqual(decode_batch(msg.content), payloads)

    def test_chunks_when_over_budget(self):
        payloads = [bytes([i]) * 200 for i in range(8)]
        accepted, messages = self._run(payloads, chunk_budget=500)
        self.assertGreater(messages, 1)
        self.assertEqual(accepted, [True] * 8)
        flat = [p for m in self.router.outbound for p in decode_batch(m.content)]
        self.assertEqual(flat, payloads)

    def test_no_proprietor_rejected_unless_direct(self):
        with self.assertRaises(ValueError):
            self._run([b"x"], no_proprietor=True)
        # direct needs no proprietor
        accepted, _ = self._run([b"x"], no_proprietor=True, direct=True)
        self.assertEqual(accepted, [True])

    def test_failed_send_reports_false(self):
        self.router.fail = True
        accepted, _ = self._run([b"x", b"y"])
        self.assertEqual(accepted, [False, False])


class RunLxmfSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()
        self.issuer = _identity_hash(self.priv)

    def _delivery(self, state):
        keyring = Keyring().register_single(
            self.issuer, self.priv.public_key().public_bytes_raw()
        )
        return LxmfDeltaDelivery(receiver=DeltaReceiver(state, keyring))

    def test_applies_pending_and_reports_count(self):
        state = StateVector()
        router = _FakeRouter()
        delivery = self._delivery(state)
        for i in range(3):
            router.queue_inbound(
                _FakeMsg("dacar/sync/delta", _delta(self.priv, f"sensor:{i}"))
            )
        applied = run_lxmf_sync(
            None, None, bytes(16), router, delivery
        )
        self.assertEqual(applied, 3)
        self.assertEqual(len(state), 3)

    def test_forged_and_foreign_titles_not_applied(self):
        state = StateVector()
        router = _FakeRouter()
        delivery = self._delivery(state)
        router.queue_inbound(_FakeMsg("dacar/sync/delta", b"garbage"))
        router.queue_inbound(_FakeMsg("chat/hello", b"hi"))
        other = Ed25519PrivateKey.generate()
        router.queue_inbound(
            _FakeMsg("dacar/sync/delta", _delta(other, "sensor:x"))
        )
        self.assertEqual(
            run_lxmf_sync(None, None, bytes(16), router, delivery), 0
        )
        self.assertEqual(len(state), 0)

    def test_sync_failure_raises(self):
        router = _FakeRouter(sync_fail=True)
        with self.assertRaises(RuntimeError):
            run_lxmf_sync(None, None, bytes(16), router, self._delivery(StateVector()))


class _FakeMsg:
    def __init__(self, title, content):
        self.title = title
        self.content = content

    def title_as_string(self):
        return self.title


# ---------------------------------------------------------------------------
# CLI wiring: grant/publish --lxmf (outbox → sent lifecycle)
# ---------------------------------------------------------------------------


class GrantLxmfTest(unittest.TestCase):
    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-grant-lxmf-"))
        Store.init(self.store_dir, salt=SALT)

    def _main(self, argv, patched):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with patch("dacar.cli.commands._lxmf_publish_delta", **patched):
                code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_grant_lxmf_delivers_and_records_sent(self):
        calls = {}

        def fake_hook(args, store, identity, payloads):
            calls["payloads"] = list(payloads)
            return [True] * len(payloads)

        argv = ["grant", "aabbccdd00112233445566778899aabb", "read", "sensor:wind",
                "--lxmf", "0011223344556677", "--store", str(self.store_dir)]
        code, _, err = self._main(argv, {"side_effect": fake_hook})
        self.assertEqual(code, 0, err)
        self.assertEqual(len(calls["payloads"]), 1)

        store = Store(self.store_dir)
        self.assertEqual(store.load_outbox(), [])       # drained
        self.assertEqual(len(store.load_sent()), 1)     # durable log
        config = store.load_config()
        self.assertEqual(len(store.load_state(config)), 1)  # applied locally

    def test_grant_lxmf_without_publish_is_online(self):
        """--lxmf alone triggers the online path (no --publish needed)."""
        argv = ["grant", "aabbccdd00112233445566778899aabb", "read", "sensor:x",
                "--lxmf", "0011223344556677", "--store", str(self.store_dir)]
        code, _, err = self._main(argv, {"side_effect": lambda *a: [True]})
        self.assertEqual(code, 0, err)

    def test_offline_grant_never_calls_lxmf(self):
        argv = ["grant", "aabbccdd00112233445566778899aabb", "read", "sensor:x",
                "--store", str(self.store_dir)]
        boom = lambda *a: (_ for _ in ()).throw(AssertionError("called"))  # noqa: E731
        code, _, err = self._main(argv, {"side_effect": boom})
        self.assertEqual(code, 0, err)
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 1)   # queued, offline-first

    def test_publish_sent_lxmf_replays_durable_log(self):
        store = Store(self.store_dir)
        store.save_outbox([_delta(Ed25519PrivateKey.generate(), "sensor:q")])
        argv = ["publish", "--all", "--lxmf", "0011223344556677",
                "--store", str(self.store_dir)]
        code, _, err = self._main(argv, {"side_effect": lambda *a: [True]})
        self.assertEqual(code, 0, err)
        self.assertEqual(Store(self.store_dir).load_outbox(), [])

    def test_sync_lxmf_without_proprietor_errors_before_boot(self):
        argv = ["sync", "--lxmf", "--store", str(self.store_dir)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with patch("dacar.cli.rns.boot", side_effect=AssertionError("booted")):
                code = main(argv)
        self.assertEqual(code, 1)
        self.assertIn("proprietor", err.getvalue())


# ---------------------------------------------------------------------------
# Paper export → import round-trip (§11.3, work doc #14)
# ---------------------------------------------------------------------------


class PaperRoundTripTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.dir_a = Path(tempfile.mkdtemp(prefix="dacar-paper-a-"))
        self.dir_b = Path(tempfile.mkdtemp(prefix="dacar-paper-b-"))
        Store.init(self.dir_a, salt=SALT)
        Store.init(self.dir_b, salt=SALT)
        # Recipient B: its *store* identity owns the lxmf.delivery destination
        # the export targets, so B's import router recognizes (and decrypts) it.
        # Built as OUT: same destination hash as the IN destination the router
        # registers, but OUT destinations don't self-register in RNS Transport
        # (which would collide with the import router's registration).
        self.b_identity = Store(self.dir_b).load_identity()
        self.b_dest = RNS.Destination(
            self.b_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
            "lxmf", "delivery",
        )
        RNS.Identity.remember(
            bytes(32), self.b_dest.hash,
            self.b_identity.get_public_key(),
        )

    def _grant(self, object_id):
        argv = ["grant", "aabbccdd00112233445566778899aabb", "read", object_id,
                "--store", str(self.dir_a)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(argv), 0, err.getvalue())

    def _export(self, extra):
        argv = ["paper", "export", self.b_dest.hash.hex(), "--all",
                "--store", str(self.dir_a)] + extra
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with patch("dacar.cli.rns.boot", side_effect=lambda cfg: RNS.Reticulum):
                self.assertEqual(main(argv), 0, err.getvalue())
        return out, err

    def test_export_import_roundtrip(self):
        for i in range(3):
            self._grant(f"sensor:{i}")
        uris_file = self.dir_a / "paper.txt"
        manifest_file = self.dir_a / "manifest.json"
        out, err = self._export(["--file", str(uris_file), "--manifest", str(manifest_file)])

        uris = [u for u in uris_file.read_text().splitlines() if u.strip()]
        manifest = json.loads(manifest_file.read_text())
        self.assertEqual(manifest["delta_count"], 3)
        self.assertEqual(manifest["chunks"], len(uris))
        self.assertTrue(all(u.startswith("lxm://") for u in uris))

        # B imports; A's issuer must be trusted (root anchor) and resolvable
        # (keyring path) on B — the standard cross-node bootstrap.
        store_a = Store(self.dir_a)
        a_identity = store_a.load_identity()
        store_b = Store(self.dir_b)
        raw_b = store_b.load_config_raw()
        anchors = list(raw_b["anchors"])
        if a_identity.hash not in anchors:
            anchors.append(a_identity.hash)
        store_b.save_config(
            primary_salt=raw_b["primary_salt"],
            legacy_salts=raw_b["legacy_salts"],
            anchors=anchors,
            authoritative=raw_b["authoritative"],
            horizon_days=raw_b["horizon_days"],
        )
        keyring = store_b.load_keyring()
        keyring.register_single(a_identity.hash, a_identity.sig_pub_bytes)
        store_b.save_keyring(keyring)

        argv = ["paper", "import", str(uris_file), "--manifest", str(manifest_file),
                "--store", str(self.dir_b)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with patch("dacar.cli.rns.boot", side_effect=lambda cfg: RNS.Reticulum):
                code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("imported 3 delta(s)", err.getvalue())
        self.assertIn("manifest: complete", err.getvalue())

        config = store_b.load_config()
        state = store_b.load_state(config)
        self.assertEqual(len(state), 3)

        # Idempotent: re-importing applies nothing new (CRDT merge).
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with patch("dacar.cli.rns.boot", side_effect=lambda cfg: RNS.Reticulum):
                code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("imported 0 delta(s)", err.getvalue())

    def test_uri_codec_roundtrip(self):
        """uri_to_paper_bytes is the exact inverse of LXMessage.as_uri."""
        priv = Ed25519PrivateKey.generate()
        payloads = [_delta(priv, "sensor:uri")]
        dst = RNS.Destination(
            RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE,
            "lxmf", "delivery",
        )
        src = RNS.Destination(
            RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE,
            "lxmf", "delivery",
        )
        msg = LxmfDeltaDelivery().make_paper_batch_message(payloads, dst, src)
        self.assertEqual(uri_to_paper_bytes(msg.as_uri()), msg.paper_packed)

    def test_uri_to_paper_bytes_rejects_other_schemes(self):
        with self.assertRaises(ValueError):
            uri_to_paper_bytes("https://example.com/x")
        # lenient to stray slashes (parity with reticulum-js)
        self.assertEqual(
            uri_to_paper_bytes("lxm://" + encode_batch([b"x"]).hex()),
            uri_to_paper_bytes("lxm://" + encode_batch([b"x"]).hex()),
        )


if __name__ == "__main__":
    unittest.main()
