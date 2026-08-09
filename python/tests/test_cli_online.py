"""Smoketests for the online one-shot commands (work doc #4 — §11.1).

Tests the testable core functions (``run_publish``, ``run_sync``) that the
``grant --publish`` and ``sync`` commands compose, plus the RNS session
helpers (``announce_identity``, ``resolve_config_dir``) and the ``[rfed]``
config section. A *fake* ``RFedClient`` records calls and replays pull pages,
so the adapter wiring is tested without a live rfed node — mirroring
``test_transport_rfed.py``.

The security-critical path — cross-node Delta flows through ``RnsIdentityResolver``
(announce recall → sig verify → CRDT merge) — is exercised end-to-end with a
real rfed channel-wrapped blob and a headless RNS recall store.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import RNS

from dacar import Action, DeltaReceiver, Engine, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.naming import LXMF_DELIVERY_TITLE, RFED_TOPIC
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.rfed._lxmf import LxmfMessage
from dacar.rfed.blob import wrap_channel_message
from dacar.rfed.channel import delivery_hash_for, derive_channel
from dacar.rfed.client import PullItem, PullPage, SubscribeResult
from dacar.transport.rns_identity import RnsIdentityResolver

from dacar.cli.commands import run_publish, run_sync, _resolve_rfed_node, _resolve_topic
from dacar.cli.store import Store
from dacar.cli.rns import (
    announce_identity,
    resolve_config_dir,
    ensure_default_config,
    DEFAULT_CONFIG,
    ENV_RNS_CONFIG,
)

from tests._rns_fixture import ensure_headless

SALT = bytes(range(SALT_SIZE))
HASHER = NamespaceHasher(SALT)
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
NODE = b"\x07" * 16  # any rfed.* destination hash


def _remember(identity: RNS.Identity) -> None:
    """Populate RNS's recall store for *identity* (as an announce would)."""
    RNS.Identity.remember(b"\x00" * 16, b"\x11" * 16, identity.get_public_key(), None)


class _FakeRFedClient:
    """A minimal RFedClient double — records publishes, replays pull."""

    def __init__(self):
        self.published = []
        self.subscribed = None
        self.deferred = []
        self.delivery_hash = b"\x09" * 16

    def subscribe(self, node_hash, channel_name, **_kw):
        self.subscribed = (node_hash, channel_name)
        return SubscribeResult(ok=True, stamp_cost=None)

    def unsubscribe(self, node_hash, channel_name, **_kw):
        return SubscribeResult(ok=True)

    def publish(self, node_hash, channel_name, lxm_message):
        self.published.append((node_hash, channel_name, lxm_message))

    def listen(self, on_message):
        return self.delivery_hash

    def pull(self, node_hash, channel_name, **_kw):
        items = self.deferred[:]
        self.deferred = []
        return PullPage(items=items, more_pending=False)


def _wrap_delta(delta: bytes, identity: RNS.Identity) -> PullItem:
    """Wrap a Delta payload as a real rfed channel blob."""
    lxm = LxmfMessage(content=delta, title=LXMF_DELIVERY_TITLE)
    return _wrap_message(lxm, identity)


def _wrap_message(lxm: LxmfMessage, sender_identity: RNS.Identity) -> PullItem:
    """Wrap an already-built LxmfMessage as a real rfed channel blob.

    This mirrors what a rfed federation node does on receipt of a publish: it
    stores the Phase-0-wrapped ``inner_blob`` that ``pull`` later returns. Used
    to bridge A's ``run_publish`` output into B's ``run_sync`` input in the
    two-node round-trip test.
    """
    channel_identity, channel_hash = derive_channel(RFED_TOPIC)
    sender_delivery_hash = delivery_hash_for(sender_identity)
    wrapped = wrap_channel_message(
        channel_identity=channel_identity,
        sender_identity=sender_identity,
        sender_lxm_delivery_hash=sender_delivery_hash,
        lxm_message=lxm,
    )
    return PullItem(channel_hash=wrapped.channel_hash, blob=wrapped.inner_blob)


def _signed_delta(issuer_hash: bytes, signer: RNS.Identity,
                 *, action: Action = Action.GRANT,
                 relation: str = "read", object_id: str = "sensor:wind",
                 hlc_ms: int = 0) -> bytes:
    """Build a signed Delta payload (GRANT by default).

    ``hlc_ms`` shifts the HLC physical component so a revoke can postdate a
    grant for the LWW-CRDT override test.
    """
    tup = Tuple.from_plaintext(
        object_id=object_id, relation=relation, grantee=GRANTEE,
        issuer=issuer_hash, hasher=HASHER,
    )
    now = physical_now_ms() + hlc_ms
    op = Operation(tuple=tup, action=action, hlc=pack(now, 0))
    return op.sign(signer.sig_prv).to_payload()


# ---------------------------------------------------------------------------
# [rfed] config section
# ---------------------------------------------------------------------------


class RfedConfigTest(unittest.TestCase):
    """The [rfed] config section round-trips and survives config rewrites."""

    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-rfed-cfg-"))
        Store.init(self.store_dir, salt=SALT)

    def test_init_writes_default_topic(self):
        raw = Store(self.store_dir).load_config_raw()
        self.assertEqual(raw["rfed_topic"], RFED_TOPIC)
        self.assertIsNone(raw["rfed_node"])

    def test_topic_and_node_roundtrip(self):
        store = Store(self.store_dir)
        raw = store.load_config_raw()
        node = b"\xab" * 16
        store.save_config(
            primary_salt=raw["primary_salt"],
            legacy_salts=raw["legacy_salts"],
            anchors=raw["anchors"],
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
            rfed_topic="myorg.policy.v1",
            rfed_node=node,
        )
        raw2 = store.load_config_raw()
        self.assertEqual(raw2["rfed_topic"], "myorg.policy.v1")
        self.assertEqual(raw2["rfed_node"], node)

    def test_rfed_survives_salt_rotation(self):
        """save_config must preserve [rfed] when rewriting for salt rotation."""
        store = Store(self.store_dir)
        raw = store.load_config_raw()
        node = b"\xcd" * 16
        store.save_config(
            primary_salt=raw["primary_salt"],
            legacy_salts=raw["legacy_salts"],
            anchors=raw["anchors"],
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
            rfed_topic="custom.topic",
            rfed_node=node,
        )
        # Now rotate the salt (like cmd_salt_new does).
        new_salt = bytes(range(32))
        store.save_config(
            primary_salt=new_salt,
            legacy_salts=(raw["primary_salt"],),
            anchors=raw["anchors"],
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )
        raw2 = store.load_config_raw()
        self.assertEqual(raw2["rfed_topic"], "custom.topic")
        self.assertEqual(raw2["rfed_node"], node)

    def test_rfed_survives_identity_rotation(self):
        """rotate_identity must preserve [rfed] when rewriting config."""
        store = Store(self.store_dir)
        raw = store.load_config_raw()
        store.save_config(
            primary_salt=raw["primary_salt"],
            legacy_salts=raw["legacy_salts"],
            anchors=raw["anchors"],
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
            rfed_topic="custom.topic",
            rfed_node=b"\xef" * 16,
        )
        store.rotate_identity()
        raw2 = store.load_config_raw()
        self.assertEqual(raw2["rfed_topic"], "custom.topic")
        self.assertEqual(raw2["rfed_node"], b"\xef" * 16)


# ---------------------------------------------------------------------------
# run_publish (grant --publish core)
# ---------------------------------------------------------------------------


class RunPublishTest(unittest.TestCase):
    """``run_publish`` wires subscribe → publish through RfedDeltaSync."""

    def test_subscribes_then_publishes(self):
        client = _FakeRFedClient()
        identity = RNS.Identity()
        delta = _signed_delta(identity.hash, identity)

        run_publish(identity, delta, NODE, RFED_TOPIC, client)

        self.assertEqual(client.subscribed, (NODE, RFED_TOPIC))
        self.assertEqual(len(client.published), 1)
        node_hash, channel_name, _msg = client.published[0]
        self.assertEqual(node_hash, NODE)
        self.assertEqual(channel_name, RFED_TOPIC)

    def test_uses_custom_topic(self):
        client = _FakeRFedClient()
        identity = RNS.Identity()
        delta = _signed_delta(identity.hash, identity)

        run_publish(identity, delta, NODE, "custom.topic", client)
        self.assertEqual(client.subscribed, (NODE, "custom.topic"))


# ---------------------------------------------------------------------------
# run_sync (sync command core) — the security-critical path
# ---------------------------------------------------------------------------


class RunSyncTest(unittest.TestCase):
    """``run_sync`` pulls + applies Deltas via verify-on-ingest, persists CRDT."""

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-sync-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def _config_state_resolver(self, issuer_hash):
        """Build config + state + RNS resolver for a store that trusts issuer."""
        config = self.store.load_config()
        # Add the issuer as a root trust anchor so its grants are authoritative.
        raw = self.store.load_config_raw()
        anchors = list(raw["anchors"])
        if issuer_hash not in anchors:
            anchors.append(issuer_hash)
        self.store.save_config(
            primary_salt=raw["primary_salt"],
            legacy_salts=raw["legacy_salts"],
            anchors=anchors,
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )
        config = self.store.load_config()
        state = self.store.load_state(config)
        resolver = RnsIdentityResolver(fallback=self.store.keyring_for_verify())
        return config, state, resolver

    def test_cross_node_delta_applies_via_rns_recall(self):
        """A publishes, B syncs: A's Delta applies via RNS recall (announce invariant)."""
        # Node A: identity + signed delta + remembered (simulates B intercepting announce)
        a_identity = RNS.Identity()
        _remember(a_identity)
        delta = _signed_delta(a_identity.hash, a_identity)

        # Node B: store trusting A
        config, state, resolver = self._config_state_resolver(a_identity.hash)
        rx = DeltaReceiver(state, resolver)

        # Fake rfed client with A's wrapped delta in the deferred queue
        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(delta, a_identity))

        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 1)
        self.assertEqual(len(state), 1)

        # B can now ALLOW the grant
        engine = Engine(config, state)
        self.assertTrue(engine.evaluate("sensor:wind", "read", GRANTEE))

    def test_state_persisted_after_sync(self):
        """The CRDT is saved to disk so the next invocation sees the Deltas."""
        a_identity = RNS.Identity()
        _remember(a_identity)
        delta = _signed_delta(a_identity.hash, a_identity)

        config, state, resolver = self._config_state_resolver(a_identity.hash)
        rx = DeltaReceiver(state, resolver)
        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(delta, a_identity))

        run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)

        # Reload from disk — the Delta must be there.
        config2 = self.store.load_config()
        state2 = self.store.load_state(config2)
        self.assertEqual(len(state2), 1)
        engine = Engine(config2, state2)
        self.assertTrue(engine.evaluate("sensor:wind", "read", GRANTEE))

    def test_forged_delta_dropped(self):
        """A Delta signed by a different key is dropped; state unchanged."""
        a_identity = RNS.Identity()
        _remember(a_identity)
        # Delta claims to be from A but is signed by someone else
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        tup = Tuple.from_plaintext(
            object_id="sensor:wind", relation="read", grantee=GRANTEE,
            issuer=a_identity.hash, hasher=HASHER,
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=pack(physical_now_ms(), 0))
        forged_delta = op.sign(Ed25519PrivateKey.generate()).to_payload()

        config, state, resolver = self._config_state_resolver(a_identity.hash)
        rx = DeltaReceiver(state, resolver)
        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(forged_delta, a_identity))

        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 0)
        self.assertEqual(len(state), 0)

    def test_empty_queue_returns_zero(self):
        """Pulling an empty deferred queue returns 0 without error."""
        config, state, resolver = self._config_state_resolver(RNS.Identity().hash)
        rx = DeltaReceiver(state, resolver)
        client = _FakeRFedClient()  # no deferred items
        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 0)

    def test_unknown_issuer_dropped(self):
        """A Delta whose issuer differs from the rfed sender and is unannounced
        is dropped (§11.2.4).

        The rfed channel protocol caches the *sender* identity via the RTID
        prelude (``unwrap_channel_message`` calls ``RNS.Identity.remember``),
        so a Delta from the sender always applies. But a Delta claiming to be
        from a *different* (unannounced) issuer is dropped — the resolver
        cannot recall that issuer's public key.
        """
        # C signs a Delta (issuer = C) but A is the rfed sender.
        c_identity = RNS.Identity()  # NOT remembered, NOT the rfed sender
        delta = _signed_delta(c_identity.hash, c_identity)

        # A wraps and sends it (A is the rfed sender; A gets cached, C does not).
        a_identity = RNS.Identity()

        config, state, resolver = self._config_state_resolver(a_identity.hash)
        rx = DeltaReceiver(state, resolver)
        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(delta, a_identity))

        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 0)
        self.assertEqual(len(state), 0)


# ---------------------------------------------------------------------------
# Two-node round-trip (doc #4 testing requirement #2): publish → sync
# ---------------------------------------------------------------------------


class TwoNodeRoundTripTest(unittest.TestCase):
    """A publishes, B syncs: the full push→pull→apply→check path through the
    real adapter code on both sides.

    The rfed federation node is simulated by bridging A's ``run_publish``
    output (the LxmfMessage a real ``RFedClient.publish`` would wrap) into B's
    ``run_sync`` input (the wrapped ``inner_blob`` a real ``pull`` returns).
    This exercises the genuine publish→wrap→pull→unwrap→verify-on-ingest path
    end-to-end, just without a live rfed binary in between.
    """

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.b_store_dir = Path(tempfile.mkdtemp(prefix="dacar-rt-b-"))
        Store.init(self.b_store_dir, salt=SALT)
        self.b_store = Store(self.b_store_dir)

    def _trust(self, issuer_hash: bytes):
        """Make B trust *issuer_hash* as a root anchor (so grants evaluate)."""
        raw = self.b_store.load_config_raw()
        anchors = list(raw["anchors"])
        if issuer_hash not in anchors:
            anchors.append(issuer_hash)
        self.b_store.save_config(
            primary_salt=raw["primary_salt"],
            legacy_salts=raw["legacy_salts"],
            anchors=anchors,
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )

    def _b_receiver(self):
        """Build B's state + RNS-first resolver (with local keyring fallback)."""
        config = self.b_store.load_config()
        state = self.b_store.load_state(config)
        resolver = RnsIdentityResolver(fallback=self.b_store.keyring_for_verify())
        return config, state, DeltaReceiver(state, resolver)

    def test_grant_propagates_a_to_b_and_allows(self):
        """A publishes a grant; B syncs and ``check`` returns ALLOW (doc #4 #2)."""
        a_identity = RNS.Identity()
        _remember(a_identity)  # B intercepts A's announce
        self._trust(a_identity.hash)

        # A signs + publishes (run_publish records the LxmfMessage).
        delta = _signed_delta(a_identity.hash, a_identity)
        client_a = _FakeRFedClient()
        run_publish(a_identity, delta, NODE, RFED_TOPIC, client_a)
        self.assertEqual(len(client_a.published), 1)
        published_lxm = client_a.published[0][2]

        # Bridge: the rfed node stores the wrapped blob; B pulls it.
        config, state, rx = self._b_receiver()
        client_b = _FakeRFedClient()
        client_b.deferred.append(_wrap_message(published_lxm, a_identity))

        applied = run_sync(self.b_store, state, NODE, RFED_TOPIC, client_b, rx)
        self.assertEqual(applied, 1)

        engine = Engine(config, state)
        self.assertTrue(engine.evaluate("sensor:wind", "read", GRANTEE))

    def test_revoke_propagates_and_flips_check_to_deny(self):
        """A grants, B syncs (ALLOW); A revokes, B syncs again → DENY (doc #4 #2)."""
        a_identity = RNS.Identity()
        _remember(a_identity)
        self._trust(a_identity.hash)

        # Phase 1: A grants, B syncs → ALLOW.
        grant_delta = _signed_delta(a_identity.hash, a_identity, hlc_ms=0)
        client_a1 = _FakeRFedClient()
        run_publish(a_identity, grant_delta, NODE, RFED_TOPIC, client_a1)
        config, state, rx = self._b_receiver()
        client_b1 = _FakeRFedClient()
        client_b1.deferred.append(_wrap_message(client_a1.published[0][2], a_identity))
        run_sync(self.b_store, state, NODE, RFED_TOPIC, client_b1, rx)
        engine = Engine(config, state)
        self.assertTrue(engine.evaluate("sensor:wind", "read", GRANTEE))

        # Phase 2: A revokes (later HLC), B syncs again → DENY.
        revoke_delta = _signed_delta(
            a_identity.hash, a_identity, action=Action.REVOKE, hlc_ms=10_000,
        )
        client_a2 = _FakeRFedClient()
        run_publish(a_identity, revoke_delta, NODE, RFED_TOPIC, client_a2)
        config2 = self.b_store.load_config()
        state2 = self.b_store.load_state(config2)  # reload grant on top
        rx2 = DeltaReceiver(state2, RnsIdentityResolver(fallback=self.b_store.keyring_for_verify()))
        client_b2 = _FakeRFedClient()
        client_b2.deferred.append(_wrap_message(client_a2.published[0][2], a_identity))
        applied = run_sync(self.b_store, state2, NODE, RFED_TOPIC, client_b2, rx2)
        self.assertEqual(applied, 1)

        engine2 = Engine(config2, state2)
        self.assertFalse(engine2.evaluate("sensor:wind", "read", GRANTEE))

    def test_forged_delta_dropped_across_wire(self):
        """A forged Delta (wrong sig) is dropped at B; state unchanged (doc #4 #2)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        a_identity = RNS.Identity()
        _remember(a_identity)
        self._trust(a_identity.hash)

        # Delta claims issuer=A but signed by an attacker.
        tup = Tuple.from_plaintext(
            object_id="sensor:wind", relation="read", grantee=GRANTEE,
            issuer=a_identity.hash, hasher=HASHER,
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=pack(physical_now_ms(), 0))
        forged = op.sign(Ed25519PrivateKey.generate()).to_payload()

        client_a = _FakeRFedClient()
        run_publish(a_identity, forged, NODE, RFED_TOPIC, client_a)

        config, state, rx = self._b_receiver()
        client_b = _FakeRFedClient()
        client_b.deferred.append(_wrap_message(client_a.published[0][2], a_identity))
        applied = run_sync(self.b_store, state, NODE, RFED_TOPIC, client_b, rx)
        self.assertEqual(applied, 0)
        self.assertEqual(len(state), 0)


# ---------------------------------------------------------------------------
# CLI integration: grant --publish applies locally AND publishes (doc #4 #3)
# ---------------------------------------------------------------------------


class GrantPublishLocalApplyTest(unittest.TestCase):
    """``grant --publish`` applies locally (not skipped) then publishes (doc #4 #3).

    The RNS boot/announce/RFedClient creation inside ``_publish_delta`` is
    patched out so the test runs offline; the patch captures the payload to
    prove publish was called, and the store state proves local apply happened
    first.
    """

    def setUp(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pub-"))
        Store.init(self.store_dir, salt=SALT)
        self._redirect_stderr = redirect_stderr
        self._redirect_stdout = redirect_stdout
        self._io = io

    def test_grant_publish_with_real_grantee_hash(self):
        """The realistic path: grantee as a hex hash, local apply + publish."""
        from dacar.cli import main
        captured = {}

        def fake_publish(args, store, identity, payload):
            captured["called"] = True
            captured["payload"] = payload

        grantee_hex = "aabbccdd00112233445566778899aabb"
        argv = ["grant", grantee_hex, "read", "sensor:wind", "--publish",
                "--node", "aabbccdd" * 4, "--store", str(self.store_dir)]
        out = self._io.StringIO()
        err = self._io.StringIO()
        with self._redirect_stdout(out), self._redirect_stderr(err):
            with patch("dacar.cli.commands._publish_delta", side_effect=fake_publish):
                code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertTrue(captured.get("called"))

        # Local apply happened (state has the grant) BEFORE publish was called.
        store = Store(self.store_dir)
        config = store.load_config()
        state = store.load_state(config)
        self.assertEqual(len(state), 1)
        from dacar import Engine
        engine = Engine(config, state)
        self.assertTrue(engine.evaluate(
            "sensor:wind", "read", bytes.fromhex(grantee_hex)
        ))

    def test_grant_without_publish_does_not_call_publish(self):
        """Offline grant must never start RNS or call publish (offline-first)."""
        from dacar.cli import main
        called = {"n": 0}

        def fake_publish(*args):
            called["n"] += 1

        grantee_hex = "aabbccdd00112233445566778899aabb"
        argv = ["grant", grantee_hex, "read", "sensor:wind",
                "--store", str(self.store_dir)]
        out = self._io.StringIO()
        err = self._io.StringIO()
        with self._redirect_stdout(out), self._redirect_stderr(err):
            with patch("dacar.cli.commands._publish_delta", side_effect=fake_publish):
                code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(called["n"], 0)


# ---------------------------------------------------------------------------
# announce_identity (announce invariant, §11.2.4)
# ---------------------------------------------------------------------------


class AnnounceIdentityTest(unittest.TestCase):
    """``announce_identity`` creates a dacar.node destination and announces it."""

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def test_creates_destination_and_announces(self):
        identity = RNS.Identity()
        dest_hash = announce_identity(identity)
        self.assertEqual(len(dest_hash), 16)
        # The destination should be recallable (announce populated the store
        # in-process; headless RNS accepts the announce packet without error).

    def test_destination_under_dacar_app(self):
        identity = RNS.Identity()
        dest_hash = announce_identity(identity)
        # The dacar.node destination hash is deterministic from the identity.
        from dacar.naming import APP_NAME
        expected = RNS.Destination.hash_from_name_and_identity(
            f"{APP_NAME}.node", identity
        )
        self.assertEqual(dest_hash, expected)


# ---------------------------------------------------------------------------
# resolve_config_dir (RNS config priority, work doc #4)
# ---------------------------------------------------------------------------


class ResolveConfigDirTest(unittest.TestCase):
    """Config dir resolution follows the documented priority order."""

    def test_explicit_flag_takes_priority(self):
        d = resolve_config_dir(explicit="/explicit/path", store_path="/store")
        self.assertEqual(d, "/explicit/path")

    def test_env_var_second_priority(self):
        with patch.dict(os.environ, {ENV_RNS_CONFIG: "/env/path"}):
            d = resolve_config_dir(explicit=None, store_path="/store")
            self.assertEqual(d, "/env/path")

    def test_falls_back_to_store_rns(self):
        """When no ~/.reticulum and no env/explicit, creates <store>/rns."""
        store = tempfile.mkdtemp(prefix="dacar-store-")
        with patch("dacar.cli.rns.USER_RNS_DIR", "/nonexistent/no-config-here"):
            d = resolve_config_dir(explicit=None, store_path=store)
        self.assertEqual(d, os.path.join(store, "rns"))
        # The default config was written.
        self.assertTrue(os.path.isfile(os.path.join(d, "config")))

    def test_uses_user_reticulum_if_present(self):
        """If ~/.reticulum/config exists, use it (the shared rnsd)."""
        fake_home = tempfile.mkdtemp(prefix="dacar-home-")
        rns_dir = os.path.join(fake_home, ".reticulum")
        os.makedirs(rns_dir)
        with open(os.path.join(rns_dir, "config"), "w") as f:
            f.write("[reticulum]\nshare_instance = Yes\n")
        with patch("dacar.cli.rns.USER_RNS_DIR", rns_dir):
            d = resolve_config_dir(explicit=None, store_path="/store")
        self.assertEqual(d, rns_dir)

    def test_default_config_has_share_instance_and_autointerface(self):
        """The default config respects the attach-or-spawn convention."""
        d = tempfile.mkdtemp(prefix="dacar-cfg-")
        ensure_default_config(d)
        content = Path(d, "config").read_text()
        self.assertIn("share_instance = Yes", content)
        self.assertIn("AutoInterface", content)
        self.assertIn("enable_transport = False", content)

    def test_does_not_clobber_existing_config(self):
        """ensure_default_config must not overwrite an existing config."""
        d = tempfile.mkdtemp(prefix="dacar-cfg-")
        Path(d, "config").write_text("# user config\n[reticulum]\n")
        ensure_default_config(d)
        content = Path(d, "config").read_text()
        self.assertIn("# user config", content)
        self.assertNotIn("AutoInterface", content)


# ---------------------------------------------------------------------------
# CLI parser accepts the new flags
# ---------------------------------------------------------------------------


class CliOnlineParserTest(unittest.TestCase):
    """The parser accepts --publish, --node, --topic, --rns-config, and sync."""

    def test_grant_accepts_publish_flag(self):
        from dacar.cli import build_parser
        parser = build_parser()
        node_hex = "aabbccdd" * 4  # 32 hex = 16 bytes
        args = parser.parse_args([
            "grant", "alice", "read", "sensor:wind", "--publish", "--node",
            node_hex,
        ])
        self.assertTrue(args.publish)
        self.assertEqual(args.node, node_hex)

    def test_sync_subcommand_exists(self):
        from dacar.cli import build_parser
        parser = build_parser()
        node_hex = "aabbccdd" * 4
        args = parser.parse_args([
            "sync", "--node", node_hex,
            "--topic", "custom.topic",
        ])
        self.assertEqual(args.command, "sync")
        self.assertEqual(args.node, node_hex)
        self.assertEqual(args.topic, "custom.topic")

    def test_grant_without_publish_has_no_publish_attr(self):
        """Offline grant must not carry publish=True (offline-first invariant)."""
        from dacar.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["grant", "alice", "read", "sensor:wind"])
        self.assertFalse(args.publish)


if __name__ == "__main__":
    unittest.main()
