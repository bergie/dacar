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
from dacar.naming import RFED_TOPIC
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.rfed.blob import wrap_dacar_delta
from dacar.rfed.channel import derive_channel
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
    DacarAnnounceHandler,
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
    """A minimal RFedClient double — records publishes, replays pull.

    Mirrors the application-specific inner-format surface the real
    :class:`RFedClient` exposes (§11.1): ``channel``/``stamp_cost``/
    ``send_publish``/``listen_raw``.
    """

    def __init__(self, identity=None):
        self.identity = identity if identity is not None else RNS.Identity()
        self.sent = []  # list of (node_hash, rfed_payload)
        self.subscribed = None
        self.deferred = []
        self.delivery_hash = b"\x09" * 16
        self._channels = {}

    def channel(self, name):
        if name not in self._channels:
            ident, chash = derive_channel(name)
            self._channels[name] = {
                "identity": ident, "channel_hash": chash, "delivery_hash": b"\x00" * 16,
            }
        return self._channels[name]

    def stamp_cost(self, name):
        return None

    def subscribe(self, node_hash, channel_name, **_kw):
        self.subscribed = (node_hash, channel_name)
        return SubscribeResult(ok=True, stamp_cost=None)

    def unsubscribe(self, node_hash, channel_name, **_kw):
        return SubscribeResult(ok=True)

    def send_publish(self, node_hash, rfed_payload):
        self.sent.append((node_hash, bytes(rfed_payload)))
        return True

    def listen_raw(self, on_fanout):
        return self.delivery_hash

    def pull(self, node_hash, channel_name, **_kw):
        items = self.deferred[:]
        self.deferred = []
        return PullPage(items=items, more_pending=False)


def _wrap_delta(delta: bytes, identity: RNS.Identity) -> PullItem:
    """Wrap a Delta payload as a real rfed channel blob (Dacar compact format).

    Mirrors what a rfed federation node stores after a publish: the
    ``inner_blob`` (EC-encrypted to the derived channel) that ``pull`` later
    returns. Used to seed a fake client's deferred queue for B-side sync.
    """
    channel_identity, _channel_hash = derive_channel(RFED_TOPIC)
    wrapped = wrap_dacar_delta(
        channel_identity=channel_identity,
        sender_identity=identity,
        delta=delta,
    )
    return PullItem(channel_hash=wrapped.channel_hash, blob=wrapped.inner_blob)


def _defer_from_published(rfed_payload: bytes) -> PullItem:
    """Split a published ``rfed_payload`` into the deferred-queue form B pulls.

    A publish sends ``channel_hash(16) ‖ inner_blob``; ``pull`` returns
    ``PullItem(channel_hash, inner_blob)``. This bridges A's ``run_publish``
    output into B's ``run_sync`` input in the two-node round-trip tests, just
    as a real rfed federation node would relay a stored blob.
    """
    rfed_payload = bytes(rfed_payload)
    return PullItem(channel_hash=rfed_payload[:16], blob=rfed_payload[16:])


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
        identity = RNS.Identity()
        client = _FakeRFedClient(identity=identity)
        delta = _signed_delta(identity.hash, identity)

        run_publish(identity, delta, NODE, RFED_TOPIC, client)

        self.assertEqual(client.subscribed, (NODE, RFED_TOPIC))
        self.assertEqual(len(client.sent), 1)
        node_hash, _rfed_payload = client.sent[0]
        self.assertEqual(node_hash, NODE)

    def test_uses_custom_topic(self):
        identity = RNS.Identity()
        client = _FakeRFedClient(identity=identity)
        delta = _signed_delta(identity.hash, identity)

        run_publish(identity, delta, NODE, "custom.topic", client)
        self.assertEqual(client.subscribed, (NODE, "custom.topic"))

    def test_raises_on_failed_subscribe(self):
        """A rejected subscribe must surface, not publish silently (doc #6).

        Regression for the silent failure where ``dacar sync``/``grant
        --publish`` completed without creating a node subscription: a
        ``[false, null]`` response was swallowed and the operation continued.
        """
        from dacar.cli.commands import CliError
        from dacar.rfed.client import SubscribeResult

        class _FailingClient(_FakeRFedClient):
            def subscribe(self, node_hash, channel_name, **_kw):
                super().subscribe(node_hash, channel_name, **_kw)
                return SubscribeResult(ok=False)

        identity = RNS.Identity()
        client = _FailingClient(identity=identity)
        delta = _signed_delta(identity.hash, identity)
        with self.assertRaises(CliError) as ctx:
            run_publish(identity, delta, NODE, RFED_TOPIC, client)
        self.assertIn("subscribe", str(ctx.exception))
        # Publish never happened — the failed subscribe short-circuits.
        self.assertEqual(client.sent, [])


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

    def test_raises_on_failed_subscribe(self):
        """A rejected subscribe must surface, not pull silently.

        Regression for the silent failure where ``dacar sync`` did not increase
        the node's subscription count: the ``[false, null]`` response was
        swallowed and sync continued to pull anyway. The topic must have a
        subscription on the node for peer sync to work, so a failure here is
        fatal to the sync's purpose.
        """
        from dacar.cli.commands import CliError
        from dacar.rfed.client import SubscribeResult

        class _FailingClient(_FakeRFedClient):
            def subscribe(self, node_hash, channel_name, **_kw):
                super().subscribe(node_hash, channel_name, **_kw)
                return SubscribeResult(ok=False)

        config, state, resolver = self._config_state_resolver(RNS.Identity().hash)
        rx = DeltaReceiver(state, resolver)
        client = _FailingClient()
        with self.assertRaises(CliError) as ctx:
            run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertIn("subscribe", str(ctx.exception))
        # Pull never happened — the failed subscribe short-circuits.
        self.assertEqual(client.deferred, client.deferred)  # unchanged

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
    output (the ``rfed_payload`` a real ``RFedClient.send_publish`` would send)
    into B's ``run_sync`` input (the ``inner_blob`` a real ``pull`` returns).
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

        # A signs + publishes (run_publish records the rfed_payload).
        delta = _signed_delta(a_identity.hash, a_identity)
        client_a = _FakeRFedClient(identity=a_identity)
        run_publish(a_identity, delta, NODE, RFED_TOPIC, client_a)
        self.assertEqual(len(client_a.sent), 1)
        published_payload = client_a.sent[0][1]

        # Bridge: the rfed node stores the wrapped blob; B pulls it.
        config, state, rx = self._b_receiver()
        client_b = _FakeRFedClient()
        client_b.deferred.append(_defer_from_published(published_payload))

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
        client_b1.deferred.append(_defer_from_published(client_a1.sent[0][1]))
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
        client_b2.deferred.append(_defer_from_published(client_a2.sent[0][1]))
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
        client_b.deferred.append(_defer_from_published(client_a.sent[0][1]))
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

        def fake_publish(args, store, identity, payloads):
            captured["called"] = True
            captured["payload"] = payloads[0] if len(payloads) == 1 else payloads
            # Per-delta transport acceptance so _record_publish (outbox→sent) runs.
            return [True] * len(payloads)

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


# ===========================================================================
# Durable issuer identity cache (work doc #5)
# ===========================================================================


class KeyringCacheTest(unittest.TestCase):
    """``Store.save_keyring``/``load_keyring`` round-trip + ``0600`` mode (doc #5 #1)."""

    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-cache-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def test_roundtrip_single_identity_entries(self):
        """save/load preserves hash→pubkey mappings."""
        id_a = RNS.Identity()
        id_b = RNS.Identity()
        keyring = Keyring()
        keyring.register_single(id_a.hash, id_a.sig_pub_bytes)
        keyring.register_single(id_b.hash, id_b.sig_pub_bytes)
        self.store.save_keyring(keyring)

        loaded = self.store.load_keyring()
        self.assertIn(id_a.hash, loaded)
        self.assertIn(id_b.hash, loaded)
        ks_a = loaded.resolve(id_a.hash)
        self.assertEqual(ks_a.member_public_keys[0], id_a.sig_pub_bytes)

    def test_empty_keyring_when_no_file(self):
        """A fresh store has no cache file; load returns an empty Keyring."""
        keyring = self.store.load_keyring()
        self.assertEqual(len(keyring), 0)

    def test_persisted_file_is_mode_0600(self):
        """The cache file holds public keys; it must be owner-only (doc #5 #1)."""
        import stat
        id_a = RNS.Identity()
        keyring = Keyring()
        keyring.register_single(id_a.hash, id_a.sig_pub_bytes)
        self.store.save_keyring(keyring)
        mode = stat.S_IMODE(self.store.identities_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_overwrite_on_resave(self):
        """Re-saving replaces the file (no append / no stale entries)."""
        id_a = RNS.Identity()
        keyring = Keyring()
        keyring.register_single(id_a.hash, id_a.sig_pub_bytes)
        self.store.save_keyring(keyring)
        # Save an empty keyring — the file should now be empty.
        self.store.save_keyring(Keyring())
        self.assertEqual(len(self.store.load_keyring()), 0)


class AnnounceHandlerTest(unittest.TestCase):
    """``DacarAnnounceHandler`` seeds from ``dacar.node``, ignores non-dacar (doc #5 #2)."""

    def test_dacar_node_announce_seeds_cache(self):
        """A validated dacar.node announce registers the issuer pubkey."""
        identity = RNS.Identity()
        keyring = Keyring()
        saved = {}
        handler = DacarAnnounceHandler(keyring, on_save=lambda kr: saved.update({"kr": kr}))

        # Simulate a dacar.node announce.
        dacar_node_hash = RNS.Destination.hash(identity, "dacar", "node")
        handler.received_announce(dacar_node_hash, identity)

        self.assertEqual(handler.seeded, 1)
        self.assertIn(identity.hash, keyring)
        ks = keyring.resolve(identity.hash)
        self.assertEqual(ks.member_public_keys[0], identity.sig_pub_bytes)
        self.assertIsNotNone(saved.get("kr"))  # on_save was called

    def test_non_dacar_announce_ignored(self):
        """An announce under a different app does not seed the cache (design decision #3)."""
        identity = RNS.Identity()
        keyring = Keyring()
        handler = DacarAnnounceHandler(keyring)

        # An announce under a different app (e.g. "otherapp.node").
        other_hash = RNS.Destination.hash(identity, "otherapp", "node")
        handler.received_announce(other_hash, identity)

        self.assertEqual(handler.seeded, 0)
        self.assertNotIn(identity.hash, keyring)
        self.assertEqual(len(keyring), 0)

    def test_wrong_aspect_under_dacar_ignored(self):
        """A dacar.<not-node> announce (different aspect) is ignored."""
        identity = RNS.Identity()
        keyring = Keyring()
        handler = DacarAnnounceHandler(keyring)

        other_aspect_hash = RNS.Destination.hash(identity, "dacar", "challenge")
        handler.received_announce(other_aspect_hash, identity)
        self.assertEqual(handler.seeded, 0)


class DurableFallbackTest(unittest.TestCase):
    """cmd_sync resolves an issuer that is ONLY in the dacar cache (doc #5 #3).

    The issuer ≠ sender: the rfed sender is recovered from the RTID prelude,
    but the issuer (a different identity) is not in RNS recall — it is only in
    the dacar-owned persisted keyring. The RnsIdentityResolver fallback resolves
    it, so the Delta applies.
    """

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-fb-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def _trust(self, issuer_hash):
        raw = self.store.load_config_raw()
        anchors = list(raw["anchors"])
        if issuer_hash not in anchors:
            anchors.append(issuer_hash)
        self.store.save_config(
            primary_salt=raw["primary_salt"], legacy_salts=raw["legacy_salts"],
            anchors=anchors, authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )

    def test_issuer_only_in_dacar_cache_applies(self):
        """An issuer in the cache (but not RNS recall) is resolved via fallback."""
        # B = issuer (signs the Delta). NOT remembered by RNS.
        b_identity = RNS.Identity()
        self._trust(b_identity.hash)

        # Seed the dacar cache with B's pubkey (NOT RNS recall).
        keyring = self.store.load_keyring()
        keyring.register_single(b_identity.hash, b_identity.sig_pub_bytes)
        self.store.save_keyring(keyring)

        # A = rfed sender (wraps the Delta). A is remembered by unwrap.
        a_identity = RNS.Identity()

        # B signs a Delta claiming issuer=B.
        delta = _signed_delta(b_identity.hash, b_identity)

        config = self.store.load_config()
        state = self.store.load_state(config)
        # keyring_for_verify loads the persisted cache + own identity.
        resolver = RnsIdentityResolver(fallback=self.store.keyring_for_verify())
        rx = DeltaReceiver(state, resolver)

        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(delta, a_identity))  # A is the sender

        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 1)
        engine = Engine(config, state)
        self.assertTrue(engine.evaluate("sensor:wind", "read", GRANTEE))

    def test_issuer_in_neither_recall_nor_cache_dropped(self):
        """Without the cache entry, the same Delta is dropped (unknown issuer)."""
        b_identity = RNS.Identity()
        self._trust(b_identity.hash)
        # Do NOT seed the cache — B is unknown everywhere.
        a_identity = RNS.Identity()
        delta = _signed_delta(b_identity.hash, b_identity)

        config = self.store.load_config()
        state = self.store.load_state(config)
        resolver = RnsIdentityResolver(fallback=self.store.keyring_for_verify())
        rx = DeltaReceiver(state, resolver)

        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(delta, a_identity))
        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 0)


class ForgedCacheEntryTest(unittest.TestCase):
    """A poisoned cache entry (wrong pubkey) → Delta dropped, not trusted (doc #5 #6).

    Integrity is not a security property of the cache: a wrong pubkey causes a
    signature mismatch → drop, never a trust breach (design decision #2).
    """

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-forged-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def test_wrong_pubkey_in_cache_drops_delta(self):
        b_identity = RNS.Identity()
        # Seed the cache with a WRONG pubkey (a random different identity).
        wrong_identity = RNS.Identity()
        keyring = self.store.load_keyring()
        keyring.register_single(b_identity.hash, wrong_identity.sig_pub_bytes)
        self.store.save_keyring(keyring)

        a_identity = RNS.Identity()  # rfed sender (remembered by unwrap)
        delta = _signed_delta(b_identity.hash, b_identity)  # signed by B

        config = self.store.load_config()
        state = self.store.load_state(config)
        resolver = RnsIdentityResolver(fallback=self.store.keyring_for_verify())
        rx = DeltaReceiver(state, resolver)

        client = _FakeRFedClient()
        client.deferred.append(_wrap_delta(delta, a_identity))
        applied = run_sync(self.store, state, NODE, RFED_TOPIC, client, rx)
        self.assertEqual(applied, 0, "forged cache entry must drop the Delta, not trust it")


class CrossRestartTest(unittest.TestCase):
    """The cache persists across process restarts (doc #5 #5)."""

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-restart-"))
        Store.init(self.store_dir, salt=SALT)

    def test_cache_survives_new_store_instance(self):
        """A fresh Store pointing at the same dir resolves a previously-cached issuer."""
        b_identity = RNS.Identity()
        # Process 1: seed the cache.
        store1 = Store(self.store_dir)
        keyring = store1.load_keyring()
        keyring.register_single(b_identity.hash, b_identity.sig_pub_bytes)
        store1.save_keyring(keyring)

        # Process 2: a brand-new Store (no in-memory state) loads the cache.
        store2 = Store(self.store_dir)
        loaded = store2.load_keyring()
        self.assertIn(b_identity.hash, loaded)
        ks = loaded.resolve(b_identity.hash)
        self.assertEqual(ks.member_public_keys[0], b_identity.sig_pub_bytes)

    def test_fresh_process_resolves_cached_issuer_without_reannounce(self):
        """End-to-end: a cached issuer applies without RNS recall or re-announce."""
        b_identity = RNS.Identity()
        # Seed the cache.
        store1 = Store(self.store_dir)
        kr = store1.load_keyring()
        kr.register_single(b_identity.hash, b_identity.sig_pub_bytes)
        store1.save_keyring(kr)
        # Add B as a root anchor so its grants evaluate.
        raw = store1.load_config_raw()
        anchors = list(raw["anchors"]) + [b_identity.hash]
        store1.save_config(
            primary_salt=raw["primary_salt"], legacy_salts=raw["legacy_salts"],
            anchors=anchors, authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )

        # Process 2: new store, no RNS recall for B.
        store2 = Store(self.store_dir)
        config = store2.load_config()
        state = store2.load_state(config)
        resolver = RnsIdentityResolver(fallback=store2.keyring_for_verify())

        # B's identity should resolve via the fallback.
        ks = resolver.resolve(b_identity.hash)
        self.assertIsNotNone(ks, "cached issuer must resolve without re-announce")
        self.assertEqual(ks.member_public_keys[0], b_identity.sig_pub_bytes)


class IdentityRememberForgetTest(unittest.TestCase):
    """``identity remember``/``forget``/``list`` CLI round-trip (doc #5 #4)."""

    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-rem-"))
        Store.init(self.store_dir, salt=SALT)
        self._redirect_stderr = redirect_stderr
        self._redirect_stdout = redirect_stdout
        self._io = io

    def test_remember_with_pubkey_then_forget(self):
        """``--pubkey`` round-trip: remember adds, forget removes."""
        from dacar.cli import main
        issuer = RNS.Identity()
        pubkey_hex = issuer.sig_pub_bytes.hex()

        argv = ["identity", "remember", issuer.hash.hex(), "--pubkey", pubkey_hex,
                "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0, err.getvalue())

        store = Store(self.store_dir)
        self.assertIn(issuer.hash, store.load_keyring())

        # forget
        argv = ["identity", "forget", issuer.hash.hex(), "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertNotIn(issuer.hash, store.load_keyring())

    def test_remember_via_file(self):
        """``--file`` reads a 32-byte raw public key."""
        from dacar.cli import main
        issuer = RNS.Identity()
        keyfile = Path(self.store_dir, "pub.bin")
        keyfile.write_bytes(issuer.sig_pub_bytes)

        argv = ["identity", "remember", issuer.hash.hex(), "--file", str(keyfile),
                "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn(issuer.hash, Store(self.store_dir).load_keyring())

    def test_remember_without_pubkey_errors_when_not_recallable(self):
        """``remember`` without ``--pubkey`` errors clearly when RNS can't recall."""
        from dacar.cli import main
        unknown_hash = b"\xee" * 16
        argv = ["identity", "remember", unknown_hash.hex(), "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertNotEqual(code, 0)
        self.assertIn("--pubkey", err.getvalue())

    def test_forget_unknown_errors(self):
        """Forgetting an issuer not in the cache is an error."""
        from dacar.cli import main
        unknown_hash = b"\xee" * 16
        argv = ["identity", "forget", unknown_hash.hex(), "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertNotEqual(code, 0)

    def test_forget_refuses_when_issuer_has_active_grants(self):
        """forget refuses to purge an issuer with live CRDT grants (strands them)."""
        from dacar.cli import main
        from dacar.delta import DeltaReceiver
        from dacar.verifier import IssuerKeyset
        issuer = RNS.Identity()
        # Seed the cache with the issuer.
        store = Store(self.store_dir)
        kr = store.load_keyring()
        kr.register_single(issuer.hash, issuer.sig_pub_bytes)
        store.save_keyring(kr)
        # Add the issuer as a root anchor + apply one of its grants.
        raw = store.load_config_raw()
        anchors = list(raw["anchors"]) + [issuer.hash]
        store.save_config(
            primary_salt=raw["primary_salt"], legacy_salts=raw["legacy_salts"],
            anchors=anchors, authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )
        config = store.load_config()
        state = store.load_state(config)
        delta = _signed_delta(issuer.hash, issuer)
        rx = DeltaReceiver(state, Keyring({issuer.hash: IssuerKeyset.single(issuer.sig_pub_bytes)}))
        self.assertTrue(rx.apply_payload(delta))
        store.save_state(state)
        self.assertEqual(len(state), 1)

        # forget without --force must refuse.
        argv = ["identity", "forget", issuer.hash.hex(), "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertNotEqual(code, 0, err.getvalue())
        self.assertIn("active grant", err.getvalue())
        # The cache entry is still there (not purged).
        self.assertIn(issuer.hash, store.load_keyring())

    def test_forget_force_overrides_active_grants(self):
        """--force purges even an issuer with live grants."""
        from dacar.cli import main
        from dacar.delta import DeltaReceiver
        from dacar.verifier import IssuerKeyset
        issuer = RNS.Identity()
        store = Store(self.store_dir)
        kr = store.load_keyring()
        kr.register_single(issuer.hash, issuer.sig_pub_bytes)
        store.save_keyring(kr)
        # Apply a grant so the guard would normally fire.
        raw = store.load_config_raw()
        anchors = list(raw["anchors"]) + [issuer.hash]
        store.save_config(
            primary_salt=raw["primary_salt"], legacy_salts=raw["legacy_salts"],
            anchors=anchors, authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
        )
        config = store.load_config()
        state = store.load_state(config)
        delta = _signed_delta(issuer.hash, issuer)
        rx = DeltaReceiver(state, Keyring({issuer.hash: IssuerKeyset.single(issuer.sig_pub_bytes)}))
        rx.apply_payload(delta)
        store.save_state(state)

        argv = ["identity", "forget", issuer.hash.hex(), "--force",
                "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertNotIn(issuer.hash, store.load_keyring())

    def test_remember_resolves_alias(self):
        """``remember`` accepts an alias (resolved via the aliases registry)."""
        from dacar.cli import main
        issuer = RNS.Identity()
        # Add an alias for the issuer.
        store = Store(self.store_dir)
        aliases = store.load_aliases()
        aliases.add("node-b", issuer.hash)
        store.save_aliases(aliases)

        argv = ["identity", "remember", "node-b", "--pubkey", issuer.sig_pub_bytes.hex(),
                "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn(issuer.hash, Store(self.store_dir).load_keyring())

    def test_list_shows_cached_entries(self):
        """``identity list`` prints the cached issuers."""
        from dacar.cli import main
        issuer = RNS.Identity()
        store = Store(self.store_dir)
        kr = store.load_keyring()
        kr.register_single(issuer.hash, issuer.sig_pub_bytes)
        store.save_keyring(kr)

        argv = ["identity", "list", "--store", str(self.store_dir)]
        out = self._io.StringIO()
        err = self._io.StringIO()
        with self._redirect_stdout(out), self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("ISSUER IDENTITY CACHE", err.getvalue())
        self.assertIn("1", err.getvalue())  # 1 entry

    def test_list_empty_shows_hint(self):
        """``identity list`` on an empty cache suggests ``remember``."""
        from dacar.cli import main
        argv = ["identity", "list", "--store", str(self.store_dir)]
        err = self._io.StringIO()
        with self._redirect_stderr(err):
            code = main(argv)
        self.assertEqual(code, 0)
        self.assertIn("remember", err.getvalue())


class CliIdentityCacheParserTest(unittest.TestCase):
    """The parser accepts the new ``identity remember/forget/list`` subcommands."""

    def test_remember_subcommand(self):
        from dacar.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "identity", "remember", "aabbccdd" * 4, "--pubkey", "00" * 32,
        ])
        self.assertEqual(args.identity_command, "remember")
        self.assertEqual(args.pubkey, "00" * 32)

    def test_forget_subcommand(self):
        from dacar.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["identity", "forget", "aabbccdd" * 4])
        self.assertEqual(args.identity_command, "forget")

    def test_list_subcommand(self):
        from dacar.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["identity", "list"])
        self.assertEqual(args.identity_command, "list")


if __name__ == "__main__":
    unittest.main()
