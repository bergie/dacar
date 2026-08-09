"""Smoketests for §11.1 RFed convergence (spec §11.1).

The Dacar-specific logic is the LXMF-content↔Delta seam routed through
verify-on-ingest; the rfed machinery (channel derivation, EC envelope, PoW
stamp, fanout/pull wire format) is exercised in :mod:`dacar.rfed` and upstream
and is not re-tested here. A *fake* ``RFedClient`` records publishes and
replays ``listen``/``pull``, so the adapter is tested without a live Reticulum
— mirroring ``javascript/test/transport-rfed.test.js``.

The one exception is :meth:`RfedDeltaSync.pull`, which unwraps a *real* rfed
``inner_blob`` (EC-encrypted to the derived channel) so the decrypt→LXMF-
deserialize→verify-on-ingest path is genuinely exercised end-to-end.

Requires the ``rns`` package (``dacar[transport]`` extra); no ``lxmf`` needed.
"""

from __future__ import annotations
import subprocess
import sys
import types
import unittest

import RNS

from dacar import Action, DeltaReceiver, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.naming import LXMF_DELIVERY_TITLE, RFED_TOPIC
from dacar.rfed._lxmf import LxmfMessage
from dacar.rfed.blob import wrap_channel_message
from dacar.rfed.channel import delivery_hash_for, derive_channel
from dacar.rfed.client import PullItem, PullPage, SubscribeResult
from dacar.transport.rfed_sync import RfedDeltaSync, message_content

from tests._rns_fixture import ensure_headless

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
# Dated "now" so the §9 stale-horizon intake check (wall-clock default used by
# listen/pull, which call apply_payload without a now_ms override) accepts them.
HLC = pack(physical_now_ms(), 0)
NODE = b"\x07" * 16  # any rfed.* destination hash


def _op(issuer, signer=None):
    t = Tuple.from_plaintext(
        object_id="sensor:wind", relation="calibrate", grantee=GRANTEE,
        issuer=issuer, hasher=HASHER,
    )
    base = Operation(tuple=t, action=Action.GRANT, hlc=HLC)
    return base.sign(signer) if signer is not None else base


class _FakeRFedClient:
    """A minimal RFedClient double that records publishes and replays listen/pull.

    Mirrors ``FakeRFedClient`` in ``javascript/test/transport-rfed.test.js``.
    """

    def __init__(self):
        self.published = []  # list of (node_hash, channel_name, message)
        self.listener = None
        self.deferred = []  # list of PullItem
        self.delivery_hash = b"\x09" * 16
        self.subscribed = None

    def subscribe(self, node_hash, channel_name, **_kwargs):
        self.subscribed = (node_hash, channel_name)
        return SubscribeResult(ok=True, stamp_cost=None)

    def unsubscribe(self, node_hash, channel_name, **_kwargs):
        return SubscribeResult(ok=True)

    def publish(self, node_hash, channel_name, lxm_message):
        self.published.append((node_hash, channel_name, lxm_message))

    def listen(self, on_message):
        self.listener = on_message
        return self.delivery_hash

    def pull(self, node_hash, channel_name, **_kwargs):
        items = self.deferred[:]
        self.deferred = []
        return PullPage(items=items, more_pending=False)


class RfedDeltaSyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def setUp(self):
        self.identity = RNS.Identity()
        self.issuer = self.identity.hash

    def _receiver(self):
        """A DeltaReceiver keyed for the test sender identity."""
        state = StateVector()
        keyring = Keyring().register_single(self.issuer, self.identity.sig_pub_bytes)
        return state, DeltaReceiver(state, keyring)

    # -- §11.1 publish: wrap Delta as LXMF content under the dacar title -----

    def test_publish_wraps_delta_as_lxmf_content_under_dacar_title(self):
        client = _FakeRFedClient()
        sync = RfedDeltaSync(client=client)
        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()

        message = sync.publish(delta, NODE)
        self.assertEqual(len(client.published), 1)
        node_hash, channel_name, _msg = client.published[0]
        self.assertEqual(node_hash, NODE)
        self.assertEqual(channel_name, RFED_TOPIC)
        self.assertEqual(message_content(message), delta)
        # The dacar title discriminator is set (no title filter on rfed, but
        # the wire carries it for cross-transport consistency, §11.2).
        self.assertEqual(message.title, LXMF_DELIVERY_TITLE.encode("utf-8"))
        # The rfed codec overwrites these on wrap; placeholders are fine
        # pre-publish.
        self.assertEqual(message.destination_hash, b"\x00" * 16)

    def test_make_message_rejects_non_bytes(self):
        sync = RfedDeltaSync(client=_FakeRFedClient())
        with self.assertRaises(TypeError):
            sync.make_message("not bytes")  # type: ignore[arg-type]

    # -- §11.1 subscribe: caches the channel and topic ----------------------

    def test_subscribe_caches_channel_and_topic(self):
        client = _FakeRFedClient()
        sync = RfedDeltaSync(client=client, topic="dacar.policy.v1")
        sync.subscribe(NODE)
        self.assertEqual(client.subscribed, (NODE, "dacar.policy.v1"))

    def test_default_topic_is_spec_default(self):
        sync = RfedDeltaSync(client=_FakeRFedClient())
        self.assertEqual(sync.topic, RFED_TOPIC)
        self.assertEqual(RfedDeltaSync.DEFAULT_TOPIC, RFED_TOPIC)

    def test_requires_a_client(self):
        with self.assertRaises(TypeError):
            RfedDeltaSync(client=None)  # type: ignore[arg-type]

    # -- §11.1 listen: routes a received Delta through verify-on-ingest ------

    def test_listen_routes_received_delta_through_verify_on_ingest(self):
        state, rx = self._receiver()
        client = _FakeRFedClient()
        sync = RfedDeltaSync(receiver=rx, client=client)
        delivery_hash = sync.listen()
        self.assertEqual(delivery_hash, client.delivery_hash)

        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()
        lxm = LxmfMessage(content=delta, title=LXMF_DELIVERY_TITLE)
        wire = lxm.serialize(self.identity)
        recovered = LxmfMessage.deserialize(wire, self.identity.get_public_key())
        client.listener(types.SimpleNamespace(message=recovered))

        self.assertEqual(len(state), 1)

    def test_listen_swallows_malformed_delta(self):
        """A transport callback must never crash on arbitrary content."""
        state, rx = self._receiver()
        client = _FakeRFedClient()
        sync = RfedDeltaSync(receiver=rx, client=client)
        sync.listen()

        lxm = LxmfMessage(content=b"not a dacar delta", title=LXMF_DELIVERY_TITLE)
        wire = lxm.serialize(self.identity)
        recovered = LxmfMessage.deserialize(wire, self.identity.get_public_key())
        client.listener(types.SimpleNamespace(message=recovered))

        self.assertEqual(len(state), 0)

    # -- §11.1 pull: unwraps deferred blobs and applies their Deltas ----------

    def test_pull_unwraps_deferred_blobs_and_applies_deltas(self):
        """Exercises the real EC-decrypt unwrap: a true rfed inner_blob."""
        state, rx = self._receiver()
        client = _FakeRFedClient()
        sync = RfedDeltaSync(receiver=rx, client=client)

        channel_identity, channel_hash = derive_channel(RFED_TOPIC)
        sender_delivery_hash = delivery_hash_for(self.identity)
        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()
        lxm = LxmfMessage(content=delta, title=LXMF_DELIVERY_TITLE)
        wrapped = wrap_channel_message(
            channel_identity=channel_identity,
            sender_identity=self.identity,
            sender_lxm_delivery_hash=sender_delivery_hash,
            lxm_message=lxm,
        )
        client.deferred.append(
            PullItem(channel_hash=wrapped.channel_hash, blob=wrapped.inner_blob)
        )

        applied = sync.pull(NODE)
        self.assertEqual(applied, 1)
        self.assertEqual(len(state), 1)

    def test_pull_drops_foreign_blob_without_crashing(self):
        """An undecryptable/foreign blob is dropped, not fatal."""
        state, rx = self._receiver()
        client = _FakeRFedClient()
        sync = RfedDeltaSync(receiver=rx, client=client)
        client.deferred.append(
            PullItem(channel_hash=b"\x00" * 16, blob=b"not an rfed blob")
        )
        self.assertEqual(sync.pull(NODE), 0)
        self.assertEqual(len(state), 0)

    # -- receiver required --------------------------------------------------

    def test_listen_and_pull_throw_without_receiver(self):
        sync = RfedDeltaSync(client=_FakeRFedClient())
        with self.assertRaises(RuntimeError):
            sync.listen()
        with self.assertRaises(RuntimeError):
            sync.pull(NODE)


class CorePurityTest(unittest.TestCase):
    def test_core_import_does_not_pull_transport_or_rfed_or_rns(self):
        """`import dacar` must stay free of the transport/rns/rfed stack."""
        out = subprocess.check_output(
            [sys.executable, "-c",
             "import sys, dacar; "
             "leaked=[m for m in ('dacar.transport','dacar.rfed','RNS','LXMF') "
             "if m in sys.modules]; "
             "assert not leaked, leaked; "
             "print('PURE')"],
            text=True,
        )
        self.assertIn("PURE", out)


if __name__ == "__main__":
    unittest.main()
