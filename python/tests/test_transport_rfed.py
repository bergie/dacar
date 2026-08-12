"""Smoketests for §11.1 RFed convergence (spec §11.1).

The Dacar-specific logic is the compact inner format (raw §5.3 Delta in the
RTID prelude, no LXMF envelope) routed through verify-on-ingest; the rfed
machinery (channel derivation, EC envelope, PoW stamp, fanout/pull wire
format) is exercised in :mod:`dacar.rfed` and upstream and is not re-tested
here. A *fake* ``RFedClient`` records publishes and replays
``listen_raw``/``pull``, so the adapter is tested without a live Reticulum —
mirroring ``javascript/test/transport-rfed.test.js``.

The :meth:`RfedDeltaSync.pull` path unwraps a *real* rfed ``inner_blob``
(EC-encrypted to the derived channel) so the decrypt→recover-Delta→verify-on-
ingest path is genuinely exercised end-to-end.

Requires the ``rns`` package (``dacar[transport]`` extra); no ``lxmf`` needed.
"""

from __future__ import annotations
import subprocess
import sys
import unittest

import RNS

from dacar import Action, DeltaReceiver, Keyring, Operation, StateVector, Tuple
from dacar.hlc import pack, physical_now_ms
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.naming import RFED_TOPIC
from dacar.rfed.blob import unwrap_dacar_delta, wrap_dacar_delta
from dacar.rfed.channel import derive_channel
from dacar.rfed.constants import HASH_LENGTH
from dacar.rfed.client import PullItem, PullPage, SubscribeResult
from dacar.transport.rfed_sync import RfedDeltaSync

from tests._rns_fixture import ensure_headless

HASHER = NamespaceHasher(bytes(range(SALT_SIZE)))
GRANTEE = bytes(range(HASH_SIZE, HASH_SIZE * 2))
# Dated "now" so the §9 stale-horizon intake check (wall-clock default used by
# listen/pull, which call apply_payload without a now_ms override) accepts them.
HLC = pack(physical_now_ms(), 0)
NODE = b"\x07" * 16  # any rfed.* destination hash
#: Default RNS path MTU (multi-hop, with stamp) the compact format must fit.
RNS_MTU = 500


def _op(issuer, signer=None):
    t = Tuple.from_plaintext(
        object_id="sensor:wind", relation="calibrate", grantee=GRANTEE,
        issuer=issuer, hasher=HASHER,
    )
    base = Operation(tuple=t, action=Action.GRANT, hlc=HLC)
    return base.sign(signer) if signer is not None else base


class _FakeRFedClient:
    """A minimal RFedClient double that records publishes and replays listen/pull.

    Mirrors the surface :class:`RfedDeltaSync` relies on (the same surface the
    real :class:`dacar.rfed.client.RFedClient` exposes for application-specific
    inner formats): ``channel``/``stamp_cost``/``send_publish``/``listen_raw``.
    """

    def __init__(self, identity):
        self.identity = identity
        self.sent = []  # list of (node_hash, rfed_payload)
        self.fanout_listener = None
        self.deferred = []  # list of PullItem
        self.delivery_hash = b"\x09" * 16
        self.subscribed = None
        self._channel_cache = {}

    def channel(self, name):
        if name not in self._channel_cache:
            ident, chash = derive_channel(name)
            self._channel_cache[name] = {
                "identity": ident, "channel_hash": chash, "delivery_hash": b"\x00" * 16,
            }
        return self._channel_cache[name]

    def stamp_cost(self, name):
        return None

    def subscribe(self, node_hash, channel_name, **_kwargs):
        self.subscribed = (node_hash, channel_name)
        return SubscribeResult(ok=True, stamp_cost=None)

    def unsubscribe(self, node_hash, channel_name, **_kwargs):
        return SubscribeResult(ok=True)

    def send_publish(self, node_hash, rfed_payload):
        self.sent.append((node_hash, bytes(rfed_payload)))
        return True

    def listen_raw(self, on_fanout):
        self.fanout_listener = on_fanout
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

    # -- §11.1 publish: wrap Delta in the compact inner format ---------------

    def test_publish_wraps_delta_in_compact_inner_format(self):
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(client=client)
        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()

        rfed_payload = sync.make_payload(delta)
        self.assertTrue(sync.publish(delta, NODE))
        self.assertEqual(len(client.sent), 1)
        node_hash, sent = client.sent[0]
        self.assertEqual(node_hash, NODE)
        # The published rfed_payload round-trips to the same Delta via the
        # compact inner format unwrapper (real EC-decrypt).
        channel = client.channel(RFED_TOPIC)
        recovered = unwrap_dacar_delta(
            inner_blob=rfed_payload[HASH_LENGTH:], channel_identity=channel["identity"]
        )
        self.assertEqual(recovered.delta, delta)
        # The recovered sender identity is the publisher's.
        self.assertEqual(recovered.sender_pub, self.identity.get_public_key())

    def test_published_payload_fits_under_rns_mtu(self):
        """A typical 170-byte Delta must fit the 500-byte MTU (work doc #10)."""
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(client=client)
        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()
        rfed_payload = sync.make_payload(delta)
        self.assertTrue(sync.publish(delta, NODE))
        self.assertLessEqual(
            len(rfed_payload), RNS_MTU,
            f"rfed_payload is {len(rfed_payload)} bytes (MTU {RNS_MTU}); "
            "Dacar's compact inner format must fit a typical Delta under MTU",
        )

    def test_make_payload_rejects_non_bytes(self):
        sync = RfedDeltaSync(client=_FakeRFedClient(self.identity))
        with self.assertRaises(TypeError):
            sync.make_payload("not bytes")  # type: ignore[arg-type]

    # -- §11.1 subscribe: caches the channel and topic ----------------------

    def test_subscribe_caches_channel_and_topic(self):
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(client=client, topic="dacar.policy.v1")
        sync.subscribe(NODE)
        self.assertEqual(client.subscribed, (NODE, "dacar.policy.v1"))

    def test_default_topic_is_spec_default(self):
        sync = RfedDeltaSync(client=_FakeRFedClient(self.identity))
        self.assertEqual(sync.topic, RFED_TOPIC)
        self.assertEqual(RfedDeltaSync.DEFAULT_TOPIC, RFED_TOPIC)

    def test_requires_a_client(self):
        with self.assertRaises(TypeError):
            RfedDeltaSync(client=None)  # type: ignore[arg-type]

    # -- §11.1 listen: routes a received Delta through verify-on-ingest ------

    def test_listen_routes_received_delta_through_verify_on_ingest(self):
        state, rx = self._receiver()
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(receiver=rx, client=client)
        delivery_hash = sync.listen()
        self.assertEqual(delivery_hash, client.delivery_hash)

        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()
        channel = client.channel(RFED_TOPIC)
        wrapped = wrap_dacar_delta(
            channel_identity=channel["identity"],
            sender_identity=self.identity,
            delta=delta,
        )
        client.fanout_listener(RFED_TOPIC, channel["identity"], wrapped.inner_blob)

        self.assertEqual(len(state), 1)

    def test_listen_swallows_malformed_blob(self):
        """A transport callback must never crash on arbitrary content."""
        state, rx = self._receiver()
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(receiver=rx, client=client)
        sync.listen()

        channel = client.channel(RFED_TOPIC)
        client.fanout_listener(RFED_TOPIC, channel["identity"], b"not an rfed blob")

        self.assertEqual(len(state), 0)

    def test_listen_drops_forged_delta_without_mutating_state(self):
        """A Delta whose signature fails verify-on-ingest is dropped, not applied.

        The compact inner format defers authenticity to the Delta's own Ed25519
        signature (§5.3 field [7]); a byte-flipped Delta decrypts fine but is
        rejected by :meth:`DeltaReceiver.apply_payload`.
        """
        state, rx = self._receiver()
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(receiver=rx, client=client)
        sync.listen()

        delta = bytearray(_op(self.issuer, signer=self.identity.sig_prv).to_payload())
        delta[-1] ^= 0xFF  # flip a bit in the signature
        channel = client.channel(RFED_TOPIC)
        wrapped = wrap_dacar_delta(
            channel_identity=channel["identity"],
            sender_identity=self.identity,
            delta=bytes(delta),
        )
        client.fanout_listener(RFED_TOPIC, channel["identity"], wrapped.inner_blob)

        self.assertEqual(len(state), 0)

    # -- §11.1 pull: unwraps deferred blobs and applies their Deltas ----------

    def test_pull_unwraps_deferred_blobs_and_applies_deltas(self):
        """Exercises the real EC-decrypt unwrap: a true rfed inner_blob."""
        state, rx = self._receiver()
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(receiver=rx, client=client)

        channel_identity, channel_hash = derive_channel(RFED_TOPIC)
        delta = _op(self.issuer, signer=self.identity.sig_prv).to_payload()
        wrapped = wrap_dacar_delta(
            channel_identity=channel_identity,
            sender_identity=self.identity,
            delta=delta,
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
        client = _FakeRFedClient(self.identity)
        sync = RfedDeltaSync(receiver=rx, client=client)
        client.deferred.append(
            PullItem(channel_hash=b"\x00" * 16, blob=b"not an rfed blob")
        )
        self.assertEqual(sync.pull(NODE), 0)
        self.assertEqual(len(state), 0)

    # -- receiver required --------------------------------------------------

    def test_listen_and_pull_throw_without_receiver(self):
        sync = RfedDeltaSync(client=_FakeRFedClient(self.identity))
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
