"""Smoketests for :class:`dacar.rfed.client.RFedClient` request-response decoding.

RNS's ``Link.request`` machinery already msgpack-unpacks the response and stores
the resulting Python object on ``RequestReceipt.response`` (see
``RNS.Link.response_received`` / ``handle_response``). The rfed client must
therefore decode that object *directly* — it must **not** call
``msgpack.unpackb`` on it again, which would raise ``TypeError`` on a list.

These tests fake the RNS ``Link``/``Identity``/``Destination`` surface (mirroring
``_FakeLink`` in ``test_transport_rns.py``) so the real
:class:`RFedClient` ``subscribe``/``unsubscribe``/``pull`` decode paths are
exercised end-to-end without a live Reticulum. They are regression coverage for
the bug where ``dacar sync`` crashed with::

    TypeError: a bytes-like object is required, not 'list'

Requires the ``rns`` package (``dacar[transport]`` extra); no ``lxmf`` needed.
"""

from __future__ import annotations

import threading
import time
import types
import unittest
from unittest.mock import patch

import RNS

from dacar.rfed.client import RFedClient, SubscribeResult
from dacar.rfed.constants import (
    CHANNEL_SUBSCRIBE_NAME,
    PULL_PATH,
    SUBSCRIBE_PATH,
    UNSUBSCRIBE_PATH,
)

NODE = b"\x07" * 16  # any rfed.* destination hash
CHANNEL = "dacar.policy.v1"

#: A valid rfed ``[ok, stamp_cost]`` subscribe response the node returns on
#: success — what a real node sends once the signed payload verifies.
_OK_RESPONSE = [True, 2]


class _FakeReceipt:
    """Mimics ``RNS.RequestReceipt``'s ``.response`` surface."""

    def __init__(self, response):
        self.response = response


class _FakeLink:
    """Mimics the ``RNS.Link`` surface used by :class:`RFedClient`.

    ``request`` fires the response callback synchronously with a receipt whose
    ``.response`` holds an *already-unpacked* Python object — exactly what real
    RNS delivers (RNS msgpack-unpacks the wire response before storing it).
    """

    def __init__(self, response, *, status=None, delay=0.0):
        self.status = status if status is not None else RNS.Link.ACTIVE
        self._response = response
        self._delay = delay
        self.last_path = None
        self.last_data = None
        self.identified_with = None

    def identify(self, identity):
        self.identified_with = identity

    def request(self, path, data, response_callback=None, failed_callback=None, timeout=None):
        self.last_path = path
        self.last_data = data

        def _emit():
            if self._delay:
                time.sleep(self._delay)
            if response_callback is not None:
                response_callback(_FakeReceipt(self._response))

        # Fire on a thread so the blocking _request waiter actually waits.
        threading.Thread(target=_emit, daemon=True).start()
        return object()  # truthy: the request "was sent"


class RFedClientResponseTest(unittest.TestCase):
    """``RFedClient`` must decode already-unpacked RNS responses directly."""

    def setUp(self):
        self.client = RFedClient(RNS.Identity(), rns=None)
        # Bypass the RNS-transport-coupled helpers: the decode path under test
        # only needs a real Identity for signing and a faked Link.
        self.client._node_identity = lambda node_hash: RNS.Identity()
        self.client._out_destination = lambda name, node_identity: object()
        self.node_identity = RNS.Identity()

    def _patch_link(self, response, *, delay=0.0):
        link = _FakeLink(response, delay=delay)
        self.client._establish_link = lambda dest, **_: link
        return link

    # -- subscribe ---------------------------------------------------------

    def test_subscribe_decodes_list_response_without_unpacking(self):
        """Regression: ``[True, 2]`` (already unpacked) must not raise TypeError."""
        link = self._patch_link([True, 2])
        result = self.client.subscribe(NODE, CHANNEL)
        self.assertIsInstance(result, SubscribeResult)
        self.assertTrue(result.ok)
        self.assertEqual(result.stamp_cost, 2)
        # The advertised PoW cost is cached for the publish path.
        channel_hash = self.client._channel(CHANNEL)["channel_hash"]
        self.assertEqual(self.client.stamp_costs[channel_hash.hex()], 2)
        self.assertEqual(link.last_path, SUBSCRIBE_PATH)

    def test_subscribe_zero_stamp_cost_means_disabled(self):
        self._patch_link([True, 0])
        result = self.client.subscribe(NODE, CHANNEL)
        self.assertTrue(result.ok)
        self.assertIsNone(result.stamp_cost)  # 0 / nil both mean "no stamping"

    def test_subscribe_legacy_bare_boolean_true(self):
        self._patch_link(True)
        result = self.client.subscribe(NODE, CHANNEL)
        self.assertTrue(result.ok)
        self.assertIsNone(result.stamp_cost)

    def test_subscribe_failure_response(self):
        self._patch_link([False, None])
        result = self.client.subscribe(NODE, CHANNEL)
        self.assertFalse(result.ok)

    def test_subscribe_no_response_is_failure(self):
        # ``_request`` returns None on timeout/partition -> ok=False, no raise.
        self.client._establish_link = lambda dest, **_: _FakeLink(None)
        result = self.client.subscribe(NODE, CHANNEL)
        self.assertFalse(result.ok)

    # -- unsubscribe -------------------------------------------------------

    def test_unsubscribe_decodes_list_response(self):
        link = self._patch_link([True, None])
        result = self.client.unsubscribe(NODE, CHANNEL)
        self.assertTrue(result.ok)
        self.assertEqual(link.last_path, UNSUBSCRIBE_PATH)

    # -- pull --------------------------------------------------------------

    def test_pull_decodes_already_unpacked_page(self):
        ch_hash = self.client._channel(CHANNEL)["channel_hash"]
        blob_a, blob_b = b"blob-a", b"blob-b"
        # RNS hands back the decoded ``[[[channel_hash, blob], ...], more_pending]``.
        self._patch_link([[[ch_hash, blob_a], [ch_hash, blob_b]], True])
        page = self.client.pull(NODE, CHANNEL)
        self.assertTrue(page.more_pending)
        self.assertEqual(len(page.items), 2)
        self.assertEqual(page.items[0].channel_hash, ch_hash)
        self.assertEqual(page.items[0].blob, blob_a)
        self.assertEqual(page.items[1].channel_hash, ch_hash)
        self.assertEqual(page.items[1].blob, blob_b)

    def test_pull_empty_or_none_returns_empty_page(self):
        self._patch_link(None)
        page = self.client.pull(NODE, CHANNEL)
        self.assertEqual(page.items, [])
        self.assertFalse(page.more_pending)

    def test_pull_malformed_response_returns_empty_page(self):
        self._patch_link(["not-a-page"])
        page = self.client.pull(NODE, CHANNEL)
        self.assertEqual(page.items, [])
        self.assertFalse(page.more_pending)

    # -- subscribe payload shape (regression: no double msgpack encoding) -----

    def test_signed_channel_payload_returns_list_not_packed_bytes(self):
        """RNS ``Link.request`` msgpack-encodes its ``data`` arg as part of the
        outer ``[time, path_hash, data]`` envelope, so the payload must be the
        **list** ``[channel_hash, pubkey, sig]`` — not pre-packed bytes. A
        pre-packed ``bytes`` payload would arrive at the node as an opaque
        ``bin`` blob, fail ``Array.isArray(data)`` in ``_verifySignedPayload``,
        and silently yield ``[false, null]`` (no subscription created).
        """
        from dacar.rfed.client import _signed_channel_payload

        channel_hash = self.client._channel(CHANNEL)["channel_hash"]
        payload = _signed_channel_payload(self.client.identity, channel_hash)
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 3)
        ch, pubkey, sig = payload
        self.assertEqual(bytes(ch), bytes(channel_hash))
        self.assertEqual(len(pubkey), 64)  # X25519 ‖ Ed25519
        self.assertEqual(len(sig), 64)    # Ed25519 signature

    def test_subscribe_passes_list_payload_to_link_request(self):
        """The data handed to ``link.request`` is the list, not packed bytes.

        Regression for the bug where ``dacar sync`` did not increase the node's
        subscription count: the node received a ``bytes`` blob instead of an
        array and rejected the (unsigned-looking) request with ``[false, null]``.
        """
        link = self._patch_link(_OK_RESPONSE)
        self.client.subscribe(NODE, CHANNEL)
        self.assertIsInstance(link.last_data, list)
        self.assertEqual(len(link.last_data), 3)
        # The signed value is the channel hash (what the node verifies).
        self.assertEqual(len(link.last_data[0]), 16)


class EnsurePathTest(unittest.TestCase):
    """``RFedClient._ensure_path`` requests a path before linking/sending.

    Regression for the bug where ``dacar sync --node <hash>`` timed out with
    ``rfed link to <derived-hash> not established``: RNS's ``RNS.Link`` does not
    auto-request a path, so a ``LINKREQUEST`` to a destination with no known
    route is silently dropped. ``_ensure_path`` mirrors rngit's
    ``RNS.Transport.await_path`` and the JS reference's
    ``_requestAndAwaitPath`` — send a ``path?`` for the *specific* derived
    channel destination and wait for the announce before linking.
    """

    def setUp(self):
        self.client = RFedClient(RNS.Identity(), rns=None)
        self.dest_hash = NODE

    @patch("dacar.rfed.client.RNS.Transport.await_path", return_value=True)
    def test_await_path_called_with_destination_hash(self, mock_await):
        self.client._ensure_path(self.dest_hash, timeout=1.0)
        mock_await.assert_called_once_with(self.dest_hash, timeout=1.0)

    @patch("dacar.rfed.client.RNS.Transport.await_path", return_value=True)
    def test_no_raise_when_path_already_known(self, mock_await):
        # A path already in the table -> await_path returns True immediately.
        self.client._ensure_path(self.dest_hash)

    @patch("dacar.rfed.client.RNS.Transport.await_path", return_value=False)
    def test_raises_timeout_when_no_path_resolved(self, mock_await):
        with self.assertRaises(TimeoutError) as ctx:
            self.client._ensure_path(self.dest_hash, timeout=0.1)
        self.assertIn("no path", str(ctx.exception))
        self.assertIn(self.dest_hash.hex(), str(ctx.exception))

    @patch("dacar.rfed.client.RNS.Transport.await_path", return_value=True)
    def test_establish_link_ensures_path_before_linking(self, mock_await):
        """``_establish_link`` requests the path *before* opening ``RNS.Link``."""
        dest = types.SimpleNamespace(hash=self.dest_hash)
        link_started = []

        def fake_link(destination, established_callback=None, **_kwargs):
            link_started.append(destination)
            link = "LINK"
            if established_callback is not None:
                # Fire synchronously so the blocking waiter resolves promptly.
                established_callback(link)
            return link

        with patch("dacar.rfed.client.RNS.Link", side_effect=fake_link):
            result = self.client._establish_link(dest, timeout=1.0)
        self.assertEqual(result, "LINK")
        # The path request preceded the link attempt (and used the dest hash).
        mock_await.assert_called_once_with(self.dest_hash, timeout=15.0)
        self.assertEqual(link_started, [dest])

    @patch("dacar.rfed.client.RNS.Transport.await_path", return_value=True)
    def test_publish_ensures_path_before_send(self, mock_await):
        """Fire-and-forget publish must also ensure a path, or the packet is dropped."""
        from dacar.naming import LXMF_DELIVERY_TITLE
        from dacar.rfed._lxmf import LxmfMessage

        client = RFedClient(RNS.Identity(), rns=None)
        client._node_identity = lambda node_hash: RNS.Identity()
        sent = []

        class _FakePacket:
            def __init__(self, destination, payload):
                self.payload = payload

            def send(self):
                sent.append(self.payload)

        class _FakeLink:
            def identify(self, identity):
                pass

        def fake_link(destination, established_callback=None, **_kwargs):
            # Fire synchronously so the blocking waiter resolves promptly.
            if established_callback is not None:
                established_callback(_FakeLink())
            return _FakeLink()

        wrapped_stub = types.SimpleNamespace(rfed_payload=b"payload")
        lxm = LxmfMessage(content=b"delta", title=LXMF_DELIVERY_TITLE)
        with patch("dacar.rfed.client.wrap_channel_message", return_value=wrapped_stub), \
             patch("dacar.rfed.client.RNS.Packet", side_effect=_FakePacket), \
             patch("dacar.rfed.client.RNS.Link", side_effect=fake_link):
            client.publish(NODE, CHANNEL, lxm)
        # The path to the rfed.channel.publish destination was ensured (via _establish_link),
        # and the packet was sent afterwards.
        self.assertTrue(mock_await.called, "await_path should be called for the publish destination")
        self.assertEqual(mock_await.call_count, 1)
        self.assertEqual(mock_await.call_args[1]['timeout'], 15.0)
        self.assertEqual(sent, [b"payload"])


if __name__ == "__main__":
    unittest.main()
