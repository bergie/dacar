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
import unittest

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


if __name__ == "__main__":
    unittest.main()
