"""Smoketests for :func:`dacar.cli.rns.ensure_node_identity` (work doc #6).

When ``--node <hash>`` (or ``--discover``) resolves to an rfed destination
whose announce isn't in RNS's recall store yet, the rfed client can't open a
link and fails with ``rfed node identity unknown for <hash>; wait for its
announce``. ``ensure_node_identity`` proactively sends a ``path?`` request and
polls the recall store until the node's path-response announce populates it
(or a timeout elapses), so an explicit ``--node`` makes dacar try to *get*
the identity instead of just failing.

Mirrors the JavaScript ``ensureNodeIdentity`` in ``src/cli/session.js``.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import RNS

from dacar.cli.rns import (
    DEFAULT_NODE_DISCOVERY_TIMEOUT,
    ensure_node_identity,
)
from tests._rns_fixture import ensure_headless

NODE_HASH = b"\x07" * 16  # any rfed.* destination hash


class EnsureNodeIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_headless()

    def _remember(self) -> RNS.Identity:
        """Populate the recall store so NODE_HASH recalls to a real identity."""
        identity = RNS.Identity()
        RNS.Identity.remember(b"\x00" * 16, NODE_HASH, identity.get_public_key(), None)
        return identity

    def test_returns_immediately_when_identity_already_known(self):
        identity = self._remember()
        requested = []
        result = ensure_node_identity(
            NODE_HASH, on_request=lambda: requested.append(True)
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.hash, identity.hash)
        self.assertEqual(requested, [])  # no path request — already known

    def test_sends_path_request_then_returns_when_announce_arrives(self):
        # Recall returns None until request_path is called, then "the announce
        # arrives" and the next poll returns the recalled identity.
        identity = RNS.Identity()
        state = {"requested": False}

        def fake_recall(target_hash, from_identity_hash=False, _no_use=False):
            return identity if state["requested"] else None

        def fake_request_path(destination_hash, *args, **kwargs):
            state["requested"] = True  # simulate the announce arriving

        requested = []
        with patch("dacar.cli.rns.RNS.Identity.recall", side_effect=fake_recall), \
             patch("dacar.cli.rns.RNS.Transport.request_path", side_effect=fake_request_path):
            result = ensure_node_identity(
                NODE_HASH, timeout=2.0, poll_interval=0.01,
                on_request=lambda: requested.append(True),
            )
        self.assertEqual(result.hash, identity.hash)
        self.assertEqual(requested, [True])  # the path request fired once

    def test_raises_after_timeout_when_never_announced(self):
        # Recall stays None forever -> path request fires, polls until timeout,
        # then raises the same "wait for its announce" error the client raises.
        requested = []
        with patch("dacar.cli.rns.RNS.Identity.recall", return_value=None) as mock_recall, \
             patch("dacar.cli.rns.RNS.Transport.request_path") as mock_path, \
             patch("dacar.cli.rns.time.sleep"):
            with self.assertRaises(ValueError) as ctx:
                ensure_node_identity(
                    NODE_HASH, timeout=0.0, poll_interval=0.0,
                    on_request=lambda: requested.append(True),
                )
        self.assertIn("rfed node identity unknown for", str(ctx.exception))
        self.assertIn(NODE_HASH.hex(), str(ctx.exception))
        self.assertEqual(requested, [True])
        mock_path.assert_called_once_with(NODE_HASH)
        # The poll loop ran at least once (initial recall) before timing out.
        self.assertGreaterEqual(mock_recall.call_count, 1)

    def test_default_timeout_is_reasonable(self):
        # A one-shot CLI shouldn't hang forever; 15s matches the JS default.
        self.assertGreater(DEFAULT_NODE_DISCOVERY_TIMEOUT, 0)
        self.assertLessEqual(DEFAULT_NODE_DISCOVERY_TIMEOUT, 60)


if __name__ == "__main__":
    unittest.main()
