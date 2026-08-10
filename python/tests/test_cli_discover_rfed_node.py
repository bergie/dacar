"""Smoketests for :func:`dacar.cli.rns.discover_rfed_node` (work doc #6/#7).

``dacar sync --discover`` listens for an ``rfed.node`` announce on the live
transport and returns that announce's destination hash — the rfed node's
canonical identifier. The rfed daemon (an external process; dacar ships only
the client) announces ``rfed.node`` + the ``rfed.channel.*`` services under one
identity; a ``dacar.node`` announce is a *different* thing (a dacar peer's
signing identity, §11.2.4) and must NOT satisfy rfed-node discovery.

These tests pin that contract against a fake transport that dispatches real
``RNS.Destination``-derived hashes, so the filter arithmetic is exercised
exactly as a live transport would. Mirrors the JS ``cli-discovery.test.js``.
"""

from __future__ import annotations

import threading
import time
import types
import unittest

import RNS

from dacar.cli.rns import discover_rfed_node
from dacar.cli.commands import CliError
from tests._rns_fixture import ensure_headless


class _FakeTransport:
    """Minimal transport: collects announce handlers and can fire them."""

    def __init__(self) -> None:
        self._handlers: list = []
        self._lock = threading.Lock()

    def add_announce_handler(self, fn) -> None:
        with self._lock:
            self._handlers.append(fn)

    def remove_announce_handler(self, fn) -> None:
        with self._lock:
            if fn in self._handlers:
                self._handlers.remove(fn)

    @property
    def handlers(self) -> list:
        with self._lock:
            return list(self._handlers)

    def fire(self, destination_hash: bytes, identity: RNS.Identity, app_data=None) -> None:
        # RNS dispatches announce callbacks on a daemon thread; mirror that so
        # the Event.wait inside discover_rfed_node can be woken from here.
        with self._lock:
            handlers = list(self._handlers)
        for h in handlers:
            threading.Thread(
                target=h,
                args=(destination_hash, identity),
                kwargs={"app_data": app_data},
                daemon=True,
            ).start()


def _fake_rns() -> types.SimpleNamespace:
    return types.SimpleNamespace(transport=_FakeTransport())


class DiscoverRfedNodeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_headless()

    @staticmethod
    def _rfed_node_hash(identity: RNS.Identity) -> bytes:
        """A real rfed.node destination hash under ``identity``."""
        return RNS.Destination.hash(identity, "rfed", "node")

    def _run_and_fire(self, rns, fires):
        """Start discover_rfed_node on a thread, fire announces, return result."""

        box: dict = {}

        def runner() -> None:
            try:
                box["hash"] = discover_rfed_node(rns, timeout=2000)
            except BaseException as exc:  # noqa: BLE001 — re-raised on main thread
                box["error"] = exc

        th = threading.Thread(target=runner, daemon=True)
        th.start()
        time.sleep(0.05)  # let the handler register
        for delay, dest_hash, identity in fires:
            if delay:
                time.sleep(delay)
            rns.transport.fire(dest_hash, identity)
        th.join(timeout=3.0)
        return box, th

    def test_returns_announce_destination_hash_directly(self) -> None:
        rns = _fake_rns()
        identity = RNS.Identity()
        dest_hash = self._rfed_node_hash(identity)

        box, th = self._run_and_fire(rns, [(0, dest_hash, identity)])
        self.assertFalse(th.is_alive(), "discover_rfed_node did not return")
        self.assertNotIn("error", box)
        self.assertEqual(bytes(box["hash"]), bytes(dest_hash))

    def test_ignores_rfed_channel_and_dacar_node_announces(self) -> None:
        rns = _fake_rns()
        node_identity = RNS.Identity()
        # rfed.channel.publish shares the identity but is not rfed.node…
        channel_hash = RNS.Destination.hash(node_identity, "rfed", "channel", "publish")
        # …and a dacar.node announce under a different identity entirely.
        dacar_identity = RNS.Identity()
        dacar_hash = RNS.Destination.hash(dacar_identity, "dacar", "node")
        rfed_node_hash = self._rfed_node_hash(node_identity)

        fires = [
            (0, channel_hash, node_identity),
            (0.05, dacar_hash, dacar_identity),
            (0.05, rfed_node_hash, node_identity),
        ]
        box, th = self._run_and_fire(rns, fires)
        self.assertFalse(th.is_alive(), "discover_rfed_node did not return")
        self.assertNotIn("error", box)
        self.assertEqual(bytes(box["hash"]), bytes(rfed_node_hash))

    def test_raises_on_timeout_when_no_rfed_node_announces(self) -> None:
        rns = _fake_rns()
        with self.assertRaises(CliError) as cm:
            discover_rfed_node(rns, timeout=300)
        msg = str(cm.exception)
        self.assertIn("no rfed.node announce received within 300ms", msg)
        self.assertIn("rfed node is reachable and announcing", msg)

    def test_removes_handler_after_returning(self) -> None:
        rns = _fake_rns()
        identity = RNS.Identity()
        dest_hash = self._rfed_node_hash(identity)

        box, th = self._run_and_fire(rns, [(0, dest_hash, identity)])
        self.assertFalse(th.is_alive())
        self.assertEqual(rns.transport.handlers, [])  # no leaked handler

    def test_raises_when_transport_missing(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            discover_rfed_node(object(), timeout=50)
        self.assertIn("RNS transport not available", str(cm.exception))

    def test_raises_when_transport_lacks_announce_handlers(self) -> None:
        rns = types.SimpleNamespace(transport=object())  # no add_announce_handler
        with self.assertRaises(RuntimeError) as cm:
            discover_rfed_node(rns, timeout=50)
        self.assertIn("does not support announce handlers", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
