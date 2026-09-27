"""Smoketests for the direct-link Delta push transport (§11, doc #16 Phase 4a).

Covers the new RNS glue around the already-tested ``DeltaReceiver`` boundary:

  * ``pack_ack`` / ``unpack_ack`` — the ack codec (a MessagePack map
    ``{"applied": <n>}``), byte-pinned so the C++/JS ports produce and parse
    identical acks.
  * ``handle_push`` — the transport-free inbound seam: single §5.3 payload,
    §11.1 batch, garbage, duplicates, unknown issuer (verify-on-ingest).
  * ``delta_request_handler`` — the RNS ``response_generator`` wrapper.
  * ``RnsSyncServer`` — the ``dacar.sync.v1`` destination wiring.
  * ``push_deltas`` — the client loop over a faked Link (ack → accepted,
    ``applied: 0`` → refused, lost request → retry-safe failure).

RNS runs headless (no interfaces, transport disabled — see ``_rns_fixture``);
no live network, deterministic. A purity guard confirms ``import dacar`` (the
core) never pulls in the transport package.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import unittest
from unittest.mock import patch

# Silence RNS's own logging so failures read cleanly.
logging.getLogger("RNS").setLevel(logging.CRITICAL)

import RNS  # noqa: E402

from dacar import Action, Clock, Operation, Tuple, serialization  # noqa: E402
from dacar.crdt import StateVector  # noqa: E402
from dacar.delta import DeltaReceiver  # noqa: E402
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE  # noqa: E402
from dacar.verifier import Keyring  # noqa: E402
from dacar.transport import rns_sync  # noqa: E402
from dacar.transport.rns_sync import (  # noqa: E402
    delta_request_handler,
    handle_push,
    pack_ack,
    unpack_ack,
)

from tests._rns_fixture import ensure_headless  # noqa: E402

SALT = bytes(range(SALT_SIZE))
HASHER = NamespaceHasher(SALT)
GRANTEE = bytes(range(HASH_SIZE))
OBJECT = "buzzer"
RELATION = "sound"


def _issuer_and_keyring() -> tuple:
    """A fresh headless RNS identity + a keyring resolving it."""
    ensure_headless()
    issuer = RNS.Identity(create_keys=True)
    keyring = Keyring().register_single(issuer.hash, issuer.sig_pub_bytes)
    return issuer, keyring


def _signed_payload(issuer: RNS.Identity, *, hlc: int | None = None,
                    relation: str = RELATION) -> bytes:
    tup = Tuple.from_plaintext(
        object_id=OBJECT, relation=relation,
        grantee=GRANTEE, issuer=issuer.hash, hasher=HASHER,
    )
    op = Operation(
        tuple=tup, action=Action.GRANT,
        hlc=hlc if hlc is not None else Clock().now(),
    ).sign(issuer.sig_prv)
    return op.to_payload()


class _SyncTestCase(unittest.TestCase):
    """One fresh receiver (state + keyring resolver) per test."""

    def setUp(self) -> None:
        self.issuer, self.keyring = _issuer_and_keyring()
        self.state = StateVector()
        self.receiver = DeltaReceiver(self.state, self.keyring)


class TestAckCodec(unittest.TestCase):
    def test_pack_ack_exact_bytes(self) -> None:
        # fixmap(1) | fixstr"applied" | 1 — pin the wire bytes so the C++/JS
        # ports ack identically.
        self.assertEqual(pack_ack(1), b"\x81\xa7applied\x01")

    def test_roundtrip(self) -> None:
        for n in (0, 1, 7, 200):
            self.assertEqual(unpack_ack(pack_ack(n)), n)

    def test_unpack_ack_failures(self) -> None:
        self.assertIsNone(unpack_ack(None))
        self.assertIsNone(unpack_ack(b""))
        self.assertIsNone(unpack_ack(b"not-msgpack"))
        self.assertIsNone(unpack_ack(serialization.packb({"applied": -1})))
        self.assertIsNone(unpack_ack(serialization.packb({"applied": True})))
        self.assertIsNone(unpack_ack(serialization.packb({"other": 1})))
        self.assertIsNone(unpack_ack(serialization.packb([1])))


class TestHandlePush(_SyncTestCase):
    def test_single_delta_applies(self) -> None:
        payload = _signed_payload(self.issuer)
        self.assertEqual(handle_push(self.receiver, payload), 1)
        self.assertEqual(sum(1 for _ in self.state.active_tuples()), 1)

    def test_batch_applies_each(self) -> None:
        batch = DeltaReceiver.pack_payloads([
            _signed_payload(self.issuer, relation="sound"),
            _signed_payload(self.issuer, relation="light"),
        ])
        self.assertEqual(handle_push(self.receiver, batch), 2)
        self.assertEqual(sum(1 for _ in self.state.active_tuples()), 2)

    def test_duplicate_is_idempotent_success(self) -> None:
        payload = _signed_payload(self.issuer)
        self.assertEqual(handle_push(self.receiver, payload), 1)
        # CRDT merge is a no-op for an already-applied delta — but it still
        # counts as applied so the pusher's outbox drains (doc #16 4a).
        self.assertEqual(handle_push(self.receiver, payload), 1)
        self.assertEqual(sum(1 for _ in self.state.active_tuples()), 1)

    def test_garbage_returns_zero(self) -> None:
        self.assertEqual(handle_push(self.receiver, b""), 0)
        self.assertEqual(handle_push(self.receiver, b"not-msgpack"), 0)
        self.assertEqual(handle_push(self.receiver, serialization.packb([1, 2])), 0)

    def test_unknown_issuer_is_refused(self) -> None:
        stranger, _ = _issuer_and_keyring()
        payload = _signed_payload(stranger)
        self.assertEqual(handle_push(self.receiver, payload), 0)
        self.assertEqual(sum(1 for _ in self.state.active_tuples()), 0)


class TestRequestHandler(_SyncTestCase):
    def test_valid_delta_acks_applied_one(self) -> None:
        handler = delta_request_handler(self.receiver)
        ack = handler("delta", _signed_payload(self.issuer), b"", b"", None, 0.0)
        self.assertEqual(serialization.unpackb(ack), {"applied": 1})

    def test_garbage_acks_applied_zero(self) -> None:
        handler = delta_request_handler(self.receiver)
        ack = handler("delta", b"garbage", b"", b"", None, 0.0)
        self.assertEqual(serialization.unpackb(ack), {"applied": 0})

    def test_handler_never_raises(self) -> None:
        class _Boom:
            def apply_payload(self, payload, **kwargs):
                raise RuntimeError("boom")

        handler = delta_request_handler(_Boom())
        self.assertIsNone(handler("delta", b"x", b"", b"", None, 0.0))


class TestRnsSyncServer(_SyncTestCase):
    def test_destination_and_path(self) -> None:
        from dacar.naming import APP_NAME, SYNC_ASPECTS, SYNC_DESTINATION
        from dacar.transport.rns_sync import RnsSyncServer, SYNC_REQUEST_PATH

        self.assertEqual(SYNC_REQUEST_PATH, "delta")
        self.assertEqual(SYNC_DESTINATION, "dacar.sync.v1")
        self.assertEqual(APP_NAME + "." + ".".join(SYNC_ASPECTS), SYNC_DESTINATION)

        server = RnsSyncServer(self.issuer, self.receiver)
        expected = RNS.Destination.hash(self.issuer, APP_NAME, *SYNC_ASPECTS)
        self.assertEqual(bytes(server.destination_hash), bytes(expected))
        self.assertIs(server.receiver, self.receiver)
        server.announce()  # headless re-announce must not raise

    def test_handler_registered_on_destination(self) -> None:
        from dacar.transport.rns_sync import RnsSyncServer

        server = RnsSyncServer(self.issuer, self.receiver)
        handlers = server.destination.request_handlers.values()
        self.assertTrue(
            any(spec[0] == RnsSyncServer.REQUEST_PATH for spec in handlers),
            "delta request path not registered on the sync destination",
        )


_UNSET = object()


class _FakeLink:
    """Link double whose ``request`` invokes the registered callbacks."""

    ACTIVE = RNS.Link.ACTIVE

    def __init__(self, responses=None, fail=False, status=_UNSET):
        self.status = self.ACTIVE if status is _UNSET else status
        self._responses = list(responses or [])
        self._fail = fail
        self.requests: list = []
        self.torn_down = False

    def request(self, path, data, response_callback=None, failed_callback=None,
                timeout=None):
        self.requests.append((path, bytes(data)))
        if self._fail:
            failed_callback(object())
            return True
        response = self._responses.pop(0) if self._responses else None
        if response is not None:
            receipt = type("R", (), {"response": response})()
            response_callback(receipt)
        return True

    def teardown(self):
        self.torn_down = True


class _FakeDestination:
    hash = b"\x00" * 16


class TestPushDeltas(_SyncTestCase):
    def _run(self, payloads, link, **kwargs):
        with patch.object(rns_sync, "ensure_destination_path",
                          return_value=_FakeDestination()), \
             patch.object(rns_sync, "establish_link", return_value=link):
            return rns_sync.push_deltas(payloads, b"\x01" * 16, **kwargs)

    def test_all_accepted(self) -> None:
        ack = pack_ack(1)
        link = _FakeLink(responses=[ack, ack])
        payload = _signed_payload(self.issuer)
        result = self._run([payload, payload], link)
        self.assertEqual(result, [True, True])
        self.assertTrue(link.torn_down)
        self.assertEqual([p for _, p in link.requests], [payload, payload])
        self.assertEqual(link.requests[0][0], rns_sync.SYNC_REQUEST_PATH)

    def test_refused_delta_is_failure(self) -> None:
        link = _FakeLink(responses=[pack_ack(0)])
        self.assertEqual(self._run([b"x"], link), [False])

    def test_lost_response_is_failure(self) -> None:
        # No queued response and no failure callback: the request is lost. The
        # client waits timeout + grace, then counts it as a failure — the CRDT
        # makes the eventual retry safe. Use a tiny timeout for the test.
        link = _FakeLink()
        self.assertEqual(self._run([b"x"], link, timeout=0.05), [False])

    def test_failed_request_is_failure(self) -> None:
        link = _FakeLink(fail=True)
        self.assertEqual(self._run([b"x"], link), [False])

    def test_unestablishable_link_fails_all(self) -> None:
        with patch.object(rns_sync, "ensure_destination_path",
                          return_value=_FakeDestination()), \
             patch.object(rns_sync, "establish_link", return_value=None):
            result = rns_sync.push_deltas([b"a", b"b"], b"\x01" * 16)
        self.assertEqual(result, [False, False])

    def test_inactive_link_fails_without_requesting(self) -> None:
        link = _FakeLink(status=None)
        self.assertEqual(self._run([b"x"], link), [False])
        self.assertEqual(link.requests, [])
        self.assertTrue(link.torn_down)


class TestPurity(unittest.TestCase):
    def test_core_import_does_not_pull_transport(self) -> None:
        code = (
            "import sys; import dacar; "
            "assert not any(m == 'dacar.transport' or m.startswith('dacar.transport.') "
            "for m in sys.modules), 'core pulled in transport'"
        )
        subprocess.run([sys.executable, "-c", code], check=True)


if __name__ == "__main__":
    unittest.main()
