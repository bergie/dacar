"""Smoketests for the §8 RNS-Link transport adapters (spec §8).

The §8 protocol itself (Challenge/Receipt/verdict) is already covered by
test_challenge.py; these tests cover the new RNS glue:

  * ``challenge_request_handler`` wraps ``AuthoritativeServer.handle`` into the
    RNS response_generator contract (allow/deny/malformed).
  * ``RnsLinkTransport`` does the synchronous request/response wait over an
    established Link, returning None on failure/timeout (partition -> DENY).

The Link is faked (its ``request`` fires the response/failed callbacks), so the
tests are deterministic and need no live RNS network. A purity guard confirms
``import dacar`` (the core) never pulls in this rns-dependent subpackage.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import unittest

import RNS  # only for the Link.ACTIVE status constant in the fake

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dacar.challenge import AuthoritativeServer, Challenge, Receipt, Verdict
from dacar.config import Config
from dacar.crdt import StateVector
from dacar.namespace import HASH_SIZE, NamespaceHasher, SALT_SIZE
from dacar.operation import Action, Operation
from dacar.hlc import pack
from dacar.tuple import Tuple
from dacar.transport.rns_challenge import (
    CHALLENGE_REQUEST_PATH,
    RnsLinkTransport,
    challenge_request_handler,
)

SALT = bytes(range(SALT_SIZE))
HASHER = NamespaceHasher(SALT)
ROOT = bytes(range(HASH_SIZE))
BOB = bytes(range(HASH_SIZE, HASH_SIZE * 2))


def _config() -> Config:
    return Config(
        root_trust_anchors=frozenset({ROOT}), primary_salt=SALT, authoritative_identity=ROOT
    )


def _allow_state() -> StateVector:
    state = StateVector()
    state.apply(
        Operation(
            tuple=Tuple.from_plaintext(
                object_id="sensor:wind", relation="calibrate", grantee=BOB,
                issuer=ROOT, hasher=HASHER,
            ),
            action=Action.GRANT, hlc=pack(1_700_000_000_000, 0),
        ),
        now_ms=1_700_000_000_000,
    )
    return state


class _FakeReceipt:
    def __init__(self, response):
        self.response = response


class _FakeLink:
    """Mimics the RNS.Link surface used by RnsLinkTransport."""

    def __init__(self, *, status=RNS.Link.ACTIVE, response=None, fail=False, fire=True, delay=0.0):
        self.status = status
        self._response = response
        self._fail = fail
        self._fire = fire
        self._delay = delay
        self.last_path = None
        self.last_data = None

    def request(self, path, data, response_callback=None, failed_callback=None, timeout=None):
        self.last_path = path
        self.last_data = data
        receipt = object()  # truthy: the request "was sent"
        if not self._fire:
            return receipt  # partition: sent but never calls back

        def _emit():
            if self._delay:
                time.sleep(self._delay)
            if self._fail:
                if failed_callback is not None:
                    failed_callback(_FakeReceipt(None))
            elif response_callback is not None:
                response_callback(_FakeReceipt(self._response))

        threading.Thread(target=_emit, daemon=True).start()
        return receipt


class ChallengeRequestHandlerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()

    def _handler(self, state):
        return challenge_request_handler(AuthoritativeServer(_config(), state, self.priv))

    def test_allows_signed_grant(self) -> None:
        handler = self._handler(_allow_state())
        challenge = Challenge.generate("sensor:wind", "calibrate", BOB, _config().hashers)
        receipt_bytes = handler(CHALLENGE_REQUEST_PATH, challenge.to_payload(), b"id", b"link", None, 0.0)
        self.assertIsNotNone(receipt_bytes)
        receipt = Receipt.from_payload(receipt_bytes)
        self.assertEqual(receipt.verdict, Verdict.ALLOW)
        self.assertTrue(receipt.verify(self.pub))
        self.assertEqual(receipt.nonce, challenge.nonce)

    def test_denies_without_grant(self) -> None:
        handler = self._handler(StateVector())  # empty -> no allow
        challenge = Challenge.generate("sensor:wind", "calibrate", BOB, _config().hashers)
        receipt = Receipt.from_payload(handler(CHALLENGE_REQUEST_PATH, challenge.to_payload(), b"id", b"link", None, 0.0))
        self.assertEqual(receipt.verdict, Verdict.DENY)
        self.assertTrue(receipt.verify(self.pub))  # still properly signed

    def test_malformed_payload_returns_none(self) -> None:
        handler = self._handler(_allow_state())
        self.assertIsNone(handler(CHALLENGE_REQUEST_PATH, b"not a msgpack payload", b"id", b"link", None, 0.0))


class RnsLinkTransportTest(unittest.TestCase):
    def test_returns_receipt_bytes_on_response(self) -> None:
        link = _FakeLink(response=b"signed-receipt")
        transport = RnsLinkTransport(link)
        self.assertEqual(transport(b"challenge-payload"), b"signed-receipt")
        self.assertEqual(link.last_path, CHALLENGE_REQUEST_PATH)
        self.assertEqual(link.last_data, b"challenge-payload")

    def test_failure_returns_none(self) -> None:
        link = _FakeLink(fail=True)
        transport = RnsLinkTransport(link, timeout=2.0)
        self.assertIsNone(transport(b"challenge-payload"))

    def test_timeout_returns_none(self) -> None:
        link = _FakeLink(fire=False)  # never calls back
        transport = RnsLinkTransport(link, timeout=0.05, grace=0.0)
        self.assertIsNone(transport(b"challenge-payload"))

    def test_inactive_link_returns_none_without_requesting(self) -> None:
        link = _FakeLink(status=RNS.Link.CLOSED)
        transport = RnsLinkTransport(link)
        self.assertIsNone(transport(b"challenge-payload"))
        self.assertIsNone(link.last_data)  # request() was never called


class CorePurityTest(unittest.TestCase):
    def test_core_import_does_not_pull_transport(self) -> None:
        """`import dacar` must stay free of the rns-dependent transport layer."""
        out = subprocess.check_output(
            [sys.executable, "-c",
             "import sys, dacar; "
             "assert 'dacar.transport' not in sys.modules, 'core leaked transport!'; "
             "print('PURE')"],
            text=True,
        )
        self.assertIn("PURE", out)


if __name__ == "__main__":
    unittest.main()
