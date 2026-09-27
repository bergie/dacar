"""Smoketests for the standalone ``dacar push`` command (§11, doc #16 Phase 4a).

Direct-link Delta delivery to a constrained node: the target's identity hash
(or alias) is a *positional* argument, its ``dacar.sync.v1`` destination is
derived from it, and one Link carries all Deltas. Source families mirror
``publish`` (docs #8/#11):

  * ``dacar push <node> <file> [<file>...]`` — previously-signed external
    payloads (exact bytes, not recorded to the sent box).
  * ``dacar push <node> [--outbox] [--sent] [--all]`` — this node's own
    issuance; accepted deltas drain outbox → sent box.

The network layer (``_push_deltas``: boot RNS, announce, link, per-Delta
requests) is patched out so the tests run offline — the patch captures the
payloads and the resolved target and returns per-delta acceptance so the store
updates (``_record_publish``) run exactly as in production.
"""

from __future__ import annotations

import io
import logging
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

# Silence RNS's own logging so captured stderr holds only the CLI's output.
logging.getLogger("RNS").setLevel(logging.CRITICAL)

from dacar import Action, Clock, Operation, Tuple  # noqa: E402
from dacar.namespace import SALT_SIZE, NamespaceHasher  # noqa: E402

from dacar.cli import main  # noqa: E402
from dacar.cli.commands import _push_deltas  # noqa: E402
from dacar.cli.store import Store  # noqa: E402

SALT = bytes(range(SALT_SIZE))
BERGIE_HASH = "000102030405060708090a0b0c0d0e0f"
NODE_HEX = "aabbccdd" * 4  # 32 hex = 16 bytes (a fake node identity hash)


def run(store_dir: Path, *argv: str) -> tuple[int, str, str]:
    """Invoke the CLI in-process against ``store_dir``; return (code, out, err)."""
    out = io.StringIO()
    err = io.StringIO()
    full = [*argv, "--store", str(store_dir)]
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(full)
    except SystemExit as exc:  # argparse --help etc.
        code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def _signed_delta_payload(store: Store, *, relation: str = "read",
                          object_id: str = "sensor:wind") -> bytes:
    """Build a signed Delta payload issued by the store's own identity."""
    config = store.load_config()
    identity = store.load_identity()
    hasher = NamespaceHasher(config.primary_salt)
    tup = Tuple.from_plaintext(
        object_id=object_id, relation=relation,
        grantee=bytes.fromhex(BERGIE_HASH), issuer=identity.hash, hasher=hasher,
    )
    op = Operation(tuple=tup, action=Action.GRANT, hlc=Clock().now()).sign(identity.sig_prv)
    return op.to_payload()


class _Capture:
    """Patches ``_push_deltas`` and records what the CLI handed it."""

    def __init__(self, accepted: list[bool] | None = None):
        self.calls: list[dict] = []
        self._accepted = accepted

    def __enter__(self):
        self._patcher = patch(
            "dacar.cli.commands._push_deltas",
            side_effect=self._fake,
        )
        self._patcher.start()
        return self

    def __exit__(self, *exc):
        self._patcher.stop()

    def _fake(self, args, store, identity, payloads, target):
        self.calls.append({
            "payloads": [bytes(p) for p in payloads],
            "target": bytes(target),
        })
        return list(self._accepted) if self._accepted is not None else [True] * len(payloads)


class InitStoreMixin:
    def setUp(self) -> None:
        super().setUp()
        self.dir = Path(tempfile.mkdtemp(prefix="dacar-push-"))
        Store.init(self.dir, salt=SALT)
        self.store = Store(str(self.dir))
        # Remember the target node under an alias for the alias-resolution test.
        code, _, err = run(self.dir, "alias", "add", "t1000e", NODE_HEX)
        assert code == 0, err


class TestPushSources(InitStoreMixin, unittest.TestCase):
    def test_requires_node_argument(self) -> None:
        code, _, err = run(self.dir, "push")
        self.assertEqual(code, 2)  # argparse: missing required positional
        self.assertIn("node", err)

    def test_outbox_default_drains_to_sent(self) -> None:
        payload = _signed_delta_payload(self.store)
        ob = self.store.load_outbox()
        ob.append(payload)
        self.store.save_outbox(ob)
        with _Capture() as cap:
            code, _, err = run(self.dir, "push", "t1000e")
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls, [{"payloads": [payload], "target": bytes.fromhex(NODE_HEX)}])
        self.assertEqual(self.store.load_outbox(), [])
        self.assertEqual(self.store.load_sent(), [payload])
        self.assertIn("pushing 1 delta(s) (outbox)", err)

    def test_files_not_recorded_to_sent(self) -> None:
        payload = _signed_delta_payload(self.store)
        f = self.dir / "delta.hex"
        f.write_text(payload.hex())
        with _Capture(accepted=[True]) as cap:
            code, _, err = run(self.dir, "push", NODE_HEX, str(f))
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls[0]["payloads"], [payload])
        self.assertEqual(cap.calls[0]["target"], bytes.fromhex(NODE_HEX))
        self.assertEqual(self.store.load_outbox(), [])
        self.assertEqual(self.store.load_sent(), [])  # external issuance
        self.assertIn("1 file(s)", err)

    def test_files_and_source_flag_are_exclusive(self) -> None:
        payload = _signed_delta_payload(self.store)
        f = self.dir / "delta.hex"
        f.write_text(payload.hex())
        code, _, err = run(self.dir, "push", NODE_HEX, str(f), "--outbox")
        self.assertEqual(code, 1)
        self.assertIn("not both", err)

    def test_empty_outbox_is_noop(self) -> None:
        with _Capture() as cap:
            code, _, err = run(self.dir, "push", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, [])
        self.assertIn("nothing to push", err)

    def test_sent_resend_leaves_sent_box_intact(self) -> None:
        payload = _signed_delta_payload(self.store)
        st = self.store.load_sent()
        st.append(payload)
        self.store.save_sent(st)
        with _Capture(accepted=[True]) as cap:
            code, _, err = run(self.dir, "push", NODE_HEX, "--sent")
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls[0]["payloads"], [payload])
        self.assertEqual(self.store.load_sent(), [payload])  # idempotent, unmodified
        self.assertIn("not modified", err)

    def test_all_is_outbox_plus_sent(self) -> None:
        a = _signed_delta_payload(self.store, relation="read")
        b = _signed_delta_payload(self.store, relation="write")
        ob = self.store.load_outbox()
        ob.append(a)
        self.store.save_outbox(ob)
        st = self.store.load_sent()
        st.append(b)
        self.store.save_sent(st)
        with _Capture(accepted=[True, True]) as cap:
            code, _, _ = run(self.dir, "push", NODE_HEX, "--all")
        self.assertEqual(code, 0)
        # Dedup by exact bytes preserves first-seen order (outbox before sent).
        self.assertEqual(cap.calls[0]["payloads"], [a, b])
        self.assertEqual(self.store.load_outbox(), [])
        self.assertEqual(self.store.load_sent(), [b, a])

    def test_partial_acceptance_keeps_failures_in_outbox(self) -> None:
        a = _signed_delta_payload(self.store, relation="read")
        b = _signed_delta_payload(self.store, relation="write")
        ob = self.store.load_outbox()
        ob.extend([a, b])
        self.store.save_outbox(ob)
        with _Capture(accepted=[True, False]) as cap:
            code, _, err = run(self.dir, "push", NODE_HEX, "--outbox")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.store.load_outbox(), [b])  # refused delta retained
        self.assertEqual(self.store.load_sent(), [a])
        self.assertIn("not accepted by the node", err)

    def test_dedup_within_source(self) -> None:
        payload = _signed_delta_payload(self.store)
        ob = self.store.load_outbox()
        ob.extend([payload, payload])
        self.store.save_outbox(ob)
        with _Capture(accepted=[True]) as cap:
            code, _, _ = run(self.dir, "push", NODE_HEX, "--outbox")
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls[0]["payloads"], [payload])
        self.assertEqual(self.store.load_outbox(), [])

    def test_unknown_node_alias_fails(self) -> None:
        code, _, err = run(self.dir, "push", "no-such-alias")
        self.assertEqual(code, 1)
        self.assertIn("unknown identity", err)


class TestPushSeam(InitStoreMixin, unittest.TestCase):
    def test_seam_announces_and_calls_transport(self) -> None:
        """``_push_deltas`` boots RNS headless, announces, and delegates."""
        from tests._rns_fixture import ensure_headless

        ensure_headless()
        payload = _signed_delta_payload(self.store)

        captured: dict = {}

        def fake_transport_push(payloads, target, *, timeout, on_request):
            captured["payloads"] = [bytes(p) for p in payloads]
            captured["target"] = bytes(target)
            captured["timeout"] = timeout
            return [True]

        identity = self.store.load_identity()
        with patch("dacar.transport.rns_sync.push_deltas", side_effect=fake_transport_push):
            with patch("dacar.cli.rns.boot", return_value=object()), \
                 patch("dacar.cli.rns.announce_identity") as announce, \
                 patch("dacar.cli.rns.register_announce_handler"):
                result = _push_deltas(
                    type("A", (), {
                        "store": str(self.dir), "rns_config": None,
                        "timeout": None, "full_hashes": False,
                    })(),
                    self.store, identity, [payload], bytes.fromhex(NODE_HEX),
                )

        self.assertEqual(result, [True])
        self.assertEqual(captured["payloads"], [payload])
        self.assertEqual(captured["target"], bytes.fromhex(NODE_HEX))
        # Default timeout applies when --timeout is not given.
        self.assertIsNotNone(captured["timeout"])
        # The announce invariant (§11.2.4): the pusher announces before pushing.
        announce.assert_called_once_with(identity)


if __name__ == "__main__":
    unittest.main()
