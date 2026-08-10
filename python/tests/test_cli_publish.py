"""Smoketests for the standalone ``dacar publish`` command (work doc #8 — §11.1).

Covers the two publish modes and the persisted outbox of locally-issued,
not-yet-published deltas:

  * ``dacar publish <file> [<file>...]`` — publish previously-signed delta
    payload(s) (exact bytes, no re-sign; multiple files → one batch).
  * ``dacar publish --all`` — pack + publish the outbox, then clear it.

The network layer (``_publish_delta``: boot RNS, announce, RFedClient) is
patched out so the tests run offline — the patch captures the payload handed to
publish, exactly like the ``grant --publish`` tests in ``test_cli_online.py``.
The store-layer outbox helpers are also unit-tested directly.
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

import RNS  # noqa: E402

from dacar import Action, Clock, Operation, Tuple, serialization  # noqa: E402
from dacar.hlc import pack, physical_now_ms  # noqa: E402
from dacar.namespace import SALT_SIZE, NamespaceHasher  # noqa: E402

from dacar.cli import build_parser, main  # noqa: E402
from dacar.cli.store import Store  # noqa: E402

SALT = bytes(range(SALT_SIZE))
BERGIE_HASH = "000102030405060708090a0b0c0d0e0f"
NODE_HEX = "aabbccdd" * 4  # 32 hex = 16 bytes (a fake rfed node hash)


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
    """Patches ``_publish_delta`` and records the last payload handed to it."""

    def __init__(self) -> None:
        self.payload: bytes | None = None
        self.calls = 0

    def __call__(self, args, store, identity, payload) -> None:
        self.payload = payload
        self.calls += 1


# ===========================================================================
# Store-layer outbox helpers (work doc #8)
# ===========================================================================


class OutboxStoreTest(unittest.TestCase):
    """``Store.load_outbox``/``save_outbox`` round-trip + ``0600`` mode."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-ob-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def test_empty_when_no_file(self):
        """A fresh store has no outbox; load returns an empty list."""
        self.assertFalse(self.store.outbox_path.exists())
        self.assertEqual(self.store.load_outbox(), [])

    def test_roundtrip_preserves_order_and_bytes(self):
        payloads = [b"\x01\x02\x03", b"", b"\xff" * 64]
        self.store.save_outbox(payloads)
        self.assertEqual(self.store.load_outbox(), payloads)

    def test_persisted_file_is_mode_0600(self):
        import stat
        self.store.save_outbox([b"\x01"])
        mode = stat.S_IMODE(self.store.outbox_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_clear_writes_empty_list(self):
        """save_outbox([]) persists an empty list that load_outbox reads back."""
        self.store.save_outbox([b"\x01", b"\x02"])
        self.store.save_outbox([])
        self.assertEqual(self.store.load_outbox(), [])

    def test_corrupted_file_returns_empty(self):
        """A corrupted outbox file does not crash the CLI (treated as empty)."""
        self.store.outbox_path.write_bytes(b"\xff\xff not msgpack \x00")
        self.assertEqual(self.store.load_outbox(), [])

    def test_non_list_payload_returns_empty(self):
        """A msgpack dict (not a list) is treated as empty, not a crash."""
        self.store.outbox_path.write_bytes(serialization.packb({"a": 1}))
        self.assertEqual(self.store.load_outbox(), [])


# ===========================================================================
# Enqueue behavior: grant/revoke populate the outbox (unless --publish)
# ===========================================================================


class EnqueueBehaviorTest(unittest.TestCase):
    """``grant``/``revoke`` enqueue locally-issued deltas unless ``--publish``."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-enq-"))
        run(self.store_dir, "init")
        run(self.store_dir, "alias", "add", "bergie", BERGIE_HASH)

    def test_grant_enqueues_to_outbox(self):
        """A normal grant (no --publish) appends its payload to the outbox."""
        code, _, err = run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        self.assertEqual(code, 0, err)
        outbox = Store(self.store_dir).load_outbox()
        self.assertEqual(len(outbox), 1)
        self.assertGreater(len(outbox[0]), 50)
        self.assertIn("queued in outbox", err)

    def test_grant_no_apply_still_enqueues(self):
        """``--no-apply`` only governs local CRDT apply, not the outbox (doc #8 #1)."""
        code, _, err = run(self.store_dir, "grant", "bergie", "read", "sensor:temp",
                           "--no-apply")
        self.assertEqual(code, 0, err)
        outbox = Store(self.store_dir).load_outbox()
        self.assertEqual(len(outbox), 1, "--no-apply must still enqueue")
        self.assertIn("queued in outbox", err)

    def test_grant_publish_does_not_enqueue(self):
        """``--publish`` sends immediately and must NOT touch the outbox."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, _ = run(self.store_dir, "grant", "bergie", "read", "sensor:wind",
                             "--publish", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, 1)  # publish was called
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 0)

    def test_multiple_grants_accumulate(self):
        """Each issued delta appends; the outbox grows until flushed."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        run(self.store_dir, "grant", "bergie", "read", "sensor:temp")
        run(self.store_dir, "revoke", "bergie", "read", "sensor:wind")
        outbox = Store(self.store_dir).load_outbox()
        self.assertEqual(len(outbox), 3)  # 2 grants + 1 revoke


# ===========================================================================
# `dacar publish --all` (flush the outbox)
# ===========================================================================


class PublishAllTest(unittest.TestCase):
    """``publish --all`` packs + publishes + clears the outbox (doc #8)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-puball-"))
        run(self.store_dir, "init")
        run(self.store_dir, "alias", "add", "bergie", BERGIE_HASH)

    def test_publishes_batch_and_clears_outbox(self):
        """Two enqueued deltas are packed into one batch, published, then cleared."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        run(self.store_dir, "grant", "bergie", "read", "sensor:temp")
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 2)

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls, 1)
        # The published payload is a msgpack array of the two deltas.
        items = serialization.unpackb(cap.payload)
        self.assertIsInstance(items, list)
        self.assertEqual(len(items), 2)
        # Outbox was cleared.
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 0)
        self.assertIn("outbox cleared", err)

    def test_single_outbox_entry_published_as_single_delta(self):
        """One enqueued delta is published as raw bytes (not a 1-element batch)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        single = Store(self.store_dir).load_outbox()[0]

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        # Exactly the original payload bytes — no wrapping.
        self.assertEqual(cap.payload, single)

    def test_empty_outbox_is_noop(self):
        """``publish --all`` on an empty outbox exits 0 without publishing."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, 0)  # never opened RNS
        self.assertIn("outbox empty", err)

    def test_failed_publish_leaves_outbox_intact(self):
        """If publish raises, the outbox is NOT cleared (retryable)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 1)

        def boom(args, store, identity, payload):
            raise RuntimeError("network down")

        with patch("dacar.cli.commands._publish_delta", side_effect=boom):
            with self.assertRaises(RuntimeError):
                main(["publish", "--all", "--node", NODE_HEX, "--store", str(self.store_dir)])
        # Outbox untouched so the next `publish --all` retries.
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 1)


# ===========================================================================
# `dacar publish <file> [<file>...]` (publish previously-signed deltas)
# ===========================================================================


class PublishFileTest(unittest.TestCase):
    """``publish <file>`` publishes the exact bytes (no re-sign); files batch."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pubfile-"))
        run(self.store_dir, "init")
        run(self.store_dir, "alias", "add", "bergie", BERGIE_HASH)

    def test_single_file_publishes_exact_bytes(self):
        """A single file's bytes are published verbatim (no re-sign, no wrap)."""
        payload = _signed_delta_payload(Store(self.store_dir))
        hex_path = self.store_dir / "delta.hex"
        hex_path.write_text(payload.hex())

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", str(hex_path), "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls, 1)
        self.assertEqual(cap.payload, payload)  # exact bytes, no batch wrap

    def test_binary_file_auto_detected(self):
        """Raw binary input is auto-detected and published verbatim."""
        payload = _signed_delta_payload(Store(self.store_dir))
        bin_path = self.store_dir / "delta.bin"
        bin_path.write_bytes(payload)

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", str(bin_path), "--node", NODE_HEX)
        self.assertEqual(cap.payload, payload)

    def test_stdin_input(self):
        """``-`` reads a hex payload from stdin."""
        import sys
        payload = _signed_delta_payload(Store(self.store_dir))
        real_stdin = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(payload.hex().encode()))
        try:
            cap = _Capture()
            with patch("dacar.cli.commands._publish_delta", side_effect=cap):
                run(self.store_dir, "publish", "-", "--node", NODE_HEX)
        finally:
            sys.stdin = real_stdin
        self.assertEqual(cap.payload, payload)

    def test_multiple_files_packed_into_batch(self):
        """Two files are packed into one batch payload (one publish call)."""
        p1 = _signed_delta_payload(Store(self.store_dir), object_id="sensor:wind")
        p2 = _signed_delta_payload(Store(self.store_dir), object_id="sensor:temp")
        f1 = self.store_dir / "d1.hex"
        f2 = self.store_dir / "d2.hex"
        f1.write_text(p1.hex())
        f2.write_text(p2.hex())

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", str(f1), str(f2), "--node", NODE_HEX)
        self.assertEqual(cap.calls, 1)
        items = serialization.unpackb(cap.payload)
        self.assertEqual([bytes(i) for i in items], [p1, p2])

    def test_publish_file_does_not_touch_outbox(self):
        """``publish <file>`` publishes an external payload, not the outbox."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")  # enqueues 1
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 1)

        payload = _signed_delta_payload(Store(self.store_dir), object_id="other:thing")
        f = self.store_dir / "ext.hex"
        f.write_text(payload.hex())

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", str(f), "--node", NODE_HEX)
        # Outbox unchanged (the file delta is external, not the node's issuance).
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 1)

    def test_empty_file_errors(self):
        """An empty payload file is a clear error, not a silent publish."""
        empty = self.store_dir / "empty.hex"
        empty.write_text("")
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", str(empty), "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("empty payload", err)
        self.assertEqual(cap.calls, 0)


# ===========================================================================
# Argument validation
# ===========================================================================


class PublishValidationTest(unittest.TestCase):
    """``publish`` requires either <file>... or --all, but not both."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pubval-"))
        run(self.store_dir, "init")

    def test_neither_file_nor_all_errors(self):
        code, _, err = run(self.store_dir, "publish", "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("or --all", err)

    def test_all_and_file_together_errors(self):
        code, _, err = run(self.store_dir, "publish", "--all", "some.hex",
                           "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("not both", err)

    def test_requires_signing_identity(self):
        """A store with no identity cannot publish."""
        # Remove the identity to simulate an uninitialized signing identity.
        Store(self.store_dir).identity_default_path.unlink()
        code, _, err = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("signing identity", err)


# ===========================================================================
# Parser
# ===========================================================================


class PublishParserTest(unittest.TestCase):
    """The ``publish`` subparser accepts files, --all, --binary, and online flags."""

    def test_publish_with_positional_files(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "a.hex", "b.hex", "--node", NODE_HEX])
        self.assertEqual(args.command, "publish")
        self.assertEqual(args.payloads, ["a.hex", "b.hex"])
        self.assertFalse(args.all)

    def test_publish_all_flag(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "--all", "--node", NODE_HEX])
        self.assertTrue(args.all)
        self.assertEqual(args.payloads, [])

    def test_publish_binary_flag(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "a.bin", "--binary", "--node", NODE_HEX])
        self.assertTrue(args.binary)

    def test_publish_accepts_online_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "publish", "--all", "--node", NODE_HEX, "--topic", "custom.topic",
            "--discover",
        ])
        self.assertEqual(args.node, NODE_HEX)
        self.assertEqual(args.topic, "custom.topic")
        self.assertTrue(args.discover)

    def test_publish_no_positional_defaults_to_empty(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "--all"])
        self.assertEqual(args.payloads, [])


# ===========================================================================
# `dacar prune` also drops stale outbox entries (doc #8 #2)
# ===========================================================================


class PruneOutboxTest(unittest.TestCase):
    """``prune`` drops outbox entries older than the §9 horizon (doc #8 #2)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pruneob-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def _backdated_delta(self, *, ms: int, object_id: str = "old:thing") -> bytes:
        """Build a signed delta with a backdated HLC physical component."""
        config = self.store.load_config()
        identity = self.store.load_identity()
        hasher = NamespaceHasher(config.primary_salt)
        tup = Tuple.from_plaintext(
            object_id=object_id, relation="read",
            grantee=bytes.fromhex(BERGIE_HASH), issuer=identity.hash, hasher=hasher,
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=pack(ms, 0)).sign(identity.sig_prv)
        return op.to_payload()

    def test_stale_outbox_entry_dropped_on_prune(self):
        """An outbox delta older than the horizon is dropped by `prune`."""
        from dacar.config import DEFAULT_DELETION_HORIZON_DAYS
        horizon_ms = DEFAULT_DELETION_HORIZON_DAYS * 24 * 3600 * 1000
        old_ms = physical_now_ms() - horizon_ms - 86_400_000  # one day past the horizon
        fresh_ms = physical_now_ms()  # now

        self.store.save_outbox([
            self._backdated_delta(ms=old_ms, object_id="old:thing"),
            self._backdated_delta(ms=fresh_ms, object_id="new:thing"),
        ])
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)
        self.assertIn("pruned 0", err)  # CRDT had nothing to prune
        self.assertIn("outbox: pruned 1", err)
        outbox = self.store.load_outbox()
        self.assertEqual(len(outbox), 1)  # only the fresh one remains

    def test_fresh_outbox_entries_kept_on_prune(self):
        """Fresh outbox entries are not touched by `prune`."""
        self.store.save_outbox([self._backdated_delta(ms=physical_now_ms())])
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)
        self.assertNotIn("outbox: pruned", err)  # nothing stale -> no outbox line
        self.assertEqual(len(self.store.load_outbox()), 1)

    def test_empty_outbox_prune_no_error(self):
        """`prune` on a store with no outbox file is a no-op (no crash)."""
        self.assertFalse(self.store.outbox_path.exists())
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)
        self.assertIn("pruned 0", err)


if __name__ == "__main__":
    unittest.main()
