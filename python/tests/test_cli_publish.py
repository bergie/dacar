"""Smoketests for the standalone ``dacar publish`` command (§11.1, docs #8/#11).

Covers the durable issuance log split into two stores (work doc #11):

  * **Outbox** — Deltas not yet published (the fresh queue). ``grant``/``revoke``
    append here (unless ``--publish``). ``publish --outbox`` flushes it: each
    Delta **moves** to the sent box once the transport accepts it.
  * **Sent box** — every Delta this node has published, as exact signed bytes
    (the durable replay log). ``publish --sent`` re-sends it idempotently
    (CRDT merge is a no-op for already-delivered deltas); the sent box is not
    modified. ``publish --all`` is ``--outbox`` + ``--sent``.

Plus ``dacar publish <file> [<file>...]`` for previously-signed external
payloads (exact bytes, no re-sign; not logged to the sent box — they are not
this node's own issuance).

The network layer (``_publish_delta``: boot RNS, announce, RFedClient) is
patched out so the tests run offline — the patch captures the payload handed to
publish and returns per-delta transport acceptance so the store updates
(``_record_publish``: outbox→sent) run exactly as in production. The store-layer
outbox/sent helpers are also unit-tested directly.
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
    """Patches ``_publish_delta`` and records the payloads handed to it.

    Returns per-delta transport acceptance (all accepted) so the caller's
    ``_record_publish`` (outbox→sent box) runs exactly as in production.
    ``payloads`` preserves publish order; ``payload`` is the single payload when
    exactly one was published (``None`` otherwise), for the single-delta tests.
    """

    def __init__(self, *, accept: bool = True) -> None:
        self.payloads: list[bytes] = []
        self.calls = 0
        self._accept = accept

    def __call__(self, args, store, identity, payloads) -> list:
        self.payloads = list(payloads)
        self.calls += 1
        return [self._accept] * len(payloads)

    @property
    def payload(self) -> bytes | None:
        """The single payload when exactly one was published, else ``None``."""
        return self.payloads[0] if len(self.payloads) == 1 else None


# ===========================================================================
# Store-layer outbox + sent box helpers (docs #8/#11)
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


class SentBoxStoreTest(unittest.TestCase):
    """``Store.load_sent``/``save_sent`` round-trip + ``0600`` mode (doc #11)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-sent-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def test_empty_when_no_file(self):
        """A fresh store has no sent box; load returns an empty list."""
        self.assertFalse(self.store.sent_path.exists())
        self.assertEqual(self.store.load_sent(), [])

    def test_roundtrip_preserves_order_and_bytes(self):
        payloads = [b"\x01\x02\x03", b"", b"\xff" * 64]
        self.store.save_sent(payloads)
        self.assertEqual(self.store.load_sent(), payloads)

    def test_persisted_file_is_mode_0600(self):
        import stat
        self.store.save_sent([b"\x01"])
        mode = stat.S_IMODE(self.store.sent_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_corrupted_file_returns_empty(self):
        """A corrupted sent box does not crash the CLI (treated as empty)."""
        self.store.sent_path.write_bytes(b"\xff\xff not msgpack \x00")
        self.assertEqual(self.store.load_sent(), [])

    def test_outbox_and_sent_are_separate_files(self):
        """The outbox and sent box persist to distinct files (doc #11)."""
        self.store.save_outbox([b"\x01"])
        self.store.save_sent([b"\x02"])
        self.assertEqual(self.store.load_outbox(), [b"\x01"])
        self.assertEqual(self.store.load_sent(), [b"\x02"])
        self.assertNotEqual(self.store.outbox_path, self.store.sent_path)


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

    def test_grant_publish_logs_to_sent_not_outbox(self):
        """``--publish`` sends immediately and logs the delta to the sent box.

        The delta is enqueued to the outbox *before* the send (durability: it
        survives a crash), then on transport acceptance it moves outbox → sent
        box (the durable replay log). Net: the outbox is empty and the sent box
        holds exactly the one issued delta (doc #11)."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "grant", "bergie", "read", "sensor:wind",
                               "--publish", "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls, 1)  # publish was called
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 0)  # moved out of outbox
        sent = store.load_sent()
        self.assertEqual(len(sent), 1)  # ...into the sent box
        self.assertEqual(sent[0], cap.payload)
        self.assertIn("logged to sent box", err)

    def test_grant_publish_failure_keeps_outbox(self):
        """A failed ``grant --publish`` leaves the delta in the outbox for retry.

        The delta was enqueued before the send (durability); when the transport
        rejects it, it is NOT moved to the sent box and stays in the outbox."""
        cap = _Capture(accept=False)
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "grant", "bergie", "read", "sensor:wind",
                               "--publish", "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 1)  # retained for retry
        self.assertEqual(len(store.load_sent()), 0)   # not logged (send failed)
        self.assertIn("retained in outbox", err)

    def test_multiple_grants_accumulate(self):
        """Each issued delta appends; the outbox grows until flushed."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        run(self.store_dir, "grant", "bergie", "read", "sensor:temp")
        run(self.store_dir, "revoke", "bergie", "read", "sensor:wind")
        outbox = Store(self.store_dir).load_outbox()
        self.assertEqual(len(outbox), 3)  # 2 grants + 1 revoke


# ===========================================================================
# `dacar publish --outbox` (flush the outbox → sent box)
# ===========================================================================


class PublishOutboxTest(unittest.TestCase):
    """``publish --outbox`` flushes the outbox; each Delta moves to the sent box."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pubob-"))
        run(self.store_dir, "init")
        run(self.store_dir, "alias", "add", "bergie", BERGIE_HASH)

    def test_publish_outbox_moves_deltas_to_sent(self):
        """Every outbox Delta is published (exact bytes) and moves to the sent box.

        Publish is fire-and-forget, but on transport acceptance the signed
        payload leaves the unsent queue and enters the durable replay log, so a
        later ``publish --sent`` can re-deliver it to new peers (doc #11)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        run(self.store_dir, "grant", "bergie", "read", "sensor:temp")
        outbox = Store(self.store_dir).load_outbox()
        self.assertEqual(len(outbox), 2)

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--outbox", "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        # One _publish_delta call with the full list, exact bytes verbatim.
        self.assertEqual(cap.calls, 1)
        self.assertEqual(cap.payloads, outbox)
        store = Store(self.store_dir)
        # Outbox drained (deltas moved out of the unsent queue).
        self.assertEqual(len(store.load_outbox()), 0)
        # ...and into the sent box (durable replay log), in publish order.
        self.assertEqual(store.load_sent(), outbox)
        self.assertIn("moved outbox", err)

    def test_bare_publish_defaults_to_outbox(self):
        """``publish`` with no files and no flag implies ``--outbox`` (doc #11)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        outbox = Store(self.store_dir).load_outbox()

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, _ = run(self.store_dir, "publish", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.payloads, outbox)
        self.assertEqual(len(Store(self.store_dir).load_sent()), 1)

    def test_single_outbox_entry_published_as_single_delta(self):
        """One enqueued delta is published verbatim and moved to the sent box."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        single = Store(self.store_dir).load_outbox()[0]

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", "--outbox", "--node", NODE_HEX)
        # Exactly the original payload bytes — no wrapping.
        self.assertEqual(cap.calls, 1)
        self.assertEqual(cap.payload, single)
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 0)
        self.assertEqual(store.load_sent(), [single])

    def test_empty_outbox_is_noop(self):
        """``publish --outbox`` on an empty outbox exits 0 without publishing."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--outbox", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, 0)  # never opened RNS
        self.assertIn("nothing to publish", err)

    def test_failed_publish_leaves_outbox_intact(self):
        """If publish raises, the outbox is NOT drained (retryable)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 1)

        def boom(args, store, identity, payloads):
            raise RuntimeError("network down")

        with patch("dacar.cli.commands._publish_delta", side_effect=boom):
            with self.assertRaises(RuntimeError):
                main(["publish", "--outbox", "--node", NODE_HEX,
                      "--store", str(self.store_dir)])
        # Outbox untouched so the next `publish --outbox` retries; sent empty.
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 1)
        self.assertEqual(len(store.load_sent()), 0)

    def test_partial_failure_keeps_unsent_in_outbox(self):
        """A delta the transport rejects stays in the outbox; accepted ones move.

        Two outbox deltas; the second is rejected by the transport (accept=False
        for it). The accepted one moves to the sent box; the rejected one stays
        in the outbox for retry (doc #11)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        run(self.store_dir, "grant", "bergie", "read", "sensor:temp")
        outbox = Store(self.store_dir).load_outbox()
        self.assertEqual(len(outbox), 2)

        # Accept the first, reject the second.
        accepted_flags = {"i": 0}

        def fake(args, store, identity, payloads):
            accepted_flags["i"] += 1
            return [True, False][:len(payloads)] if len(payloads) == 2 else [True]

        with patch("dacar.cli.commands._publish_delta", side_effect=fake):
            code, _, _ = run(self.store_dir, "publish", "--outbox", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        store = Store(self.store_dir)
        sent = store.load_sent()
        outbox_after = store.load_outbox()
        # Exactly one moved to the sent box, one stayed in the outbox.
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(outbox_after), 1)
        self.assertIn(sent[0], outbox)
        self.assertIn(outbox_after[0], outbox)


# ===========================================================================
# `dacar publish --sent` (re-send the durable replay log)
# ===========================================================================


class PublishSentTest(unittest.TestCase):
    """``publish --sent`` re-sends the sent box without modifying it (doc #11)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pubsent-"))
        run(self.store_dir, "init")
        run(self.store_dir, "alias", "add", "bergie", BERGIE_HASH)

    def _seed_sent(self, n: int = 2) -> list[bytes]:
        """Populate the sent box with ``n`` signed deltas (simulate published)."""
        store = Store(self.store_dir)
        payloads = [
            _signed_delta_payload(store, object_id=f"sensor:{i}") for i in range(n)
        ]
        store.save_sent(payloads)
        return payloads

    def test_sent_resend_publishes_all_without_modifying(self):
        """``publish --sent`` re-sends every Delta; the sent box is unchanged.

        Re-send is idempotent on peers (CRDT merge is a no-op for already-
        delivered deltas), and the sent box is not appended to (the payloads are
        already present)."""
        sent = self._seed_sent(2)

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--sent", "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls, 1)
        self.assertEqual(cap.payloads, sent)  # exact bytes, in order
        # Sent box unchanged (no duplicates appended)...
        self.assertEqual(Store(self.store_dir).load_sent(), sent)
        # ...and the outbox untouched.
        self.assertEqual(len(Store(self.store_dir).load_outbox()), 0)
        self.assertIn("idempotent", err)

    def test_sent_resend_does_not_duplicate(self):
        """Re-sending the sent box never appends duplicates (dedup by bytes)."""
        sent = self._seed_sent(2)
        for _ in range(3):  # re-send three times
            cap = _Capture()
            with patch("dacar.cli.commands._publish_delta", side_effect=cap):
                run(self.store_dir, "publish", "--sent", "--node", NODE_HEX)
        self.assertEqual(Store(self.store_dir).load_sent(), sent)  # still exactly 2

    def test_empty_sent_is_noop(self):
        """``publish --sent`` on an empty sent box exits 0 without publishing."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--sent", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, 0)
        self.assertIn("nothing to publish", err)


# ===========================================================================
# `dacar publish --all` (outbox + sent box)
# ===========================================================================


class PublishAllTest(unittest.TestCase):
    """``publish --all`` sends outbox + sent box (everything this node issued)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-puball-"))
        run(self.store_dir, "init")
        run(self.store_dir, "alias", "add", "bergie", BERGIE_HASH)

    def test_all_sends_outbox_and_sent(self):
        """``--all`` publishes the outbox (moved to sent) + the sent box.

        Outbox deltas move to the sent box; already-sent deltas are re-sent
        (deduplicated against the outbox deltas by exact bytes)."""
        # One delta already published (in the sent box).
        store = Store(self.store_dir)
        sent_existing = _signed_delta_payload(store, object_id="sensor:sent")
        store.save_sent([sent_existing])
        # Two fresh deltas queued in the outbox.
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        run(self.store_dir, "grant", "bergie", "read", "sensor:temp")
        outbox = store.load_outbox()
        self.assertEqual(len(outbox), 2)

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertEqual(code, 0, err)
        self.assertEqual(cap.calls, 1)
        # All three were published (outbox(2) + sent(1)), deduped by bytes.
        self.assertEqual(len(cap.payloads), 3)
        self.assertEqual(set(cap.payloads[:2]), set(outbox))  # outbox first
        self.assertEqual(cap.payloads[2], sent_existing)    # ...then the sent box
        # Outbox drained...
        self.assertEqual(len(store.load_outbox()), 0)
        # ...sent box now has all three (deduped).
        sent_after = store.load_sent()
        self.assertEqual(len(sent_after), 3)
        self.assertEqual(set(sent_after), {sent_existing, *outbox})

    def test_all_empty_is_noop(self):
        """``publish --all`` with empty outbox + sent box exits 0 without publishing."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, 0)
        self.assertIn("nothing to publish", err)

    def test_all_with_only_outbox(self):
        """``--all`` with deltas only in the outbox behaves like ``--outbox``."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")
        outbox = Store(self.store_dir).load_outbox()

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, _ = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.payloads, outbox)
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 0)
        self.assertEqual(store.load_sent(), outbox)

    def test_all_with_only_sent(self):
        """``--all`` with deltas only in the sent box behaves like ``--sent``."""
        store = Store(self.store_dir)
        sent = _signed_delta_payload(store, object_id="sensor:sent")
        store.save_sent([sent])

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, _ = run(self.store_dir, "publish", "--all", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.payloads, [sent])
        # Sent box unchanged (re-send, no dedup-needed append).
        self.assertEqual(store.load_sent(), [sent])


# ===========================================================================
# `dacar publish <file> [<file>...]` (publish previously-signed deltas)
# ===========================================================================


class PublishFileTest(unittest.TestCase):
    """``publish <file>`` publishes the exact bytes (no re-sign); files batch.

    File publishes are external payloads (not this node's own issuance), so they
    are NOT logged to the sent box and do not drain the outbox (doc #11)."""

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

    def test_multiple_files_published_individually(self):
        """Two files are published as two rfed messages (one per Delta).

        Each file's exact signed bytes are published verbatim, in argument
        order — no batch wrapping (§11.1.1: one Operation per envelope)."""
        p1 = _signed_delta_payload(Store(self.store_dir), object_id="sensor:wind")
        p2 = _signed_delta_payload(Store(self.store_dir), object_id="sensor:temp")
        f1 = self.store_dir / "d1.hex"
        f2 = self.store_dir / "d2.hex"
        f1.write_text(p1.hex())
        f2.write_text(p2.hex())

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", str(f1), str(f2), "--node", NODE_HEX)
        # One _publish_delta call with the full list, exact bytes verbatim.
        self.assertEqual(cap.calls, 1)
        self.assertEqual(cap.payloads, [p1, p2])

    def test_publish_file_does_not_touch_outbox_or_sent(self):
        """``publish <file>`` publishes an external payload, touching neither store.

        The file delta is not this node's issuance: it does not drain the
        outbox (it is not in it) and is not appended to the sent box (external
        payloads are excluded from the durable replay log, doc #11)."""
        run(self.store_dir, "grant", "bergie", "read", "sensor:wind")  # enqueues 1
        store = Store(self.store_dir)
        self.assertEqual(len(store.load_outbox()), 1)

        payload = _signed_delta_payload(store, object_id="other:thing")
        f = self.store_dir / "ext.hex"
        f.write_text(payload.hex())

        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            run(self.store_dir, "publish", str(f), "--node", NODE_HEX)
        # Outbox unchanged; sent box not populated (external payload).
        self.assertEqual(len(store.load_outbox()), 1)
        self.assertEqual(len(store.load_sent()), 0)

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
    """``publish`` requires either <file>... or a source flag, but not both."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pubval-"))
        run(self.store_dir, "init")

    def test_bare_publish_empty_outbox_is_noop(self):
        """Bare ``publish`` (no files, no flag) implies ``--outbox`` (doc #11).

        On an empty outbox it is a friendly no-op (exit 0), not an error."""
        cap = _Capture()
        with patch("dacar.cli.commands._publish_delta", side_effect=cap):
            code, _, err = run(self.store_dir, "publish", "--node", NODE_HEX)
        self.assertEqual(code, 0)
        self.assertEqual(cap.calls, 0)
        self.assertIn("nothing to publish", err)

    def test_flag_and_file_together_errors(self):
        """A source flag and <file>... are mutually exclusive."""
        code, _, err = run(self.store_dir, "publish", "--outbox", "some.hex",
                           "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("not both", err)

    def test_all_and_file_together_errors(self):
        code, _, err = run(self.store_dir, "publish", "--all", "some.hex",
                           "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("not both", err)

    def test_requires_signing_identity(self):
        """A store with no identity cannot publish."""
        # Remove the identity to simulate an uninitialized signing identity.
        Store(self.store_dir).identity_default_path.unlink()
        code, _, err = run(self.store_dir, "publish", "--outbox", "--node", NODE_HEX)
        self.assertNotEqual(code, 0)
        self.assertIn("signing identity", err)


# ===========================================================================
# Parser
# ===========================================================================


class PublishParserTest(unittest.TestCase):
    """The ``publish`` subparser accepts files, --outbox/--sent/--all, --binary."""

    def test_publish_with_positional_files(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "a.hex", "b.hex", "--node", NODE_HEX])
        self.assertEqual(args.command, "publish")
        self.assertEqual(args.payloads, ["a.hex", "b.hex"])
        self.assertFalse(args.all)
        self.assertFalse(args.outbox)
        self.assertFalse(args.sent)

    def test_publish_outbox_flag(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "--outbox", "--node", NODE_HEX])
        self.assertTrue(args.outbox)
        self.assertFalse(args.sent)
        self.assertFalse(args.all)

    def test_publish_sent_flag(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "--sent", "--node", NODE_HEX])
        self.assertTrue(args.sent)
        self.assertFalse(args.outbox)
        self.assertFalse(args.all)

    def test_publish_all_flag(self):
        parser = build_parser()
        args = parser.parse_args(["publish", "--all", "--node", NODE_HEX])
        self.assertTrue(args.all)

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
# `dacar prune` drops stale outbox + sent box entries (docs #8/#11)
# ===========================================================================


class _BackdatedDeltaMixin:
    """Helper to build signed deltas with a backdated HLC physical component."""

    def _backdated_delta(self, *, ms: int, object_id: str = "old:thing") -> bytes:
        config = self.store.load_config()
        identity = self.store.load_identity()
        hasher = NamespaceHasher(config.primary_salt)
        tup = Tuple.from_plaintext(
            object_id=object_id, relation="read",
            grantee=bytes.fromhex(BERGIE_HASH), issuer=identity.hash, hasher=hasher,
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=pack(ms, 0)).sign(identity.sig_prv)
        return op.to_payload()


class PruneOutboxTest(_BackdatedDeltaMixin, unittest.TestCase):
    """``prune`` drops outbox entries older than the §9 horizon (doc #8 #2)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-pruneob-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

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


class PruneSentTest(_BackdatedDeltaMixin, unittest.TestCase):
    """``prune`` drops sent-box entries older than the §9 horizon (doc #11)."""

    def setUp(self) -> None:
        self.store_dir = Path(tempfile.mkdtemp(prefix="dacar-prunesent-"))
        Store.init(self.store_dir, salt=SALT)
        self.store = Store(self.store_dir)

    def test_stale_sent_entry_dropped_on_prune(self):
        """A sent-box delta older than the horizon is dropped by `prune`."""
        from dacar.config import DEFAULT_DELETION_HORIZON_DAYS
        horizon_ms = DEFAULT_DELETION_HORIZON_DAYS * 24 * 3600 * 1000
        old_ms = physical_now_ms() - horizon_ms - 86_400_000
        fresh_ms = physical_now_ms()

        self.store.save_sent([
            self._backdated_delta(ms=old_ms, object_id="old:thing"),
            self._backdated_delta(ms=fresh_ms, object_id="new:thing"),
        ])
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)
        self.assertIn("sent: pruned 1", err)
        self.assertEqual(len(self.store.load_sent()), 1)  # only the fresh one remains

    def test_fresh_sent_entries_kept_on_prune(self):
        """Fresh sent-box entries are not touched by `prune`."""
        self.store.save_sent([self._backdated_delta(ms=physical_now_ms())])
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)
        self.assertNotIn("sent: pruned", err)
        self.assertEqual(len(self.store.load_sent()), 1)

    def test_empty_sent_prune_no_error(self):
        """`prune` on a store with no sent file is a no-op (no crash)."""
        self.assertFalse(self.store.sent_path.exists())
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)

    def test_prune_drops_both_outbox_and_sent(self):
        """`prune` bounds both stores by the same §9 horizon."""
        from dacar.config import DEFAULT_DELETION_HORIZON_DAYS
        horizon_ms = DEFAULT_DELETION_HORIZON_DAYS * 24 * 3600 * 1000
        old_ms = physical_now_ms() - horizon_ms - 86_400_000

        self.store.save_outbox([self._backdated_delta(ms=old_ms, object_id="ob:old")])
        self.store.save_sent([self._backdated_delta(ms=old_ms, object_id="sent:old")])
        code, _, err = run(self.store_dir, "prune")
        self.assertEqual(code, 0, err)
        self.assertIn("outbox: pruned 1", err)
        self.assertIn("sent: pruned 1", err)
        self.assertEqual(len(self.store.load_outbox()), 0)
        self.assertEqual(len(self.store.load_sent()), 0)


if __name__ == "__main__":
    unittest.main()
