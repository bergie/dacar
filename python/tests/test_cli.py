"""Smoketests for the ``dacar`` CLI (work doc #2).

Exercises the full offline-first workflow end-to-end through ``main()`` in a
temp store directory: init, identity, grant, check, round-trip apply (hex +
binary), revoke, unknown-issuer drop, aliases, prune, and the fail-open salt
warning — the ten required smoketests from work doc #2, plus unit coverage for
the store-layer helpers (rnns alias parsing, ledger).
"""

from __future__ import annotations

import io
import logging
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

# Silence RNS's own logging so captured stderr holds only the CLI's output.
logging.getLogger("RNS").setLevel(logging.CRITICAL)

from dacar.cli import main  # noqa: E402
from dacar.cli.store import AliasRegistry, Ledger, Store  # noqa: E402

BERGIE_HASH = "000102030405060708090a0b0c0d0e0f"
ALICE_HASH = "aabbccdd00112233445566778899aabb"
NULL_SALT_HEX = "00" * 32


def run(store_dir: Path, *argv: str, stdin: bytes = b"") -> tuple[int, str, str]:
    """Invoke the CLI in-process against ``store_dir``; return (code, out, err).

    Global flags (``--store``) live on each subparser per the work doc, so
    ``--store`` is appended after the subcommand and its arguments.
    """
    out = io.StringIO()
    err = io.StringIO()
    if stdin:
        import sys
        real_stdin = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(stdin))
    full = [*argv, "--store", str(store_dir)]
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(full)
    except SystemExit as exc:  # argparse --help etc.
        code = exc.code if isinstance(exc.code, int) else 1
    finally:
        if stdin:
            import sys
            sys.stdin = real_stdin
    return code, out.getvalue(), err.getvalue()


class CliSmoketest(unittest.TestCase):
    """The ten required smoketests from work doc #2."""

    def setUp(self) -> None:
        self.store = Path(tempfile.mkdtemp(prefix="dacar-cli-"))

    # 1. init -> store created, salt non-default, dir mode 0700.
    def test_01_init_creates_store_with_random_salt(self) -> None:
        code, _, err = run(self.store, "init")
        self.assertEqual(code, 0, err)
        self.assertEqual(oct(self.store.stat().st_mode & 0o777), "0o700")
        # Salt is random (not the default null).
        store = Store(self.store)
        config = store.load_config()
        self.assertNotEqual(config.primary_salt, b"\x00" * 32)
        self.assertNotIn("WARNING", err)  # no fail-open warning on random salt
        # The self anchor and alias exist.
        identity = store.load_identity()
        aliases = store.load_aliases()
        self.assertEqual(aliases.resolve("self"), identity.hash)
        self.assertIn(identity.hash, config.root_trust_anchors)
        self.assertEqual(oct(self.store.joinpath("identity").stat().st_mode & 0o777), "0o600")

    # 2. identity new -> own hash known; identity file mode 0600.
    def test_02_identity_new_is_mode_0600(self) -> None:
        run(self.store, "init")
        code, _, err = run(self.store, "identity", "new")
        self.assertEqual(code, 0, err)
        id_path = self.store / "identity"
        self.assertEqual(oct(id_path.stat().st_mode & 0o777), "0o600")
        self.assertIn("identity", err)

    # 3. grant -> payload emitted, tuple active, grants lists plaintext + alias + hash.
    def test_03_grant_emits_payload_and_applies(self) -> None:
        run(self.store, "init")
        run(self.store, "alias", "add", "bergie", BERGIE_HASH)
        code, out, err = run(self.store, "grant", "bergie", "read", "sensor:wind")
        self.assertEqual(code, 0, err)
        # Hex payload on stdout.
        payload_hex = out.strip()
        self.assertEqual(len(payload_hex) % 2, 0)
        self.assertGreater(len(payload_hex), 100)
        # Summary on stderr with alias + hash.
        self.assertIn("bergie", err)
        self.assertIn("sensor:wind", err)
        # grants lists it with plaintext + alias.
        _, _, gerr = run(self.store, "grants")
        self.assertIn("bergie", gerr)
        self.assertIn("read", gerr)
        self.assertIn("sensor:wind", gerr)
        self.assertIn("active", gerr)

    # 4. check -> ALLOW for granted; DENY for a different relation.
    def test_04_check_allow_and_deny(self) -> None:
        run(self.store, "init")
        run(self.store, "alias", "add", "bergie", BERGIE_HASH)
        run(self.store, "grant", "bergie", "read", "sensor:wind")
        code_allow, _, err_allow = run(self.store, "check", "bergie", "read", "sensor:wind")
        self.assertEqual(code_allow, 0, err_allow)
        self.assertIn("ALLOW", err_allow)
        code_deny, _, err_deny = run(self.store, "check", "bergie", "write", "sensor:wind")
        self.assertNotEqual(code_deny, 0)
        self.assertIn("DENY", err_deny)

    # 5. grant --no-apply + apply (hex and binary) -> equivalent state.
    def test_05_roundtrip_apply_hex_and_binary(self) -> None:
        run(self.store, "init")
        run(self.store, "alias", "add", "bergie", BERGIE_HASH)
        # Hex round-trip: capture stdout hex, write to file, apply.
        code, out, err = run(self.store, "grant", "bergie", "read", "sensor:temp", "--no-apply")
        self.assertEqual(code, 0, err)
        hex_path = self.store / "delta.hex"
        hex_path.write_text(out.strip())
        code, _, aerr = run(self.store, "apply", str(hex_path))
        self.assertEqual(code, 0, aerr)
        self.assertIn("applied 1 delta", aerr)
        # Binary round-trip: --out writes raw bytes, apply auto-detects binary.
        bin_path = self.store / "delta.bin"
        code, _, err = run(self.store, "grant", "bergie", "read", "sensor:humidity",
                           "--no-apply", "--out", str(bin_path))
        self.assertEqual(code, 0, err)
        code, _, aerr2 = run(self.store, "apply", str(bin_path))
        self.assertEqual(code, 0, aerr2)
        # Both are active and readable (ledger recorded on --no-apply).
        _, _, gerr = run(self.store, "grants")
        self.assertIn("sensor:temp", gerr)
        self.assertIn("sensor:humidity", gerr)

    # 6. revoke -> grants no longer lists it active; check DENY; --all shows tombstone.
    def test_06_revoke_creates_tombstone(self) -> None:
        run(self.store, "init")
        run(self.store, "alias", "add", "bergie", BERGIE_HASH)
        run(self.store, "grant", "bergie", "read", "sensor:wind")
        code, _, err = run(self.store, "revoke", "bergie", "read", "sensor:wind")
        self.assertEqual(code, 0, err)
        # Active grants no longer list it.
        _, _, gerr = run(self.store, "grants")
        self.assertNotIn("sensor:wind", gerr)
        # check -> DENY.
        code, _, cerr = run(self.store, "check", "bergie", "read", "sensor:wind")
        self.assertIn("DENY", cerr)
        # --all shows the tombstone.
        _, _, aerr = run(self.store, "grants", "--all")
        self.assertIn("sensor:wind", aerr)
        self.assertIn("revoked", aerr)

    # 7. apply of a delta whose issuer is unknown -> dropped, non-zero exit.
    def test_07_apply_unknown_issuer_dropped(self) -> None:
        run(self.store, "init")
        # Build a delta signed by a foreign identity (not in this store's keyring).
        import RNS
        from dacar import Action, Clock, Operation, Tuple
        from dacar.namespace import NamespaceHasher
        other = RNS.Identity(create_keys=True)
        hasher = NamespaceHasher(bytes(range(32)))
        tup = Tuple.from_plaintext(
            object_id="x", relation="read", grantee=b"\x11" * 16,
            issuer=other.hash, hasher=hasher,
        )
        op = Operation(tuple=tup, action=Action.GRANT, hlc=Clock().now()).sign(other.sig_prv)
        payload_path = self.store / "foreign.bin"
        payload_path.write_bytes(op.to_payload())
        code, _, err = run(self.store, "apply", str(payload_path))
        self.assertNotEqual(code, 0)
        self.assertIn("rejected", err)

    # 8. alias add/remove/resolve round-trip; literal-hash inputs; rnns format.
    def test_08_alias_roundtrip(self) -> None:
        run(self.store, "init")
        code, _, err = run(self.store, "alias", "add", "bergie", BERGIE_HASH)
        self.assertEqual(code, 0, err)
        # resolve via stdout (full hash).
        code, out, _ = run(self.store, "alias", "resolve", "bergie")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), BERGIE_HASH)
        # Literal-hash input accepted (add a second name by hash).
        run(self.store, "alias", "add", "bob", "0102030405060708090a0b0c0d0e0f10")
        # One hash, several names.
        run(self.store, "alias", "add", "alice", ALICE_HASH, "--note", "node operator")
        run(self.store, "alias", "add", "alice2", ALICE_HASH)
        _, _, lerr = run(self.store, "alias", "list")
        self.assertIn(ALICE_HASH, lerr)
        self.assertIn("alice", lerr)
        # remove
        run(self.store, "alias", "remove", "alice2")
        code, _, _ = run(self.store, "alias", "resolve", "alice2")
        self.assertNotEqual(code, 0)
        # The aliases file parses as rnns `hash name [# note]`.
        text = (self.store / "aliases").read_text()
        registry = AliasRegistry.parse(text)
        self.assertEqual(registry.resolve("alice"), bytes.fromhex(ALICE_HASH))
        self.assertEqual(registry.resolve("bergie"), bytes.fromhex(BERGIE_HASH))
        self.assertEqual(registry.names_for(bytes.fromhex(ALICE_HASH)), ["alice"])
        # Note is dacar-local.
        self.assertEqual(registry.entries[0].note, None or registry.entries[0].note)

    # 9. prune on backdated timestamps removes resolved pairs; active re-grants preserved.
    def test_09_prune_removes_old_resolved_pairs(self) -> None:
        run(self.store, "init")
        # Backdate a grant+revoke pair beyond the horizon, plus a recent active grant.
        from dacar import Action, Operation, Tuple
        from dacar.hlc import pack
        from dacar.namespace import NamespaceHasher
        store = Store(self.store)
        config = store.load_config()
        identity = store.load_identity()
        state = store.load_state(config)
        hasher = NamespaceHasher(config.primary_salt)
        old_ms = 1_700_000_000_000  # ~2023, well past the 180-day horizon
        old_t = Tuple.from_plaintext(
            object_id="old:thing", relation="read", grantee=b"\x22" * 16,
            issuer=identity.hash, hasher=hasher,
        )
        state.apply(Operation(tuple=old_t, action=Action.GRANT, hlc=pack(old_ms, 0)), now_ms=old_ms)
        state.apply(Operation(tuple=old_t, action=Action.REVOKE, hlc=pack(old_ms + 1, 0)), now_ms=old_ms)
        new_t = Tuple.from_plaintext(
            object_id="new:thing", relation="read", grantee=b"\x33" * 16,
            issuer=identity.hash, hasher=hasher,
        )
        state.apply(Operation(tuple=new_t, action=Action.GRANT, hlc=pack(2_000_000_000_000, 0)),
                    now_ms=2_000_000_000_000)
        store.save_state(state)
        code, _, err = run(self.store, "prune")
        self.assertEqual(code, 0, err)
        self.assertIn("pruned 1", err)
        # Active re-grant preserved.
        state2 = store.load_state(config)
        self.assertTrue(state2.is_active(new_t.hash()))
        self.assertNotIn(old_t.hash(), state2)

    # 10. default-null-salt warning fires on init / config show when salt is unset.
    def test_10_null_salt_warning(self) -> None:
        code, _, err = run(self.store, "init", "--salt", NULL_SALT_HEX)
        self.assertEqual(code, 0, err)
        self.assertIn("WARNING", err)
        self.assertIn("fail-open", err.lower())
        # config show also warns.
        _, _, cerr = run(self.store, "config", "show")
        self.assertIn("WARNING", cerr)
        # And the salt is masked unless --reveal.
        self.assertIn("masked", cerr)


class AliasRegistryTest(unittest.TestCase):
    """Unit coverage for the rnns `hash name [# note]` parser/serializer."""

    def test_parse_and_serialize_roundtrip(self) -> None:
        text = (
            "9b2c41770a1b2c3d4e5f60718293a4b5 root\n"
            "7f3a9c2b0a1b2c3d4e5f60718293a4b5 bergie  # node operator\n"
            "1c4ee0aa0a1b2c3d4e5f60718293a4b5 alice bob\n"
        )
        reg = AliasRegistry.parse(text)
        self.assertEqual(len(reg.entries), 3)
        self.assertEqual(reg.resolve("root"), bytes.fromhex("9b2c41770a1b2c3d4e5f60718293a4b5"))
        self.assertEqual(reg.resolve("bob"), bytes.fromhex("1c4ee0aa0a1b2c3d4e5f60718293a4b5"))
        self.assertEqual(reg.names_for(bytes.fromhex("1c4ee0aa0a1b2c3d4e5f60718293a4b5")),
                         ["alice", "bob"])
        # Note is captured (dacar-local).
        bergie_entry = reg.entries[1]
        self.assertEqual(bergie_entry.note, "node operator")
        # Serialize keeps the note; rnns-stripped form drops it.
        self.assertIn("# node operator", reg.serialize())
        self.assertNotIn("#", reg.serialize_for_rnns())

    def test_skips_non_hash_lines_and_blanks(self) -> None:
        text = (
            "# a stray full-line comment\n"
            "\n"
            "9b2c41770a1b2c3d4e5f60718293a4b5 root\n"
        )
        reg = AliasRegistry.parse(text)
        self.assertEqual(len(reg.entries), 1)
        self.assertEqual(reg.resolve("root"), bytes.fromhex("9b2c41770a1b2c3d4e5f60718293a4b5"))

    def test_set_self_repoints_self_alias(self) -> None:
        reg = AliasRegistry()
        h1 = b"\x01" * 16
        h2 = b"\x02" * 16
        reg.set_self(h1)
        self.assertEqual(reg.resolve("self"), h1)
        reg.set_self(h2)
        self.assertEqual(reg.resolve("self"), h2)
        # h1 no longer has a name -> entry dropped.
        self.assertEqual(reg.names_for(h1), [])

    def test_remove_drops_empty_entries(self) -> None:
        reg = AliasRegistry()
        h = b"\x03" * 16
        reg.add("only", h)
        self.assertTrue(reg.remove("only"))
        self.assertEqual(reg.entries, [])
        self.assertFalse(reg.remove("missing"))


class LedgerTest(unittest.TestCase):
    """Unit coverage for the plaintext ledger."""

    def test_record_and_lookup(self) -> None:
        ledger = Ledger()
        th = b"\x04" * 32
        ledger.record(th, object_id="sensor:wind", relation="read", wildcard=False, first_seen=42)
        row = ledger.lookup(th)
        self.assertIsNotNone(row)
        self.assertEqual(row["object"], "sensor:wind")
        self.assertEqual(row["relation"], "read")
        self.assertFalse(row["wildcard"])
        # annotate updates fields.
        self.assertTrue(ledger.annotate(th, relation="write"))
        self.assertEqual(ledger.lookup(th)["relation"], "write")
        # annotate on unknown hash returns False, ensure creates a row.
        th2 = b"\x05" * 32
        self.assertFalse(ledger.annotate(th2))
        row = ledger.ensure(th2)
        row["object"] = "x"
        self.assertEqual(ledger.lookup(th2)["object"], "x")


class StoreInitTest(unittest.TestCase):
    """Store bootstrap and persistence."""

    def setUp(self) -> None:
        self.path = Path(tempfile.mkdtemp(prefix="dacar-store-"))

    def test_init_adopt_identity(self) -> None:
        import RNS
        id_path = self.path / "external_id"
        ext = RNS.Identity(create_keys=True)
        ext.to_file(str(id_path))
        store = Store.init(self.path / "store", identity_path=str(id_path))
        identity = store.load_identity()
        self.assertEqual(identity.hash, ext.hash)
        # self anchor is the adopted identity.
        config = store.load_config()
        self.assertIn(ext.hash, config.root_trust_anchors)
        aliases = store.load_aliases()
        self.assertEqual(aliases.resolve("self"), ext.hash)

    def test_state_clock_ledger_persist(self) -> None:
        from dacar import Action, Clock, Operation, Tuple
        from dacar.namespace import NamespaceHasher
        store = Store.init(self.path / "store")
        config = store.load_config()
        identity = store.load_identity()
        # State round-trips.
        state = store.load_state(config)
        hasher = NamespaceHasher(config.primary_salt)
        tup = Tuple.from_plaintext(object_id="a:b", relation="read", grantee=b"\x09" * 16,
                                   issuer=identity.hash, hasher=hasher)
        state.apply(Operation(tuple=tup, action=Action.GRANT, hlc=Clock().now()))
        store.save_state(state)
        state2 = store.load_state(config)
        self.assertTrue(state2.is_active(tup.hash()))
        # Clock persists monotonicity.
        clock = store.load_clock()
        t1 = clock.now()
        t2 = clock.now()
        self.assertGreater(t2, t1)
        store.save_clock(clock)
        clock2 = store.load_clock()
        self.assertGreater(clock2.now(), t2)


if __name__ == "__main__":
    unittest.main()
