"""The ``dacar`` command-line tool (work doc #2).

An offline-first, daemon-free CLI for managing Dacar authorization grants:
issue signed Grant/Revoke operations, ingest received deltas (verify-on-ingest),
evaluate permissions locally, and inspect the CRDT state. Built on the
``dacar`` Python library.

Offline commands never start ``RNS.Reticulum`` — only ``RNS.Identity`` is used
for key load/create. The verify-on-ingest keyring resolves the node's own
identity (and any ``--identity PATH``); unknown issuers are dropped (§11.2.4).

Usage::

    dacar init
    dacar grant bergie read sensor:wind
    dacar check bergie read sensor:wind
    dacar grants
    dacar revoke bergie read sensor:wind
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from dacar.config import DEFAULT_DELETION_HORIZON_DAYS
from dacar.naming import RFED_TOPIC
from dacar.namespace import MAX_LEGACY_SALTS

from dacar.cli.commands import CliError, EXIT_FAIL, EXIT_OK
from dacar.cli.store import StoreError

__all__ = ["main", "build_parser"]

#: Default store directory (overridable via ``--store`` or ``$DACAR_HOME``).
DEFAULT_STORE = "~/.dacar"


def _default_store() -> str:
    return os.environ.get("DACAR_HOME", DEFAULT_STORE)


def _add_global_flags(parser: argparse.ArgumentParser) -> None:
    """Global flags available on every mutating/querying command."""
    parser.add_argument("--store", default=None,
                        help="store directory (default: $DACAR_HOME or ~/.dacar)")
    parser.add_argument("--identity", default=None,
                        help="path to an RNS Identity file overriding the signing identity")
    parser.add_argument("-v", "--full-hashes", action="store_true",
                        help="show full 32-hex identity hashes instead of short prefixes")


def _add_online_flags(parser: argparse.ArgumentParser) -> None:
    """Flags for online commands (grant --publish, sync) that open RNS."""
    parser.add_argument("--node", default=None,
                        help="rfed node identity hash or alias (default: [rfed] node in config)")
    parser.add_argument("--topic", default=None,
                        help=f"rfed channel topic (default: {RFED_TOPIC!r} or [rfed] topic in config)")
    parser.add_argument("--rns-config", default=None,
                        help="RNS config directory (default: ~/.reticulum or $DACAR_RNS_CONFIG)")


def _store_path(args) -> str:
    return os.path.expanduser(args.store if args.store else _default_store())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dacar",
        description="Offline-first Dacar grant management (issue, apply, check, inspect).",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    # -- init ---------------------------------------------------------------
    p = sub.add_parser("init", help="bootstrap a node store")
    p.add_argument("--salt", default=None,
                   help="primary salt as 64-hex or a path to a 32-byte file (default: random)")
    p.add_argument("--horizon", type=int, default=DEFAULT_DELETION_HORIZON_DAYS,
                   help=f"deletion horizon in days (default: {DEFAULT_DELETION_HORIZON_DAYS})")
    _add_global_flags(p)
    p.set_defaults(func=_cmd_init)

    # -- config -------------------------------------------------------------
    p = sub.add_parser("config", help="show node configuration")
    config_sub = p.add_subparsers(dest="config_command", metavar="<subcommand>", required=True)
    pc = config_sub.add_parser("show", help="show config (salt masked unless --reveal)")
    pc.add_argument("--reveal", action="store_true", help="reveal the privacy salt")
    _add_global_flags(pc)
    pc.set_defaults(func=_cmd_config_show)

    # -- salt ---------------------------------------------------------------
    p = sub.add_parser("salt", help="manage the Privacy Salt")
    salt_sub = p.add_subparsers(dest="salt_command", metavar="<subcommand>", required=True)
    pn = salt_sub.add_parser("new", help="generate a new random primary salt (§10.2 rotation)")
    _add_global_flags(pn)
    pn.set_defaults(func=_cmd_salt_new)
    ps = salt_sub.add_parser("set", help="set the primary salt explicitly")
    ps.add_argument("--hex", default=None, help="salt as 64 hex characters")
    ps.add_argument("--file", default=None, help="path to a 32-byte salt file")
    _add_global_flags(ps)
    ps.set_defaults(func=_cmd_salt_set)

    # -- anchor -------------------------------------------------------------
    p = sub.add_parser("anchor", help="manage Root Trust Anchors")
    anchor_sub = p.add_subparsers(dest="anchor_command", metavar="<subcommand>", required=True)
    pa = anchor_sub.add_parser("add", help="add a Root Trust Anchor")
    pa.add_argument("hash", help="anchor identity hash or alias")
    _add_global_flags(pa)
    pa.set_defaults(func=_cmd_anchor_add)
    pl = anchor_sub.add_parser("list", help="list Root Trust Anchors")
    _add_global_flags(pl)
    pl.set_defaults(func=_cmd_anchor_list)

    # -- identity -----------------------------------------------------------
    p = sub.add_parser("identity", help="manage the signing identity")
    idn_sub = p.add_subparsers(dest="identity_command", metavar="<subcommand>", required=True)
    pi = idn_sub.add_parser("show", help="show the signing identity hash + aliases")
    _add_global_flags(pi)
    pi.set_defaults(func=_cmd_identity_show)
    pn = idn_sub.add_parser("new", help="generate a fresh RNS Identity (rotates the self-anchor)")
    _add_global_flags(pn)
    pn.set_defaults(func=_cmd_identity_new)
    pr = idn_sub.add_parser("remember", help="seed an issuer pubkey into the durable cache (work doc #5)")
    pr.add_argument("hash", help="issuer identity hash or alias")
    pr.add_argument("--pubkey", default=None, help="32-byte Ed25519 public key as 64 hex chars")
    pr.add_argument("--file", default=None, help="path to a 32-byte raw public key file")
    _add_global_flags(pr)
    pr.set_defaults(func=_cmd_identity_remember)
    pf = idn_sub.add_parser("forget", help="remove an issuer from the durable cache (work doc #5)")
    pf.add_argument("hash", help="issuer identity hash or alias")
    pf.add_argument("--force", action="store_true",
                    help="purge even if the issuer has active grants in the CRDT (may strand them)")
    _add_global_flags(pf)
    pf.set_defaults(func=_cmd_identity_forget)
    pl = idn_sub.add_parser("list", help="list the durable issuer identity cache (work doc #5)")
    _add_global_flags(pl)
    pl.set_defaults(func=_cmd_identity_list)

    # -- grant / revoke -----------------------------------------------------
    for name, verb in (("grant", "issue a signed Grant"), ("revoke", "issue a signed Revoke")):
        p = sub.add_parser(name, help=verb)
        p.add_argument("grantee", help="grantee identity hash or alias")
        p.add_argument("relation", nargs="?", default=None,
                       help="relation plaintext (e.g. read, admin, -read to deny)")
        p.add_argument("object", nargs="?", default=None,
                       help="object plaintext (e.g. sensor:wind; trailing * = wildcard)")
        p.add_argument("--no-apply", action="store_true",
                       help="sign and export only; do not merge into the local CRDT")
        p.add_argument("-o", "--out", default=None,
                       help="write the binary payload to this file instead of stdout")
        p.add_argument("--binary", action="store_true",
                       help="emit the payload as raw bytes on stdout (default: hex)")
        p.add_argument("--legacy", type=int, default=None,
                       help=f"use legacy salt index 0-{MAX_LEGACY_SALTS - 1} (§10.3)")
        p.add_argument("--copy-hashes", default=None,
                       help="revoke by exact pre-hashed tuple fields from a file (no salt)")
        p.add_argument("--publish", action="store_true",
                       help="publish the signed Delta to the rfed channel (online, §11.1)")
        _add_online_flags(p)
        _add_global_flags(p)
        p.set_defaults(func=_cmd_grant if name == "grant" else _cmd_revoke)

    # -- sync ---------------------------------------------------------------
    p = sub.add_parser("sync", help="pull pending Deltas from the rfed channel (online, §11.1)")
    _add_online_flags(p)
    _add_global_flags(p)
    p.set_defaults(func=_cmd_sync)

    # -- apply --------------------------------------------------------------
    p = sub.add_parser("apply", help="ingest a received delta payload (verify-on-ingest)")
    p.add_argument("payload", help="payload file path, or - for stdin (hex or binary)")
    p.add_argument("--binary", action="store_true", help="treat input as raw binary (skip hex auto-detect)")
    _add_global_flags(p)
    p.set_defaults(func=_cmd_apply)

    # -- check --------------------------------------------------------------
    p = sub.add_parser("check", help="evaluate a permission locally (ALLOW/DENY)")
    p.add_argument("grantee", help="grantee identity hash or alias")
    p.add_argument("relation", help="relation plaintext")
    p.add_argument("object", help="object plaintext (e.g. sensor:wind)")
    _add_global_flags(p)
    p.set_defaults(func=_cmd_check)

    # -- grants -------------------------------------------------------------
    p = sub.add_parser("grants", help="list grants in the local CRDT")
    p.add_argument("--all", action="store_true", help="include revoked tombstones")
    p.add_argument("--revoked", action="store_true", help="only revoked tombstones")
    p.add_argument("--grantee", default=None, help="filter by grantee alias or hash")
    p.add_argument("--issuer", default=None, help="filter by issuer alias or hash")
    p.add_argument("--effective", action="store_true",
                   help="annotate each row ✔/⚠ whether the issuer's authority traces to an anchor")
    _add_global_flags(p)
    p.set_defaults(func=_cmd_grants)

    # -- show ---------------------------------------------------------------
    p = sub.add_parser("show", help="show full detail for one tuple")
    p.add_argument("ref", help="64-hex tuple hash, or <alias>:<relation>:<object>")
    _add_global_flags(p)
    p.set_defaults(func=_cmd_show)

    # -- prune --------------------------------------------------------------
    p = sub.add_parser("prune", help="run §9 Time-Horizon Tombstone Pruning")
    _add_global_flags(p)
    p.set_defaults(func=_cmd_prune)

    # -- alias --------------------------------------------------------------
    p = sub.add_parser("alias", help="manage identity aliases (rnns hash name)")
    alias_sub = p.add_subparsers(dest="alias_command", metavar="<subcommand>", required=True)
    pa = alias_sub.add_parser("add", help="add a name for an identity hash")
    pa.add_argument("name", help="alias name")
    pa.add_argument("hash", help="identity hash (16-byte/32-hex) or existing alias")
    pa.add_argument("--note", default=None, help="optional dacar-local note")
    _add_global_flags(pa)
    pa.set_defaults(func=_cmd_alias_add)
    pr = alias_sub.add_parser("remove", help="remove an alias name")
    pr.add_argument("name", help="alias name to remove")
    _add_global_flags(pr)
    pr.set_defaults(func=_cmd_alias_remove)
    pl = alias_sub.add_parser("list", help="list all aliases")
    _add_global_flags(pl)
    pl.set_defaults(func=_cmd_alias_list)
    pr = alias_sub.add_parser("resolve", help="print the hash for an alias name")
    pr.add_argument("name", help="alias name")
    _add_global_flags(pr)
    pr.set_defaults(func=_cmd_alias_resolve)

    # -- ledger -------------------------------------------------------------
    p = sub.add_parser("ledger", help="manage the plaintext ledger")
    ledger_sub = p.add_subparsers(dest="ledger_command", metavar="<subcommand>", required=True)
    pa = ledger_sub.add_parser("annotate", help="annotate an opaque tuple's plaintext")
    pa.add_argument("tuple_hash", help="64-hex tuple hash")
    pa.add_argument("--object", default=None, help="object plaintext")
    pa.add_argument("--relation", default=None, help="relation plaintext")
    _add_global_flags(pa)
    pa.set_defaults(func=_cmd_ledger_annotate)

    return parser


# -- thin wrappers that resolve --store then dispatch to commands.py ---------


def _cmd_init(args):
    from dacar.cli.commands import cmd_init
    args.store = _store_path(args)
    return cmd_init(args)


def _cmd_config_show(args):
    from dacar.cli.commands import cmd_config_show
    args.store = _store_path(args)
    return cmd_config_show(args)


def _cmd_salt_new(args):
    from dacar.cli.commands import cmd_salt_new
    args.store = _store_path(args)
    return cmd_salt_new(args)


def _cmd_salt_set(args):
    from dacar.cli.commands import cmd_salt_set
    args.store = _store_path(args)
    return cmd_salt_set(args)


def _cmd_anchor_add(args):
    from dacar.cli.commands import cmd_anchor_add
    args.store = _store_path(args)
    return cmd_anchor_add(args)


def _cmd_anchor_list(args):
    from dacar.cli.commands import cmd_anchor_list
    args.store = _store_path(args)
    return cmd_anchor_list(args)


def _cmd_identity_show(args):
    from dacar.cli.commands import cmd_identity_show
    args.store = _store_path(args)
    return cmd_identity_show(args)


def _cmd_identity_new(args):
    from dacar.cli.commands import cmd_identity_new
    args.store = _store_path(args)
    return cmd_identity_new(args)


def _cmd_identity_remember(args):
    from dacar.cli.commands import cmd_identity_remember
    args.store = _store_path(args)
    return cmd_identity_remember(args)


def _cmd_identity_forget(args):
    from dacar.cli.commands import cmd_identity_forget
    args.store = _store_path(args)
    return cmd_identity_forget(args)


def _cmd_identity_list(args):
    from dacar.cli.commands import cmd_identity_list
    args.store = _store_path(args)
    return cmd_identity_list(args)


def _cmd_grant(args):
    from dacar.cli.commands import cmd_grant
    args.store = _store_path(args)
    return cmd_grant(args)


def _cmd_revoke(args):
    from dacar.cli.commands import cmd_revoke
    args.store = _store_path(args)
    return cmd_revoke(args)


def _cmd_apply(args):
    from dacar.cli.commands import cmd_apply
    args.store = _store_path(args)
    return cmd_apply(args)


def _cmd_check(args):
    from dacar.cli.commands import cmd_check
    args.store = _store_path(args)
    return cmd_check(args)


def _cmd_grants(args):
    from dacar.cli.commands import cmd_grants
    args.store = _store_path(args)
    return cmd_grants(args)


def _cmd_show(args):
    from dacar.cli.commands import cmd_show
    args.store = _store_path(args)
    return cmd_show(args)


def _cmd_prune(args):
    from dacar.cli.commands import cmd_prune
    args.store = _store_path(args)
    return cmd_prune(args)


def _cmd_alias_add(args):
    from dacar.cli.commands import cmd_alias_add
    args.store = _store_path(args)
    return cmd_alias_add(args)


def _cmd_alias_remove(args):
    from dacar.cli.commands import cmd_alias_remove
    args.store = _store_path(args)
    return cmd_alias_remove(args)


def _cmd_alias_list(args):
    from dacar.cli.commands import cmd_alias_list
    args.store = _store_path(args)
    return cmd_alias_list(args)


def _cmd_alias_resolve(args):
    from dacar.cli.commands import cmd_alias_resolve
    args.store = _store_path(args)
    return cmd_alias_resolve(args)


def _cmd_ledger_annotate(args):
    from dacar.cli.commands import cmd_ledger_annotate
    args.store = _store_path(args)
    return cmd_ledger_annotate(args)


def _cmd_sync(args):
    from dacar.cli.commands import cmd_sync
    args.store = _store_path(args)
    return cmd_sync(args)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CliError, StoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except BrokenPipeError:
        return EXIT_OK
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
