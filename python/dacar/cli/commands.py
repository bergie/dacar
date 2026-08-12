"""Command implementations for the ``dacar`` CLI (work doc #2).

Each ``cmd_*`` function takes the parsed argparse namespace, performs its work
against a :class:`~dacar.cli.store.Store`, prints a human summary on **stderr**
(and payload/data on **stdout**), and returns a process exit code. A
:class:`CliError` is raised for expected, recoverable failures (unknown alias,
rejected delta, etc.); :func:`dacar.cli.main` reports it and exits non-zero.

Output convention (work doc #2): every resolved identity is rendered as
``<alias> (<short-hash>…)``; with ``-v`` the full 32-hex hash is shown. Hashes
are authoritative; aliases are convenience only.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple as _Tuple

from dacar import Action, Engine, Operation, Tuple
from dacar.delta import DeltaReceiver
from dacar.hlc import unpack, physical_now_ms
from dacar.naming import RFED_TOPIC
from dacar.namespace import DEFAULT_SALT, covers

from dacar.cli.store import (
    AliasRegistry,
    Store,
    _generate_salt,
    _parse_salt_value,
)

#: Inline short-hash prefix length (open item: proposed 7 hex chars).
SHORT_HASH_HEX = 7

#: Exit codes.
EXIT_OK = 0
EXIT_FAIL = 1


class CliError(Exception):
    """An expected, recoverable CLI failure (reported, non-zero exit)."""


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _short(hash_bytes: bytes, full: bool = False) -> str:
    if full:
        return hash_bytes.hex()
    return hash_bytes.hex()[:SHORT_HASH_HEX] + "…"


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _utc(hlc: int) -> str:
    """Render an HLC's physical component as a UTC timestamp."""
    if not hlc:
        return "-"
    ms, _ = unpack(hlc)
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def resolve_identity(value: str, aliases: AliasRegistry) -> bytes:
    """Resolve an alias or 16-byte (32-hex) hash to a 16-byte identity hash."""
    h = aliases.resolve(value)
    if h is not None:
        return h
    candidate = value.strip().lower()
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    try:
        raw = bytes.fromhex(candidate)
    except ValueError:
        raise CliError(
            f"unknown identity {value!r} (not a known alias or 16-byte hex hash)"
        ) from None
    if len(raw) != 16:
        raise CliError(
            f"identity {value!r} is {len(raw)} bytes; expected 16 (32 hex)"
        )
    return raw


def render_identity(hash_bytes: bytes, aliases: AliasRegistry, *, full: bool = False) -> str:
    """Render ``<alias> (<short-hash>…)`` or ``? (<short-hash>…)``."""
    name = aliases.primary_name(hash_bytes)
    sh = _short(hash_bytes, full)
    return f"{name} ({sh})" if name else f"? ({sh})"


def render_relation(relation_hash: bytes, ledger_row: Optional[dict], *,
                    full: bool = False) -> str:
    if ledger_row and ledger_row.get("relation"):
        return ledger_row["relation"]
    return f"[{_short(relation_hash, full)}]"


def render_object(object_hashes: _Tuple[bytes, ...], wildcard: bool,
                  ledger_row: Optional[dict], *, full: bool = False) -> str:
    if ledger_row and ledger_row.get("object"):
        text = ledger_row["object"]
        return text
    n = len(object_hashes)
    if n == 0:
        return "[*]" if wildcard else "[∅]"
    head = _short(object_hashes[0], full)
    more = f" · {n} seg" if n > 1 else ""
    return f"[{head}{more}]"


# ---------------------------------------------------------------------------
# Lifecycle / config
# ---------------------------------------------------------------------------


def cmd_init(args) -> int:
    store_path = Path(args.store)
    if store_path.exists() and Store(store_path).exists():
        raise CliError(f"store already initialized at {store_path}")
    salt: Optional[bytes] = None
    salt_provided = args.salt is not None
    if salt_provided:
        salt = _parse_salt_value(args.salt)
        if salt == DEFAULT_SALT:
            _err("WARNING: --salt is the default null salt (§3.3 fail-open on privacy).")
    Store.init(
        store_path,
        salt=salt,
        horizon_days=args.horizon,
        identity_path=args.identity,
    )
    store = Store(store_path, identity_override=args.identity)
    identity = store.load_identity()
    aliases = store.load_aliases()
    config = store.load_config()
    _err(f"✔ initialized store at {store_path}")
    _err(f"  identity : {render_identity(identity.hash, aliases, full=args.full_hashes)}")
    _err(f"  anchor   : {render_identity(identity.hash, aliases, full=args.full_hashes)} (self)")
    _err(f"  salt     : {_short(config.primary_salt, full=args.full_hashes)} "
         f"({'default null — FAIL-OPEN' if config.primary_salt == DEFAULT_SALT else 'random'})")
    _err(f"  horizon  : {config.deletion_horizon_days} days")
    if config.primary_salt == DEFAULT_SALT:
        _err("  WARNING: primary salt is the default null (§3.3 fail-open on privacy).")
    if not salt_provided:
        _err("  WARNING: a unique random salt was generated. Grants will be opaque across")
        _err("           nodes unless they share the same salt (see README).")
    return EXIT_OK


def cmd_config_show(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    raw = store.load_config_raw()
    full = args.full_hashes or args.reveal
    _err(f"store: {store.path}")
    reveal = args.reveal
    salt_display = raw["primary_salt"].hex() if reveal else "<masked (use --reveal)>"
    _err("[salt]")
    _err(f"  primary   : {salt_display}"
         + ("  ⚠ FAIL-OPEN (default null)" if raw["primary_salt"] == DEFAULT_SALT else ""))
    for i, legacy in enumerate(raw["legacy_salts"]):
        _err(f"  legacy{i}   : {legacy.hex() if reveal else '<masked>'}")
    _err("[trust]")
    aliases = store.load_aliases()
    for a in raw["anchors"]:
        _err(f"  anchor    : {render_identity(a, aliases, full=full)}")
    if raw["authoritative"] is not None:
        _err(f"  authoritative : {render_identity(raw['authoritative'], aliases, full=full)}")
    _err("[policy]")
    _err(f"  deletion_horizon_days : {raw['horizon_days']}")
    _err("[rfed]")
    _err(f"  topic : {raw.get('rfed_topic', RFED_TOPIC)}")
    node = raw.get("rfed_node")
    _err(f"  node  : {render_identity(node, aliases, full=full) if node else '(not set)'}")
    _err(f"[aliases] {len(aliases.entries)} entries ({store.aliases_path})")
    if raw["primary_salt"] == DEFAULT_SALT:
        _err("WARNING: primary salt is the default null (§3.3 fail-open on privacy).")
    return EXIT_OK


def cmd_salt_new(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    raw = store.load_config_raw()
    # §10.2 rotation: old primary → legacy0, old legacy0 → legacy1, drop old legacy1.
    new_primary = _generate_salt()
    new_legacy = (raw["primary_salt"],) + raw["legacy_salts"][:1]
    new_legacy = new_legacy[:2]
    store.save_config(
        primary_salt=new_primary,
        legacy_salts=new_legacy,
        anchors=raw["anchors"],
        authoritative=raw["authoritative"],
        horizon_days=raw["horizon_days"],
    )
    _err("✔ rotated primary salt (old primary → legacy0, §10.2)")
    _err(f"  primary : {_short(new_primary, full=args.full_hashes)}"
         + ("  ⚠ FAIL-OPEN" if new_primary == DEFAULT_SALT else ""))
    for i, legacy in enumerate(new_legacy):
        _err(f"  legacy{i}: {_short(legacy, full=args.full_hashes)}")
    return EXIT_OK


def cmd_salt_set(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    raw = store.load_config_raw()
    if args.hex is not None:
        try:
            salt = bytes.fromhex(args.hex)
        except ValueError:
            raise CliError(f"--hex is not valid hex: {args.hex!r}")
    elif args.file is not None:
        with open(args.file, "rb") as fh:
            data = fh.read()
        if len(data) != 32:
            raise CliError(f"salt file must contain 32 bytes, got {len(data)}")
        salt = data
    else:
        raise CliError("salt set requires --hex <hex> or --file <path>")
    if len(salt) != 32:
        raise CliError(f"salt must be 32 bytes, got {len(salt)}")
    store.save_config(
        primary_salt=salt,
        legacy_salts=raw["legacy_salts"],
        anchors=raw["anchors"],
        authoritative=raw["authoritative"],
        horizon_days=raw["horizon_days"],
    )
    _err(f"✔ set primary salt to {_short(salt, full=args.full_hashes)}"
         + ("  ⚠ FAIL-OPEN (default null)" if salt == DEFAULT_SALT else ""))
    return EXIT_OK


def cmd_anchor_add(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    anchor = resolve_identity(args.hash, aliases)
    raw = store.load_config_raw()
    if anchor in raw["anchors"]:
        raise CliError(f"anchor already present: {render_identity(anchor, aliases, full=args.full_hashes)}")
    anchors = list(raw["anchors"])
    anchors.append(anchor)
    store.save_config(
        primary_salt=raw["primary_salt"],
        legacy_salts=raw["legacy_salts"],
        anchors=anchors,
        authoritative=raw["authoritative"],
        horizon_days=raw["horizon_days"],
    )
    _err(f"✔ added anchor {render_identity(anchor, aliases, full=args.full_hashes)}")
    return EXIT_OK


def cmd_anchor_list(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    raw = store.load_config_raw()
    aliases = store.load_aliases()
    if not raw["anchors"]:
        _err("(no Root Trust Anchors configured)")
        return EXIT_OK
    _err(f"ROOT TRUST ANCHORS ({len(raw['anchors'])})")
    for a in raw["anchors"]:
        _err(f"  {render_identity(a, aliases, full=args.full_hashes)}")
    if raw["authoritative"] is not None:
        _err(f"authoritative: {render_identity(raw['authoritative'], aliases, full=args.full_hashes)}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def cmd_identity_show(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    identity = store.load_identity()
    if identity is None:
        raise CliError("no signing identity (run `dacar init` or `dacar identity new`)")
    aliases = store.load_aliases()
    _err(f"identity : {render_identity(identity.hash, aliases, full=args.full_hashes)}")
    if store.identity_override:
        _err(f"  source  : --identity {store.identity_override}")
    else:
        _err(f"  source  : {store.identity_default_path}")
    _err(f"  pubkey  : {identity.sig_pub_bytes.hex()}")
    if aliases.entries:
        _err("aliases  :")
        for entry in aliases.entries:
            _err(f"  {entry.hash.hex()}  {' '.join(entry.names)}"
                 + (f"  # {entry.note}" if entry.note else ""))
    return EXIT_OK


def cmd_identity_new(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    old_hash, new_hash = store.rotate_identity()
    aliases = store.load_aliases()
    _err("✔ generated new signing identity")
    _err(f"  old : {_short(old_hash, full=args.full_hashes) if old_hash else '(none)'}")
    _err(f"  new : {render_identity(new_hash, aliases, full=args.full_hashes)}")
    _err(f"  file: {store.identity_default_path} (mode 0600)")
    _err("  NOTE: previous identity's signatures will no longer verify; "
         "self-anchor rotated to the new identity.")
    return EXIT_OK


# -- issuer identity cache (work doc #5) ------------------------------------

_PUBLIC_KEY_HEX_LEN = 64  # 32-byte Ed25519 public key as hex


def cmd_identity_remember(args) -> int:
    """Pre-load an issuer pubkey into the durable cache (work doc #5).

    Reads the pubkey from ``--pubkey <hex>`` / ``--file <path>`` if given, else
    boots RNS and tries :meth:`RNS.Identity.recall` (the live recall store,
    populated from persisted announces on Python RNS). Errors clearly if the
    issuer cannot be resolved out-of-band.
    """
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    issuer_hash = resolve_identity(args.hash, aliases)

    if args.pubkey is not None:
        try:
            sig_pub = bytes.fromhex(args.pubkey)
        except ValueError:
            raise CliError(f"--pubkey is not valid hex: {args.pubkey!r}")
        if len(sig_pub) != 32:
            raise CliError(f"--pubkey must be 32 bytes (64 hex), got {len(sig_pub)}")
    elif args.file is not None:
        sig_pub = Path(args.file).read_bytes()
        if len(sig_pub) != 32:
            raise CliError(f"pubkey file must contain 32 bytes, got {len(sig_pub)}")
    else:
        # Boot RNS if not already running, then try to recall (Python RNS loads
        # persisted announces).
        import RNS
        from dacar.cli.rns import boot, resolve_config_dir
        if RNS.Reticulum.get_instance() is None:
            config_dir = resolve_config_dir(store_path=args.store)
            boot(config_dir)
        recalled = RNS.Identity.recall(issuer_hash, from_identity_hash=True)
        if recalled is None:
            raise CliError(
                f"could not recall {render_identity(issuer_hash, aliases, full=args.full_hashes)} "
                "from RNS; use --pubkey <hex> or --file <path> to specify the key out-of-band"
            )
        sig_pub = recalled.sig_pub_bytes

    keyring = store.load_keyring()
    keyring.register_single(issuer_hash, sig_pub)
    store.save_keyring(keyring)
    _err(f"✔ remembered issuer {render_identity(issuer_hash, aliases, full=args.full_hashes)}")
    _err(f"  pubkey : {sig_pub.hex()}")
    _err(f"  cache  : {store.identities_path} ({len(keyring)} entries)")
    return EXIT_OK


def cmd_identity_forget(args) -> int:
    """Remove an issuer from the durable cache (work doc #5).

    Refuses to purge an issuer that still has *active* grants in the live CRDT:
    forgetting such an issuer would make its future revokes unverifiable,
    leaving those grants stuck (unrevocable from this node's perspective).
    Override with ``--force`` once you understand the consequence.
    """
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    issuer_hash = resolve_identity(args.hash, aliases)

    if not args.force:
        config = store.load_config()
        state = store.load_state(config)
        active = [
            tup for tup, add_ts, remove_ts in state.iter_entries()
            if tup.issuer == issuer_hash
            and add_ts is not None
            and (remove_ts is None or add_ts > remove_ts)
        ]
        if active:
            raise CliError(
                f"issuer {render_identity(issuer_hash, aliases, full=args.full_hashes)} "
                f"has {len(active)} active grant(s) in the live CRDT; forgetting it would "
                "make its revokes unverifiable (use --force to override)"
            )

    keyring = store.load_keyring()
    if not keyring.forget(issuer_hash):
        raise CliError(
            f"issuer {render_identity(issuer_hash, aliases, full=args.full_hashes)} "
            "not in the cache"
        )
    store.save_keyring(keyring)
    _err(f"✔ forgot issuer {render_identity(issuer_hash, aliases, full=args.full_hashes)}")
    _err(f"  cache : {store.identities_path} ({len(keyring)} entries)")
    return EXIT_OK


def cmd_identity_list(args) -> int:
    """List the durable issuer identity cache (work doc #5)."""
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    keyring = store.load_keyring()
    _err(f"ISSUER IDENTITY CACHE ({len(keyring)})  {store.identities_path}")
    if not len(keyring):
        _err("(none — use `dacar identity remember <hash>` to seed)")
        return EXIT_OK
    for issuer_hash, keyset in keyring.entries():
        pubkey = keyset.member_public_keys[0] if keyset.member_public_keys else b""
        _err(f"  {render_identity(issuer_hash, aliases, full=args.full_hashes)}  "
             f"pubkey={pubkey.hex()[:SHORT_HASH_HEX]}…")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Issuing operations (grant / revoke)
# ---------------------------------------------------------------------------


def _build_tuple(args, store, config, aliases) -> _Tuple[Tuple, Optional[str], Optional[str], Optional[bool]]:
    """Return ``(tuple, object_id, relation, wildcard)`` for plaintext or copy-hashes."""
    grantee = resolve_identity(args.grantee, aliases)
    issuer = store.identity_hash()
    if getattr(args, "copy_hashes", None):
        relation_hash, object_hashes, wildcard = _parse_copy_hashes(args.copy_hashes)
        tup = Tuple(
            relation_hash=relation_hash,
            object_hashes=object_hashes,
            wildcard=wildcard,
            grantee=grantee,
            issuer=issuer,
        )
        return tup, None, None, None
    relation = args.relation
    object_id = args.object
    hasher = config.primary_hasher
    if getattr(args, "legacy", None) is not None:
        legacy = config.legacy_hashers
        if args.legacy >= len(legacy):
            raise CliError(
                f"--legacy index {args.legacy} out of range "
                f"(have {len(legacy)} legacy salts)"
            )
        hasher = legacy[args.legacy]
    wildcard = object_id.endswith("*") and object_id != "*"
    tup = Tuple.from_plaintext(
        object_id=object_id, relation=relation, grantee=grantee, issuer=issuer, hasher=hasher,
    )
    return tup, object_id, relation, wildcard


def _parse_copy_hashes(path: str) -> _Tuple[bytes, _Tuple[bytes, ...], bool]:
    """Parse a ``--copy-hashes`` file: ``relation_hash=<hex>`` etc."""
    relation_hash: Optional[bytes] = None
    object_hashes: List[bytes] = []
    wildcard = False
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if key == "relation_hash":
            relation_hash = bytes.fromhex(val)
        elif key == "object_hashes":
            object_hashes = tuple(bytes.fromhex(p) for p in val.split(":") if p)
        elif key == "wildcard":
            wildcard = val.lower() in ("true", "1", "yes")
    if relation_hash is None or len(relation_hash) != 16:
        raise CliError("--copy-hashes file must define a 16-byte relation_hash")
    return relation_hash, tuple(object_hashes), wildcard


def _issue(args, action: Action) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    aliases = store.load_aliases()
    identity = store.load_identity()
    tup, object_id, relation, wildcard = _build_tuple(args, store, config, aliases)

    # Monotonic HLC, persisted across invocations.
    clock = store.load_clock()
    hlc = clock.now()
    store.save_clock(clock)

    op = Operation(tuple=tup, action=action, hlc=hlc).sign(identity.sig_prv)
    payload = op.to_payload()

    applied = False
    if not args.no_apply:
        state = store.load_state(config)
        applied = state.apply(op)
        if not applied:
            raise CliError("local apply rejected (§9 stale / §12 future-skew)")
        store.save_state(state)

    # Record plaintext ledger for any locally-issued op with known plaintext.
    if object_id is not None and relation is not None:
        ledger = store.load_ledger()
        ledger.record(
            tup.hash(),
            object_id=object_id, relation=relation,
            wildcard=bool(wildcard), first_seen=hlc,
        )
        store.save_ledger(ledger)

    # Emit the signed payload (hex on stdout by default).
    if args.out:
        Path(args.out).write_bytes(payload)
        where = f"binary file {args.out}"
    elif args.binary:
        sys.stdout.buffer.write(payload)
        where = "binary on stdout"
    else:
        sys.stdout.write(payload.hex() + "\n")
        where = "hex on stdout"

    verb = "granted" if action == Action.GRANT else "revoked"
    mark = "✔"
    _err(f"{mark} {verb:8} {render_identity(tup.grantee, aliases, full=args.full_hashes)}  "
         f"{relation or '[hash]'}  on  {object_id or '[hash]'}")
    _err(f"  grantee : {render_identity(tup.grantee, aliases, full=args.full_hashes)}")
    _err(f"  issuer  : {render_identity(tup.issuer, aliases, full=args.full_hashes)}")
    if object_id is not None:
        nseg = len([s for s in object_id.split(":") if s]) if object_id != "*" else 0
        _err(f"  object  : {object_id}  ({nseg} segment{'s' if nseg != 1 else ''}"
             f"{', wildcard' if wildcard else ''})")
    else:
        _err(f"  object  : [copy-hashes, {len(tup.object_hashes)} segment(s)"
             f"{', wildcard' if tup.wildcard else ''}]")
    _err(f"  hlc     : 0x{hlc:016x}")
    _err(f"  payload : {where} ({len(payload)} bytes)")
    if args.no_apply:
        _err("  (not applied locally: --no-apply)")
    elif applied:
        _err("  (applied locally)")
    if getattr(args, "publish", False):
        _publish_delta(args, store, identity, payload)
    else:
        # Outbox (work doc #8): queue locally-issued deltas for ``publish --all``.
        # ``--publish`` sends immediately and never enqueues; ``--no-apply`` only
        # governs local CRDT apply, not whether the delta was issued.
        outbox = store.load_outbox()
        outbox.append(payload)
        store.save_outbox(outbox)
        _err("  (queued in outbox: `dacar publish --all` to flush)")
    return EXIT_OK


def cmd_grant(args) -> int:
    return _issue(args, Action.GRANT)


def cmd_revoke(args) -> int:
    return _issue(args, Action.REVOKE)


# ---------------------------------------------------------------------------
# Receiving / evaluating
# ---------------------------------------------------------------------------


def _read_payload_input(path: str, force_binary: bool) -> bytes:
    if path == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(path).read_bytes()
    if force_binary:
        return data
    # Auto-detect hex (open item): an all-hex, even-length ASCII blob decodes.
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return data
    if text and len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text)
    return data


def cmd_apply(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    state = store.load_state(config)
    keyring = store.keyring_for_verify()
    rx = DeltaReceiver(state, keyring)
    data = _read_payload_input(args.payload, args.binary)

    if not data:
        raise CliError("empty payload")

    # Try a single delta first; fall back to a batch.
    if rx.apply_payload(data):
        count = 1
        store.save_state(state)
        _err("✔ applied 1 delta")
        try:
            op = Operation.from_payload(data)
            aliases = store.load_aliases()
            ledger = store.load_ledger()
            _err(f"  {render_identity(op.grantee, aliases, full=args.full_hashes)}  "
                 f"{render_relation(op.relation_hash, ledger.lookup(op.tuple.hash()), full=args.full_hashes)}  "
                 f"{render_object(op.object_hashes, op.wildcard, ledger.lookup(op.tuple.hash()), full=args.full_hashes)}  "
                 f"← {render_identity(op.issuer, aliases, full=args.full_hashes)}")
        except (ValueError, TypeError):
            pass
        return EXIT_OK

    count = rx.apply_payloads(data)
    if count > 0:
        store.save_state(state)
        _err(f"✔ applied {count} delta(s) (batch)")
        return EXIT_OK

    _err("✘ delta rejected (unknown issuer, bad signature, stale §9, or malformed)")
    return EXIT_FAIL


def cmd_check(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    state = store.load_state(config)
    aliases = store.load_aliases()
    ledger = store.load_ledger()
    engine = Engine(config, state)
    grantee = resolve_identity(args.grantee, aliases)
    allowed = engine.evaluate(args.object, args.relation, grantee)

    mark = "✔" if allowed else "✘"
    verdict = "ALLOW" if allowed else "DENY"
    _err(f"{mark} {verdict:5} {render_identity(grantee, aliases, full=args.full_hashes)}  "
         f"{args.relation}  {args.object}")

    # Best-effort trace: find the matching active tuples across all salts.
    matches = _find_matching_tuples(config, state, args.relation, args.object, grantee)
    if not matches:
        _err("  no matching active tuple")
    else:
        for kind, tup, hasher in matches:
            row = ledger.lookup(tup.hash())
            rel = row["relation"] if row and row.get("relation") else f"[{_short(tup.relation_hash, args.full_hashes)}]"
            obj = row["object"] if row and row.get("object") else "[hash]"
            issuer_label = render_identity(tup.issuer, aliases, full=args.full_hashes)
            anchor = "is a Root Trust Anchor" if config.is_root_anchor(tup.issuer) else "is NOT an anchor"
            tag = "deny" if kind == "deny" else "allow"
            _err(f"  {tag:5} : {issuer_label} {rel} {obj}  ({anchor})")
    return EXIT_OK if allowed else EXIT_FAIL


def _find_matching_tuples(config, state, relation: str, object_id: str,
                          grantee: bytes):
    """Yield ``(kind, tuple, hasher)`` for active tuples matching the request."""
    for hasher in config.hashers:
        allow_rh = hasher.hash_relation(relation)
        deny_rh = hasher.hash_relation("-" + relation)
        obj_hashes, _ = hasher.hash_object(object_id)
        for tup in state.active_tuples():
            if tup.grantee != grantee:
                continue
            if tup.relation_hash == deny_rh and covers(tup.object_hashes, tup.wildcard, obj_hashes):
                yield ("deny", tup, hasher)
            elif tup.relation_hash == allow_rh and covers(tup.object_hashes, tup.wildcard, obj_hashes):
                yield ("allow", tup, hasher)


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


def cmd_grants(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    state = store.load_state(config)
    aliases = store.load_aliases()
    ledger = store.load_ledger()
    engine = Engine(config, state) if args.effective else None

    rows = []
    for tup, add_ts, remove_ts in state.iter_entries():
        active = add_ts is not None and (remove_ts is None or add_ts > remove_ts)
        if args.revoked and active:
            continue
        if not args.all and not args.revoked and not active:
            continue
        if args.grantee is not None:
            wanted = resolve_identity(args.grantee, aliases)
            if tup.grantee != wanted:
                continue
        if args.issuer is not None:
            wanted = resolve_identity(args.issuer, aliases)
            if tup.issuer != wanted:
                continue
        rows.append((tup, add_ts, remove_ts, active))

    label = "ACTIVE GRANTS" if not args.revoked else "REVOKED TOMBSTONES"
    if args.all:
        label = "ALL TUPLES"
    _err(f"{label} ({len(rows)}){'':>16}store: {store.path}")
    if not rows:
        _err("(none)")
        return EXIT_OK

    _err(f"{'GRANTEE':<20} {'RELATION':<10} {'OBJECT':<16} {'ISSUER':<20} {'STATUS':<8} {'TIMESTAMP'}")
    for tup, add_ts, remove_ts, active in rows:
        row = ledger.lookup(tup.hash())
        grantee = render_identity(tup.grantee, aliases, full=args.full_hashes)
        relation = render_relation(tup.relation_hash, row, full=args.full_hashes)
        obj = render_object(tup.object_hashes, tup.wildcard, row, full=args.full_hashes)
        issuer = render_identity(tup.issuer, aliases, full=args.full_hashes)
        if active:
            status = "active"
            ts = _utc(add_ts) if add_ts else "-"
        else:
            status = "revoked"
            ts = _utc(remove_ts) if remove_ts else "-"
        opaque = ""
        if not (row and row.get("object")):
            opaque = " ◂ opaque"
        effective = ""
        if engine is not None and row and row.get("object"):
            # The issuer is "effective" iff its authority traces to a root
            # anchor. A root anchor is effective by definition (the genesis
            # tuple is implicit, §4.2); a delegated issuer is effective iff
            # the engine grants it admin on this object.
            has_auth = config.is_root_anchor(tup.issuer) or engine.evaluate(
                row["object"], "admin", tup.issuer
            )
            effective = " ✔" if has_auth else " ⚠"
        _err(f"{grantee:<20} {relation:<10} {obj:<16} {issuer:<20} {status:<8} {ts}{opaque}{effective}")
    return EXIT_OK


def cmd_show(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    state = store.load_state(config)
    aliases = store.load_aliases()
    ledger = store.load_ledger()

    ref = args.ref.strip()
    shown = False
    # Tuple-hash form (64 hex = 32 bytes).
    if len(ref) == 64:
        try:
            tuple_hash = bytes.fromhex(ref)
            entry = state.get(tuple_hash)
            if entry is not None:
                _print_tuple_detail(entry.tuple, entry.add_ts, entry.remove_ts, aliases, ledger, args.full_hashes)
                shown = True
        except ValueError:
            pass

    if not shown:
        # alias:relation:object form — search across issuers/salts.
        parts = ref.split(":")
        if len(parts) < 2:
            raise CliError("show expects a 64-hex tuple hash or <alias>:<relation>:<object>")
        grantee_alias = parts[0]
        relation = parts[1]
        object_id = ":".join(parts[2:]) if len(parts) > 2 else ""
        grantee = resolve_identity(grantee_alias, aliases)
        for hasher in config.hashers:
            allow_rh = hasher.hash_relation(relation)
            obj_hashes, _ = hasher.hash_object(object_id)
            for tup, add_ts, remove_ts in state.iter_entries():
                if tup.grantee != grantee:
                    continue
                if tup.relation_hash == allow_rh and covers(tup.object_hashes, tup.wildcard, obj_hashes):
                    _print_tuple_detail(tup, add_ts, remove_ts, aliases, ledger, args.full_hashes)
                    shown = True

    if not shown:
        raise CliError(f"no tuple found for {ref!r}")
    return EXIT_OK


def _print_tuple_detail(tup, add_ts, remove_ts, aliases, ledger, full) -> None:
    row = ledger.lookup(tup.hash())
    active = add_ts is not None and (remove_ts is None or add_ts > remove_ts)
    _err(f"tuple   : {tup.hash().hex()}")
    _err(f"  status  : {'ACTIVE' if active else 'REVOKED'}")
    _err(f"  grantee : {render_identity(tup.grantee, aliases, full=full)}")
    _err(f"  issuer  : {render_identity(tup.issuer, aliases, full=full)}")
    _err(f"  relation: {render_relation(tup.relation_hash, row, full=full)}")
    _err(f"  object  : {render_object(tup.object_hashes, tup.wildcard, row, full=full)}")
    _err(f"  wildcard: {tup.wildcard}")
    _err(f"  segments: {len(tup.object_hashes)}")
    _err(f"  added   : {_utc(add_ts) if add_ts else '-'}  (hlc 0x{add_ts:016x})" if add_ts else "  added   : -")
    _err(f"  removed : {_utc(remove_ts) if remove_ts else '-'}  (hlc 0x{remove_ts:016x})" if remove_ts else "  removed : -")


def cmd_prune(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    state = store.load_state(config)
    count = state.prune()
    store.save_state(state)
    _err(f"✔ pruned {count} resolved tombstone pair(s) (§9)")
    # Also drop outbox entries older than the §9 horizon: such deltas are
    # intake-rejected by receivers (§9) so publishing them is pointless, and
    # this keeps the outbox bounded for long-lived offline nodes (work doc #8).
    dropped = _prune_outbox(store, state.deletion_horizon_ms)
    if dropped:
        _err(f"  outbox: pruned {dropped} stale delta(s) (older than horizon)")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Aliases / ledger
# ---------------------------------------------------------------------------


def cmd_alias_add(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    hash_bytes = resolve_identity(args.hash, aliases)
    existing = aliases.resolve(args.name)
    if existing is not None and existing != hash_bytes:
        raise CliError(
            f"alias {args.name!r} already names a different hash "
            f"({_short(existing, full=args.full_hashes)})"
        )
    aliases.add(args.name, hash_bytes, note=args.note)
    store.save_aliases(aliases)
    _err(f"✔ alias {args.name!r} → {render_identity(hash_bytes, aliases, full=args.full_hashes)}")
    return EXIT_OK


def cmd_alias_remove(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    if not aliases.remove(args.name):
        raise CliError(f"no alias named {args.name!r}")
    store.save_aliases(aliases)
    _err(f"✔ removed alias {args.name!r}")
    return EXIT_OK


def cmd_alias_list(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    if not aliases.entries:
        _err("(no aliases)")
        return EXIT_OK
    for entry in aliases.entries:
        line = f"{entry.hash.hex()}  {' '.join(entry.names)}"
        if entry.note:
            line += f"  # {entry.note}"
        _err(line)
    return EXIT_OK


def cmd_alias_resolve(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    aliases = store.load_aliases()
    h = aliases.resolve(args.name)
    if h is None:
        raise CliError(f"unknown alias {args.name!r}")
    # Print the full hash to stdout (machine-readable).
    sys.stdout.write(h.hex() + "\n")
    return EXIT_OK


def cmd_ledger_annotate(args) -> int:
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    try:
        tuple_hash = bytes.fromhex(args.tuple_hash)
    except ValueError:
        raise CliError(f"tuple-hash must be hex, got {args.tuple_hash!r}")
    if len(tuple_hash) != 32:
        raise CliError(f"tuple-hash must be 32 bytes (64 hex), got {len(tuple_hash)}")
    ledger = store.load_ledger()
    if not ledger.annotate(tuple_hash, object_id=args.object, relation=args.relation):
        # Ensure a row exists so annotate can populate it.
        row = ledger.ensure(tuple_hash)
        if args.object is not None:
            row["object"] = args.object
        if args.relation is not None:
            row["relation"] = args.relation
    store.save_ledger(ledger)
    _err(f"✔ annotated tuple {tuple_hash[:SHORT_HASH_HEX].hex()}…")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Online commands (work doc #4 — one-shot, no daemon)
# ---------------------------------------------------------------------------


def _resolve_rfed_node(args, store: Store, aliases: AliasRegistry, rns: object = None) -> bytes:
    """Resolve the rfed node identity hash from --node or [rfed] node config."""
    node = getattr(args, "node", None)
    if node:
        return resolve_identity(node, aliases)
    raw = store.load_config_raw()
    if raw.get("rfed_node"):
        return raw["rfed_node"]
    if getattr(args, "discover", False) and rns is not None:
        from dacar.cli.rns import discover_rfed_node
        return discover_rfed_node(rns, timeout=30000)
    raise CliError(
        "no rfed node configured (use --node <hash>, --discover, or set [rfed] node in config)"
    )


def _resolve_topic(args, store: Store) -> str:
    """Resolve the rfed topic from --topic or [rfed] topic config."""
    topic = getattr(args, "topic", None)
    if topic:
        return topic
    raw = store.load_config_raw()
    return raw.get("rfed_topic", RFED_TOPIC)


def _resolve_rns_config_dir(args) -> str:
    """Resolve the RNS config directory per the priority order (work doc #4)."""
    from dacar.cli.rns import resolve_config_dir
    return resolve_config_dir(
        explicit=getattr(args, "rns_config", None),
        store_path=args.store,
    )


def run_publish(
    identity: object,
    payload: bytes,
    node_hash: bytes,
    topic: str,
    client: object,
) -> None:
    """Publish a signed Delta to the rfed channel (§11.1, work doc #4).

    Testable core: takes an explicit ``client`` (RFedClient or compatible fake)
    so tests inject doubles without booting RNS. The ``cmd_*`` wrappers handle
    RNS boot + announce + real client creation.
    """
    from dacar.transport.rfed_sync import RfedDeltaSync
    sync = RfedDeltaSync(client=client, topic=topic)
    result = sync.subscribe(node_hash)
    if getattr(result, "ok", True) is False:
        raise CliError(
            f"rfed subscribe to {_short(node_hash, full=False)} failed; "
            "the node rejected the subscription (signature/channel mismatch) "
            "or returned no response — the topic will not sync with peers"
        )
    sync.publish(payload, node_hash)


def run_sync(
    store: Store,
    state: object,
    node_hash: bytes,
    topic: str,
    client: object,
    receiver: DeltaReceiver,
) -> int:
    """Pull pending Deltas from the rfed channel and apply via verify-on-ingest.

    Testable core: takes an explicit ``client`` and ``receiver`` so tests inject
    doubles. Routes every blob through :meth:`DeltaReceiver.apply_payload`
    (§11.2.4) — never through the unauthenticated ``StateVector.merge`` path.
    Persists the CRDT if any Delta was applied. Returns the count applied.
    """
    from dacar.transport.rfed_sync import RfedDeltaSync
    sync = RfedDeltaSync(receiver=receiver, client=client, topic=topic)
    result = sync.subscribe(node_hash)
    if getattr(result, "ok", True) is False:
        raise CliError(
            f"rfed subscribe to {_short(node_hash, full=False)} failed; "
            "the node rejected the subscription (signature/channel mismatch) "
            "or returned no response — the topic will not sync with peers"
        )
    applied = sync.pull(node_hash)
    if applied > 0:
        store.save_state(state)
    return applied


def _publish_delta(args, store: Store, identity, payload: bytes) -> None:
    """Online publish hook for ``grant --publish`` / ``revoke --publish``."""
    from dacar.cli.rns import announce_identity, boot, ensure_node_identity, register_announce_handler
    from dacar.rfed.client import RFedClient

    aliases = store.load_aliases()
    topic = _resolve_topic(args, store)

    # RNS must be booted first for discover mode
    config_dir = _resolve_rns_config_dir(args)
    rns = boot(config_dir)

    node_hash = _resolve_rfed_node(args, store, aliases, rns)
    # Proactively fetch the rfed node's identity: when --node is given (or
    # --discover derived it), the destination's announce may not yet be in
    # RNS's recall store. Send a path? request and wait for the announce
    # rather than failing with "wait for its announce" (work doc #6).
    ensure_node_identity(
        node_hash, on_request=lambda: _err("  requesting rfed node identity…")
    )
    announce_identity(identity)  # announce invariant (§11.2.4)

    # Seed the durable cache from any dacar.node announces observed during the
    # publish window (work doc #5, design decision #4).
    keyring = store.load_keyring()
    keyring.register_single(identity.hash, identity.sig_pub_bytes)
    register_announce_handler(keyring, on_save=store.save_keyring)

    client = RFedClient(identity=identity, rns=rns)
    run_publish(identity, payload, node_hash, topic, client)
    _err(f"  published to rfed channel {topic!r} via "
         f"{_short(node_hash, full=args.full_hashes)}")


def cmd_sync(args) -> int:
    """``dacar sync`` — pull pending Deltas from the rfed channel (§11.1).

    One-shot: attach-or-spawn RNS, announce the node identity, subscribe +
    pull (drain to empty), route every blob through verify-on-ingest, persist
    the CRDT, exit. No daemon — store-and-forward means transient online windows
    suffice (work doc #4).
    """
    from dacar.cli.rns import announce_identity, boot, ensure_node_identity, register_announce_handler
    from dacar.rfed.client import RFedClient
    from dacar.transport.rns_identity import RnsIdentityResolver

    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    config = store.load_config()
    aliases = store.load_aliases()

    identity = store.load_identity()
    if identity is None:
        raise CliError("no signing identity (run `dacar init` or `dacar identity new`)")

    topic = _resolve_topic(args, store)

    # Boot RNS + announce (announce invariant, §11.2.4).
    config_dir = _resolve_rns_config_dir(args)
    rns = boot(config_dir)
    announce_identity(identity)

    # Durable issuer cache (work doc #5): load the persisted keyring, ensure our
    # own identity is in it, and register an announce handler so any
    # dacar.node announces observed during the sync window seed the cache for
    # future runs. The keyring is the RnsIdentityResolver fallback (RNS recall
    # is consulted first — announced identities win).
    keyring = store.load_keyring()
    keyring.register_single(identity.hash, identity.sig_pub_bytes)
    register_announce_handler(keyring, on_save=store.save_keyring)

    state = store.load_state(config)
    node_hash = _resolve_rfed_node(args, store, aliases, rns)
    # Proactively fetch the rfed node's identity: when --node is given (or
    # --discover derived it), the destination's announce may not yet be in
    # RNS's recall store. Send a path? request and wait for the announce
    # rather than failing with "wait for its announce" (work doc #6).
    ensure_node_identity(
        node_hash, on_request=lambda: _err("  requesting rfed node identity…")
    )
    resolver = RnsIdentityResolver(fallback=keyring)
    rx = DeltaReceiver(state, resolver)

    client = RFedClient(identity=identity, rns=rns)
    applied = run_sync(store, state, node_hash, topic, client, rx)

    # Persist the keyring if any announces were observed during the window.
    store.save_keyring(keyring)

    _err(f"✔ synced: applied {applied} delta(s) from rfed channel {topic!r}")
    return EXIT_OK


def cmd_publish(args) -> int:
    """``dacar publish`` — push signed delta(s) to the rfed channel (§11.1, doc #8).

    Two modes:

      * ``dacar publish <file> [<file>...]`` — publish previously-signed delta
        payload(s). Files (or ``-`` for stdin) are read with the same
        hex/binary auto-detect as ``apply`` (+ ``--binary`` to force raw).
        Multiple files are packed into one batch payload
        (:meth:`DeltaReceiver.pack_payloads`). The **exact signed bytes** are
        published — no re-signing, no new HLC, no local state change — so the
        receiver's verify-on-ingest authenticates the *original* issuer.

      * ``dacar publish --all`` — pack every locally-issued, not-yet-published
        delta from the outbox into one batch, publish it, then clear the
        outbox. A no-op (exit 0) on an empty outbox.

    Both reuse the ``grant --publish`` machinery (boot RNS, announce the node
    identity, subscribe, publish) via :func:`_publish_delta`.
    """
    store = Store(args.store, identity_override=args.identity)
    store.ensure()
    identity = store.load_identity()
    if identity is None:
        raise CliError("no signing identity (run `dacar init` or `dacar identity new`)")

    use_all = getattr(args, "all", False)
    payloads = list(args.payloads or [])

    if use_all and payloads:
        raise CliError("publish: use either <file>... or --all, not both")
    if not use_all and not payloads:
        raise CliError("publish: provide <file>... (one or more) or --all")

    if use_all:
        to_publish = store.load_outbox()
        if not to_publish:
            _err("outbox empty (nothing to publish)")
            return EXIT_OK
    else:
        to_publish = []
        for path in payloads:
            data = _read_payload_input(path, args.binary)
            if not data:
                raise CliError(f"empty payload: {path}")
            to_publish.append(data)

    # Pack into a single rfed message: a batch if >1, raw bytes if exactly 1
    # (so a single-delta publish stays a single-delta payload on the wire).
    if len(to_publish) == 1:
        batch = to_publish[0]
    else:
        batch = DeltaReceiver.pack_payloads(to_publish)

    label = "outbox" if use_all else f"{len(to_publish)} file(s)"
    kind = "a batch" if len(to_publish) > 1 else "a single delta"
    _err(f"  publishing {len(to_publish)} delta(s) ({label}) as {kind}")

    # Reuse the grant --publish machinery (boot RNS, announce, subscribe, publish).
    _publish_delta(args, store, identity, batch)

    if use_all:
        store.save_outbox([])
        _err("  outbox cleared")
    return EXIT_OK


def _prune_outbox(store: Store, horizon_ms: int, *, now_ms: Optional[int] = None) -> int:
    """Drop outbox entries whose HLC physical time is older than the §9 horizon.

    Such deltas are intake-rejected by receivers (§9), so publishing them is
    pointless; pruning keeps the outbox bounded for long-lived offline nodes.
    Entries that fail to decode are left intact (do not destroy on a decode
    error). Returns the number dropped.
    """
    outbox = store.load_outbox()
    if not outbox:
        return 0
    now = now_ms if now_ms is not None else physical_now_ms()
    cutoff = now - horizon_ms
    kept: List[bytes] = []
    dropped = 0
    for payload in outbox:
        try:
            op = Operation.from_payload(payload)
            phys, _ = unpack(op.hlc)
        except (ValueError, TypeError):
            kept.append(payload)  # can't decode -> keep (don't destroy)
            continue
        if phys < cutoff:
            dropped += 1
        else:
            kept.append(payload)
    if dropped:
        store.save_outbox(kept)
    return dropped
