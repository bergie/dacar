"""Persistent node store for the ``dacar`` CLI (work doc #2).

Manages the on-disk store directory and its Reticulum-native file formats
(design decision #10 — no JSON):

  * ``config``         — INI (``configparser``, like RNS's own config)
  * ``identity``       — the node's own RNS Identity (private key), mode ``0600``
  * ``clock.msgpack``  — persisted HLC ``{ last_ms, logical }``
  * ``state.msgpack``  — ``StateVector.to_payload()`` (the CRDT)
  * ``aliases``        — rnns ``hash name [# note]`` format
  * ``ledger.msgpack`` — ``{ tuple_hash_hex: { object, relation, wildcard, first_seen } }``

The store dir is mode ``0700``; the config, identity, state, and ledger files
are mode ``0600`` (they hold the salt, the private key, CRDT state, and
plaintext labels respectively).
"""

from __future__ import annotations

import configparser
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import RNS
from dacar import serialization
from dacar.config import Config, DEFAULT_DELETION_HORIZON_DAYS
from dacar.crdt import StateVector, TrustedLocalOnlyWarning
from dacar.hlc import Clock
from dacar.naming import RFED_TOPIC
from dacar.namespace import DEFAULT_SALT, HASH_SIZE, MAX_LEGACY_SALTS, SALT_SIZE
from dacar.verifier import Keyring, _PUBLIC_KEY_SIZE

#: File modes.
DIR_MODE = 0o700
SECRET_MODE = 0o600
PUBLIC_MODE = 0o644

#: The alias that always names the node's own signing identity.
SELF_ALIAS = "self"

CONFIG_NAME = "config"
IDENTITY_NAME = "identity"
CLOCK_NAME = "clock.msgpack"
STATE_NAME = "state.msgpack"
ALIASES_NAME = "aliases"
LEDGER_NAME = "ledger.msgpack"
IDENTITIES_NAME = "identities.msgpack"


def _generate_salt() -> bytes:
    """Return a cryptographically secure 32-byte Privacy Salt (§3.3)."""
    return secrets.token_bytes(SALT_SIZE)


def _parse_salt_value(value: str) -> bytes:
    """Parse a ``--salt``/``salt set`` value that is either hex or a file path.

    A 64-character hex string is read as hex; anything else is treated as a
    path to a 32-byte raw salt file.
    """
    value = value.strip()
    hex_candidate = value.removeprefix("0x") if value.lower().startswith("0x") else value
    if len(hex_candidate) == SALT_SIZE * 2:
        try:
            return bytes.fromhex(hex_candidate)
        except ValueError:
            pass  # fall through to file interpretation
    with open(value, "rb") as fh:
        data = fh.read()
    if len(data) != SALT_SIZE:
        raise ValueError(
            f"salt file {value!r} must contain {SALT_SIZE} bytes, got {len(data)}"
        )
    return data


@dataclass
class AliasEntry:
    """One rnns alias line: a 16-byte hash with one or more names and a note."""

    hash: bytes
    names: List[str]
    note: Optional[str] = None


@dataclass
class AliasRegistry:
    """The in-memory form of the ``aliases`` file (rnns ``hash name [# note]``).

    One hash may carry several names (rnns semantics); names are unique across
    the registry. The registry is a naming layer only — it never stores public
    keys (design decision #5).
    """

    entries: List[AliasEntry] = field(default_factory=list)

    # -- parsing / serialization -------------------------------------------
    @classmethod
    def parse(cls, text: str) -> "AliasRegistry":
        """Parse rnns ``hash name [# note]`` lines.

        Blank lines and lines whose first token is not a 32-hex hash are
        skipped (so stray full-line comments are tolerated). A trailing
        ``# note`` is captured per entry and is dacar-local.
        """
        registry = cls()
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            # Split off a trailing ``# note`` (dacar-local).
            if "#" in line:
                head, _, note = line.partition("#")
                note = note.strip() or None
            else:
                head, note = line, None
            tokens = head.split()
            if not tokens:
                continue
            hash_hex = tokens[0]
            names = tokens[1:]
            # Only 32-hex (16-byte) first tokens are real alias lines.
            if len(hash_hex) != HASH_SIZE * 2:
                continue
            try:
                hash_bytes = bytes.fromhex(hash_hex)
            except ValueError:
                continue
            if not names:
                continue
            existing = registry._entry_for(hash_bytes)
            if existing is not None:
                for n in names:
                    if n not in existing.names:
                        existing.names.append(n)
                if note is not None:
                    existing.note = note
            else:
                registry.entries.append(AliasEntry(hash_bytes, list(names), note))
        return registry

    def serialize(self) -> str:
        """Render back to rnns ``hash name [# note]`` lines."""
        lines = []
        for entry in self.entries:
            hash_hex = entry.hash.hex()
            field_text = hash_hex + " " + " ".join(entry.names) if entry.names else hash_hex
            if entry.note:
                field_text += f"  # {entry.note}"
            lines.append(field_text)
        return "\n".join(lines) + ("\n" if lines else "")

    def serialize_for_rnns(self) -> str:
        """Render stripped of dacar-local ``# note`` (safe for unmodified rnns)."""
        lines = []
        for entry in self.entries:
            hash_hex = entry.hash.hex()
            if not entry.names:
                continue
            lines.append(hash_hex + " " + " ".join(entry.names))
        return "\n".join(lines) + ("\n" if lines else "")

    # -- lookups ------------------------------------------------------------
    def _entry_for(self, hash_bytes: bytes) -> Optional[AliasEntry]:
        for entry in self.entries:
            if entry.hash == hash_bytes:
                return entry
        return None

    def resolve(self, name: str) -> Optional[bytes]:
        """Return the 16-byte hash aliased to ``name``, or ``None``."""
        for entry in self.entries:
            if name in entry.names:
                return entry.hash
        return None

    def names_for(self, hash_bytes: bytes) -> List[str]:
        entry = self._entry_for(hash_bytes)
        return list(entry.names) if entry is not None else []

    def primary_name(self, hash_bytes: bytes) -> Optional[str]:
        names = self.names_for(hash_bytes)
        return names[0] if names else None

    # -- mutation -----------------------------------------------------------
    def add(self, name: str, hash_bytes: bytes, note: Optional[str] = None) -> None:
        """Add ``name`` for ``hash_bytes``; set ``note`` if given."""
        entry = self._entry_for(hash_bytes)
        if entry is not None:
            if name not in entry.names:
                entry.names.append(name)
            if note is not None:
                entry.note = note
        else:
            self.entries.append(AliasEntry(hash_bytes, [name], note))

    def remove(self, name: str) -> bool:
        """Remove ``name`` from its entry. Returns True if it existed."""
        for entry in self.entries:
            if name in entry.names:
                entry.names.remove(name)
                if not entry.names:
                    self.entries.remove(entry)
                return True
        return False

    def set_self(self, hash_bytes: bytes) -> None:
        """Point the ``self`` alias at ``hash_bytes`` (replacing any prior)."""
        for entry in self.entries:
            if SELF_ALIAS in entry.names:
                entry.names.remove(SELF_ALIAS)
        self.entries = [e for e in self.entries if e.names]
        self.add(SELF_ALIAS, hash_bytes)


@dataclass
class Ledger:
    """The plaintext ledger: ``tuple_hash_hex -> { object, relation, wildcard, first_seen }``.

    Records the plaintext ``(object, relation, wildcard)`` for every grant/revoke
    *issued locally* so ``grants``/``show`` can render readable rows. Network-
    received opaque deltas have no plaintext and stay hashed (design decision #7).
    """

    rows: Dict[str, dict] = field(default_factory=dict)

    @staticmethod
    def key_for(tuple_hash: bytes) -> str:
        return tuple_hash.hex()

    def record(self, tuple_hash: bytes, *, object_id: str, relation: str,
               wildcard: bool, first_seen: int) -> None:
        """Record or refresh the plaintext for a tuple hash."""
        key = self.key_for(tuple_hash)
        existing = self.rows.get(key)
        if existing is None:
            self.rows[key] = {
                "object": object_id,
                "relation": relation,
                "wildcard": wildcard,
                "first_seen": first_seen,
            }
        else:
            # Keep earliest first_seen; refresh plaintext if it was missing.
            existing["object"] = object_id
            existing["relation"] = relation
            existing["wildcard"] = wildcard
            if first_seen < existing.get("first_seen", first_seen):
                existing["first_seen"] = first_seen

    def annotate(self, tuple_hash: bytes, *, object_id: Optional[str] = None,
                 relation: Optional[str] = None, wildcard: Optional[bool] = None) -> bool:
        """Manually name an opaque tuple's plaintext. Returns True if the row exists."""
        key = self.key_for(tuple_hash)
        row = self.rows.get(key)
        if row is None:
            return False
        if object_id is not None:
            row["object"] = object_id
        if relation is not None:
            row["relation"] = relation
        if wildcard is not None:
            row["wildcard"] = wildcard
        return True

    def ensure(self, tuple_hash: bytes) -> dict:
        """Get or create a (possibly empty) ledger row for a tuple hash."""
        key = self.key_for(tuple_hash)
        row = self.rows.get(key)
        if row is None:
            row = {"object": None, "relation": None, "wildcard": None, "first_seen": 0}
            self.rows[key] = row
        return row

    def lookup(self, tuple_hash: bytes) -> Optional[dict]:
        return self.rows.get(self.key_for(tuple_hash))


class Store:
    """A dacar node store directory and its persistence operations.

    Each CLI invocation builds a :class:`Store`, loads what it needs, mutates
    in memory, and writes back. Nothing is kept running between invocations —
    this is the offline-first, daemon-free model (work doc #2).
    """

    def __init__(self, path: Path, *, identity_override: Optional[str] = None) -> None:
        self.path = Path(path)
        # When set, ``--identity PATH`` overrides the signing identity and is
        # also added to the verify-on-ingest keyring.
        self.identity_override = identity_override

    # -- paths --------------------------------------------------------------
    @property
    def config_path(self) -> Path:
        return self.path / CONFIG_NAME

    @property
    def identity_default_path(self) -> Path:
        return self.path / IDENTITY_NAME

    @property
    def identity_path(self) -> Path:
        return Path(self.identity_override) if self.identity_override else self.identity_default_path

    @property
    def clock_path(self) -> Path:
        return self.path / CLOCK_NAME

    @property
    def state_path(self) -> Path:
        return self.path / STATE_NAME

    @property
    def aliases_path(self) -> Path:
        return self.path / ALIASES_NAME

    @property
    def ledger_path(self) -> Path:
        return self.path / LEDGER_NAME

    @property
    def identities_path(self) -> Path:
        return self.path / IDENTITIES_NAME

    def exists(self) -> bool:
        return self.config_path.exists()

    def ensure(self) -> None:
        """Raise a clear error if the store has not been initialized."""
        if not self.exists():
            raise StoreError(f"store not initialized at {self.path} (run `dacar init`)")

    # -- bootstrap ----------------------------------------------------------
    @classmethod
    def init(
        cls,
        path: Path,
        *,
        salt: Optional[bytes] = None,
        horizon_days: int = DEFAULT_DELETION_HORIZON_DAYS,
        identity_path: Optional[str] = None,
    ) -> "Store":
        """Bootstrap a fresh node store (work doc #2 ``init``).

        Creates the store dir (mode ``0700``), writes the INI config (with the
        node's own identity as the root trust anchor — the v1 bootstrap), and
        initializes empty state, clock, aliases (with the ``self`` alias), and
        ledger. If ``identity_path`` is given that identity is adopted (copied
        in); otherwise a fresh one is generated.
        """
        path = Path(path)
        if path.exists() and not path.is_dir():
            raise StoreError(f"{path} exists and is not a directory")
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, DIR_MODE)
        store = cls(path, identity_override=identity_path)

        # Resolve / create the signing identity.
        if identity_path is not None:
            identity = RNS.Identity.from_file(identity_path)
            if identity is None:
                raise StoreError(f"could not load identity from {identity_path!r}")
            # Adopt by copying into the store at the default path (0600).
            _copy_identity_file(Path(identity_path), store.identity_default_path)
        else:
            identity = _create_identity(store.identity_default_path)

        # Config: own identity is the root trust anchor (v1 bootstrap).
        primary_salt = salt if salt is not None else _generate_salt()
        store._write_config(
            primary_salt=primary_salt,
            legacy_salts=(),
            anchors=[identity.hash],
            authoritative=None,
            horizon_days=horizon_days,
        )

        # Empty persisted state, clock, ledger.
        store.save_state(StateVector(deletion_horizon_days=horizon_days))
        store.save_clock(Clock())
        store.save_ledger(Ledger())

        # Aliases: name the own identity ``self``.
        aliases = AliasRegistry()
        aliases.set_self(identity.hash)
        store.save_aliases(aliases)
        return store

    # -- config (INI) -------------------------------------------------------
    def _read_ini(self) -> configparser.ConfigParser:
        self.ensure()
        parser = configparser.ConfigParser()
        parser.read(self.config_path)
        return parser

    def _write_config(
        self,
        *,
        primary_salt: bytes,
        legacy_salts: Tuple[bytes, ...],
        anchors: List[bytes],
        authoritative: Optional[bytes],
        horizon_days: int,
        rfed_topic: str = RFED_TOPIC,
        rfed_node: Optional[bytes] = None,
    ) -> None:
        parser = configparser.ConfigParser()
        parser["salt"] = {"primary": primary_salt.hex()}
        for i, salt in enumerate(legacy_salts[:MAX_LEGACY_SALTS]):
            parser["salt"][f"legacy{i}"] = salt.hex()
        parser["trust"] = {"anchors": ", ".join(a.hex() for a in anchors)}
        if authoritative is not None:
            parser["trust"]["authoritative"] = authoritative.hex()
        parser["policy"] = {"deletion_horizon_days": str(horizon_days)}
        parser["rfed"] = {"topic": rfed_topic}
        if rfed_node is not None:
            parser["rfed"]["node"] = rfed_node.hex()
        with open(self.config_path, "w") as fh:
            parser.write(fh)
        os.chmod(self.config_path, SECRET_MODE)

    def load_config_raw(self) -> dict:
        """Load the raw config fields as a dict (no Config validation)."""
        parser = self._read_ini()
        primary = _require_hex(parser, "salt", "primary", SALT_SIZE, default=DEFAULT_SALT.hex())
        legacy: List[bytes] = []
        for i in range(MAX_LEGACY_SALTS):
            if parser.has_option("salt", f"legacy{i}"):
                legacy.append(_hex(parser.get("salt", f"legacy{i}"), SALT_SIZE))
        anchors_raw = parser.get("trust", "anchors", fallback="").strip()
        anchors = [
            _hex(h, 16) for h in (s.strip() for s in anchors_raw.split(",")) if h
        ]
        authoritative = None
        if parser.has_option("trust", "authoritative"):
            authoritative = _hex(parser.get("trust", "authoritative"), 16)
        horizon = parser.getint("policy", "deletion_horizon_days",
                                fallback=DEFAULT_DELETION_HORIZON_DAYS)
        rfed_topic = RFED_TOPIC
        rfed_node: Optional[bytes] = None
        if parser.has_section("rfed"):
            rfed_topic = parser.get("rfed", "topic", fallback=RFED_TOPIC)
            if parser.has_option("rfed", "node"):
                node_hex = parser.get("rfed", "node").strip()
                if node_hex:
                    rfed_node = _hex(node_hex, 16)
        return {
            "primary_salt": primary,
            "legacy_salts": tuple(legacy),
            "anchors": anchors,
            "authoritative": authoritative,
            "horizon_days": horizon,
            "rfed_topic": rfed_topic,
            "rfed_node": rfed_node,
        }

    def load_config(self) -> Config:
        """Build a validated :class:`Config` from the INI."""
        raw = self.load_config_raw()
        if not raw["anchors"]:
            raise StoreError(
                "no Root Trust Anchors configured (run `dacar anchor add <hash>`)"
            )
        # The CLI emits its own explicit fail-open warnings; silence the
        # library's audible warning so output stays clean.
        import warnings
        from dacar.config import NullPrivacySaltWarning
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", NullPrivacySaltWarning)
            return Config(
                root_trust_anchors=frozenset(raw["anchors"]),
                primary_salt=raw["primary_salt"],
                legacy_salts=raw["legacy_salts"],
                authoritative_identity=raw["authoritative"],
                deletion_horizon_days=raw["horizon_days"],
            )

    def save_config(
        self,
        *,
        primary_salt: bytes,
        legacy_salts: Tuple[bytes, ...] = (),
        anchors: Optional[List[bytes]] = None,
        authoritative: Optional[bytes] = None,
        horizon_days: Optional[int] = None,
        rfed_topic: Optional[str] = None,
        rfed_node: Optional[bytes] = None,
    ) -> None:
        """Write the INI config, preserving unspecified fields from disk."""
        raw = self.load_config_raw() if self.exists() else {}
        self._write_config(
            primary_salt=primary_salt,
            legacy_salts=legacy_salts if legacy_salts else raw.get("legacy_salts", ()),
            anchors=anchors if anchors is not None else raw.get("anchors", []),
            authoritative=authoritative if authoritative is not None else raw.get("authoritative"),
            horizon_days=horizon_days if horizon_days is not None else raw.get(
                "horizon_days", DEFAULT_DELETION_HORIZON_DAYS
            ),
            rfed_topic=rfed_topic if rfed_topic is not None else raw.get("rfed_topic", RFED_TOPIC),
            rfed_node=rfed_node if rfed_node is not None else raw.get("rfed_node"),
        )

    # -- identity -----------------------------------------------------------
    def load_identity(self) -> Optional[RNS.Identity]:
        """Load the signing identity (``--identity PATH`` override else store's own).

        Returns ``None`` if the override path does not load. The store's own
        identity is expected to exist after ``init``.
        """
        path = self.identity_path
        if self.identity_override is not None:
            identity = RNS.Identity.from_file(str(path))
            if identity is None:
                raise StoreError(f"could not load identity from {path}")
            return identity
        if not path.exists():
            return None
        identity = RNS.Identity.from_file(str(path))
        if identity is None:
            raise StoreError(f"could not load identity from {path}")
        return identity

    def identity_hash(self) -> bytes:
        """Return the signing identity's 16-byte hash (raises if unset)."""
        identity = self.load_identity()
        if identity is None:
            raise StoreError(
                "no signing identity; run `dacar init` or `dacar identity new`"
            )
        return identity.hash

    def rotate_identity(self) -> Tuple[bytes, bytes]:
        """Generate a fresh identity, rotate the self-anchor, return ``(old, new)``."""
        old_hash = None
        old_identity = self.load_identity()
        if old_identity is not None:
            old_hash = old_identity.hash
        new_identity = _create_identity(self.identity_default_path)

        # Update anchors: replace the old own hash with the new one.
        raw = self.load_config_raw()
        anchors = list(raw["anchors"])
        if old_hash is not None and old_hash in anchors:
            anchors.remove(old_hash)
        if new_identity.hash not in anchors:
            anchors.append(new_identity.hash)
        self._write_config(
            primary_salt=raw["primary_salt"],
            legacy_salts=raw["legacy_salts"],
            anchors=anchors,
            authoritative=raw["authoritative"],
            horizon_days=raw["horizon_days"],
            rfed_topic=raw.get("rfed_topic", RFED_TOPIC),
            rfed_node=raw.get("rfed_node"),
        )
        # Re-point the ``self`` alias.
        aliases = self.load_aliases()
        aliases.set_self(new_identity.hash)
        self.save_aliases(aliases)
        return (old_hash if old_hash is not None else b""), new_identity.hash

    def keyring_for_verify(self) -> Keyring:
        """Build a verify-on-ingest keyring from the persisted cache + own identity.

        The durable issuer cache (work doc #5) is loaded as the base so issuers
        observed in a prior session (or seeded via ``identity remember``) are
        resolvable without a live re-announce. The node's own identity is
        registered on top so self-signed Deltas always verify.
        """
        keyring = self.load_keyring()
        own = self.load_identity()
        if own is not None:
            keyring.register_single(own.hash, own.sig_pub_bytes)
        return keyring

    # -- clock (HLC) --------------------------------------------------------
    def load_clock(self) -> Clock:
        clock = Clock()
        if self.clock_path.exists():
            data = self.clock_path.read_bytes()
            if data:
                obj = serialization.unpackb(data)
                if isinstance(obj, dict):
                    clock._last_ms = int(obj.get(b"last_ms", obj.get("last_ms", 0)))
                    clock._logical = int(obj.get(b"logical", obj.get("logical", 0)))
        return clock

    def save_clock(self, clock: Clock) -> None:
        data = serialization.packb({"last_ms": clock._last_ms, "logical": clock._logical})
        self.clock_path.write_bytes(data)
        os.chmod(self.clock_path, PUBLIC_MODE)

    # -- state (CRDT) -------------------------------------------------------
    def load_state(self, config: Optional[Config] = None) -> StateVector:
        horizon = (
            config.deletion_horizon_days if config is not None
            else self.load_config_raw()["horizon_days"]
        )
        if self.state_path.exists():
            data = self.state_path.read_bytes()
            if data:
                # Trusted-local restore of this node's own snapshot.
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", TrustedLocalOnlyWarning)
                    state = StateVector.from_payload(data, deletion_horizon_days=horizon)
                return state
        return StateVector(deletion_horizon_days=horizon)

    def save_state(self, state: StateVector) -> None:
        data = state.to_payload()
        self.state_path.write_bytes(data)
        os.chmod(self.state_path, SECRET_MODE)

    # -- aliases ------------------------------------------------------------
    def load_aliases(self) -> AliasRegistry:
        if self.aliases_path.exists():
            return AliasRegistry.parse(self.aliases_path.read_text(encoding="utf-8"))
        return AliasRegistry()

    def save_aliases(self, aliases: AliasRegistry) -> None:
        self.aliases_path.write_text(aliases.serialize(), encoding="utf-8")
        os.chmod(self.aliases_path, PUBLIC_MODE)

    # -- ledger -------------------------------------------------------------
    def load_ledger(self) -> Ledger:
        ledger = Ledger()
        if self.ledger_path.exists():
            data = self.ledger_path.read_bytes()
            if data:
                obj = serialization.unpackb(data)
                if isinstance(obj, dict):
                    # msgpack may give bytes or str keys depending on options.
                    for key, value in obj.items():
                        k = key.decode("utf-8") if isinstance(key, (bytes, bytearray)) else key
                        row = dict(value) if isinstance(value, dict) else {}
                        ledger.rows[k] = row
        return ledger

    def save_ledger(self, ledger: Ledger) -> None:
        data = serialization.packb(ledger.rows)
        self.ledger_path.write_bytes(data)
        os.chmod(self.ledger_path, SECRET_MODE)

    # -- issuer identity cache (work doc #5) ---------------------------------
    def load_keyring(self) -> Keyring:
        """Load the persisted issuer identity cache (work doc #5).

        Returns an empty :class:`Keyring` if no cache file exists yet. The
        on-disk format is ``{hash_hex: sig_pub_bytes}`` — single-identity
        entries only; threshold-group keysets are a separate (future) item.
        """
        keyring = Keyring()
        if self.identities_path.exists():
            data = self.identities_path.read_bytes()
            if data:
                obj = serialization.unpackb(data)
                if isinstance(obj, dict):
                    for hash_hex, sig_pub in obj.items():
                        h = (hash_hex.decode("utf-8")
                              if isinstance(hash_hex, (bytes, bytearray)) else hash_hex)
                        if isinstance(sig_pub, (bytes, bytearray)) and len(sig_pub) == _PUBLIC_KEY_SIZE:
                            try:
                                keyring.register_single(bytes.fromhex(h), bytes(sig_pub))
                            except ValueError:
                                continue  # skip malformed hash
        return keyring

    def save_keyring(self, keyring: Keyring) -> None:
        """Persist the issuer identity cache (work doc #5).

        Serializes single-identity entries as ``{hash_hex: sig_pub_bytes}``,
        mode ``0600``. Threshold-group keysets are skipped (out of scope: a
        poisoned cache entry causes a signature mismatch → drop, not a trust
        breach — design decision #2).
        """
        obj = {}
        for issuer_hash, keyset in keyring.entries():
            if keyset.threshold == 1 and len(keyset.member_public_keys) == 1:
                obj[issuer_hash.hex()] = bytes(keyset.member_public_keys[0])
        data = serialization.packb(obj)
        self.identities_path.write_bytes(data)
        os.chmod(self.identities_path, SECRET_MODE)


class StoreError(Exception):
    """A recoverable CLI-level store error (bad path, missing init, etc.)."""


# -- helpers ------------------------------------------------------------------


def _create_identity(path: Path) -> RNS.Identity:
    """Generate a fresh RNS Identity and persist it at ``path`` (mode ``0600``)."""
    identity = RNS.Identity(create_keys=True)
    identity.to_file(str(path))
    os.chmod(path, SECRET_MODE)  # RNS writes 0o644; tighten to 0o600.
    return identity


def _copy_identity_file(src: Path, dst: Path) -> None:
    """Copy an identity file into the store at mode ``0600``."""
    import shutil
    shutil.copyfile(src, dst)
    os.chmod(dst, SECRET_MODE)


def _hex(value: str, length: int) -> bytes:
    """Parse a hex string into exactly ``length`` bytes."""
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    raw = bytes.fromhex(value)
    if len(raw) != length:
        raise ValueError(f"expected {length} bytes ({length * 2} hex), got {len(raw)}")
    return raw


def _require_hex(parser: configparser.ConfigParser, section: str, option: str,
                 length: int, *, default: Optional[str] = None) -> bytes:
    if parser.has_option(section, option):
        return _hex(parser.get(section, option), length)
    if default is not None:
        return bytes.fromhex(default)
    raise ValueError(f"missing [{section}] {option}")
