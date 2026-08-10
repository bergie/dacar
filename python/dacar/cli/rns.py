"""RNS session boot and identity announce helpers for online commands.

Online commands (``grant --publish``, ``sync``) attach-or-spawn a Reticulum
instance per invocation — the same one-shot model used by ``rnx`` / ``lxsend``
/ ``lxmsg``. No long-running daemon: store-and-forward (rfed deferred queue,
LXMF propagation) means a node only needs transient online windows to push or
pull, then exit (work doc #4).

Config resolution priority (work doc #4):

1. ``--rns-config DIR`` (explicit flag)
2. ``$DACAR_RNS_CONFIG``
3. ``~/.reticulum`` if a config exists there (the user's shared rnsd — standard
   RNS behavior, matching ``rnx``/``lxsend``)
4. Otherwise: dacar creates ``<store>/rns/`` with a default config and uses that

The default config respects the RNS attach-or-spawn convention: with
``share_instance = Yes``, RNS attaches to a running shared instance if present,
else spawns standalone using the config's interfaces. A ``Default interface``
of type ``AutoInterface`` is included by default so two nodes on the same link
can find each other with zero configuration. Users add their own interfaces by
editing the config or pointing ``--rns-config`` at their own — AutoInterface is
a *default entry*, not a hardcoded programmatic fallback.
"""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

import RNS

from dacar.naming import APP_NAME

#: Environment variable overriding the RNS config directory.
ENV_RNS_CONFIG = "DACAR_RNS_CONFIG"

#: Default RNS user config directory (the shared rnsd).
USER_RNS_DIR = "~/.reticulum"

__all__ = [
    "ENV_RNS_CONFIG",
    "USER_RNS_DIR",
    "DEFAULT_CONFIG",
    "resolve_config_dir",
    "ensure_default_config",
    "boot",
    "announce_identity",
    "ensure_node_identity",
    "DEFAULT_NODE_DISCOVERY_TIMEOUT",
    "DacarAnnounceHandler",
    "register_announce_handler",
]


#: The default RNS config dacar writes when none exists. ``share_instance = Yes``
#: gives the attach-or-spawn precedence: shared rnsd first, else standalone with
#: the AutoInterface default; users edit this or point ``--rns-config`` at their
#: own config to add interfaces.
DEFAULT_CONFIG = """\
[reticulum]
  share_instance = Yes
  enable_transport = False

[interfaces]
  [[Default interface]]
    type = AutoInterface
    enabled = Yes
"""


def resolve_config_dir(
    *, explicit: Optional[str] = None, store_path: Optional[str] = None
) -> str:
    """Resolve the RNS config directory per the priority order (work doc #4)."""
    # 1. explicit --rns-config
    if explicit:
        return os.path.expanduser(explicit)
    # 2. environment
    env = os.environ.get(ENV_RNS_CONFIG)
    if env:
        return os.path.expanduser(env)
    # 3. ~/.reticulum if it already has a config (the user's shared rnsd)
    user = os.path.expanduser(USER_RNS_DIR)
    if os.path.isfile(os.path.join(user, "config")):
        return user
    # 4. <store>/rns — create a default config there
    if store_path is None:
        store_path = os.path.expanduser("~/.dacar")
    store_rns = os.path.join(store_path, "rns")
    ensure_default_config(store_rns)
    return store_rns


def ensure_default_config(config_dir: str) -> None:
    """Write the default dacar RNS config if none exists at ``config_dir``.

    Never clobbers an existing config (the user's own or a prior init).
    """
    path = os.path.join(config_dir, "config")
    if os.path.exists(path):
        return
    os.makedirs(config_dir, exist_ok=True)
    with open(path, "w") as fh:
        fh.write(DEFAULT_CONFIG)


def boot(config_dir: str) -> "RNS.Reticulum":
    """Start (attach-or-spawn) a Reticulum using ``config_dir``.

    With ``share_instance = Yes`` (the default config), RNS attaches to a
    running shared instance if one exists, else spawns standalone using the
    config's interfaces. This is the one-shot attach-or-spawn model.
    """
    return RNS.Reticulum(config_dir)


def announce_identity(identity: RNS.Identity) -> bytes:
    """Announce the node's identity on the ``dacar.node`` destination.

    Any announced destination under an identity makes that identity recallable
    by peers via :meth:`RNS.Identity.recall` with ``from_identity_hash=True`` —
    the announce invariant (§11.2.4): without it, receivers drop the node's
    signed Deltas as "unknown issuer" because the :class:`RnsIdentityResolver`
    cannot recall the issuer's public key. Returns the announced destination
    hash.

    Both online commands (``grant --publish``, ``sync``) call this on start
    *before* publishing or pulling — it is non-negotiable (work doc #4).
    """
    dest = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        APP_NAME,
        "node",
    )
    dest.announce()
    return dest.hash


#: How long :func:`ensure_node_identity` waits for a path-response announce
#: after sending a ``path?`` request before giving up, in seconds.
DEFAULT_NODE_DISCOVERY_TIMEOUT = 15.0


def ensure_node_identity(
    node_hash: bytes,
    *,
    timeout: float = DEFAULT_NODE_DISCOVERY_TIMEOUT,
    poll_interval: float = 0.25,
    on_request: Optional[Callable[[], None]] = None,
) -> "RNS.Identity":
    """Recall a node's identity, proactively requesting its path if unknown.

    When ``--node <hash>`` resolves to an rfed destination whose announce hasn't
    been received (or persisted) yet, :func:`RNS.Identity.recall` returns
    ``None`` and the rfed client can't open a link — failing with
    ``rfed node identity unknown for <hash>; wait for its announce``. Rather
    than fail immediately, this sends a ``path?`` request for the destination
    and polls the recall store until the node's path-response announce
    populates it (or ``timeout`` elapses), then returns the identity.

    The rfed node announces every ``rfed.*`` destination under one shared
    identity, so a path request for any of them is answered with an announce
    that makes that identity recallable by destination hash.

    ``on_request`` (if given) is invoked once when the path request is sent, so
    the CLI can surface "requesting node identity…" progress to the user.
    Raises :class:`ValueError` (the same message the rfed client raises) if
    still unknown after ``timeout`` — so callers that skip this helper see no
    behavior change.
    """
    node_hash = bytes(node_hash)
    identity = RNS.Identity.recall(node_hash)
    if identity is not None:
        return identity
    # Not yet known — proactively request the destination's path (§7.1). The
    # rfed node answers with a path-response announce (§7.2.4) that populates
    # the recall store; poll until it arrives or the timeout elapses.
    if on_request is not None:
        on_request()
    RNS.Transport.request_path(node_hash)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        identity = RNS.Identity.recall(node_hash)
        if identity is not None:
            return identity
        time.sleep(poll_interval)
    raise ValueError(
        f"rfed node identity unknown for {node_hash.hex()}; "
        "wait for its announce"
    )


class DacarAnnounceHandler:
    """Announce handler that seeds the durable issuer cache (work doc #5).

    RNS's own persistence policy differs across runtimes: Python RNS persists
    *all* validated announces to disk, but reticulum-js persists only
    *contacted*/*favorited* destinations — and in the rfed model a peer never
    sends a routable packet to the issuer directly, so passively-observed
    announces are lost on restart. This handler makes dacar-owned durability
    independent of the RNS runtime: on a validated ``dacar.node`` announce it
    registers the issuer's Ed25519 public key into the persisted
    :class:`~dacar.verifier.Keyring` (the ``RnsIdentityResolver`` fallback).

    Scoped to the ``dacar`` app (design decision #3): only ``dacar.node``
    announces seed the cache; arbitrary RNS announces are ignored (dacar is not
    a general identity directory). The filter is applied in
    :meth:`received_announce` (not via ``aspect_filter``) so it is directly
    testable without a live RNS transport.
    """

    #: ``None`` = receive all announces; we filter by app in the callback.
    aspect_filter = None

    def __init__(
        self,
        keyring: "object",
        on_save: Optional[Callable[["object"], None]] = None,
    ) -> None:
        self._keyring = keyring
        self._on_save = on_save
        self.seeded: int = 0  # count of announces that seeded the cache (test aid)

    def received_announce(
        self, destination_hash: bytes, announced_identity: RNS.Identity,
        app_data=None, *args, **kwargs,
    ) -> None:
        """Cache a ``dacar.node`` announce's issuer pubkey (design decision #3)."""
        # Only seed from dacar.node announces: verify the destination hash
        # matches what a dacar.node destination under this identity would be.
        expected = RNS.Destination.hash(announced_identity, APP_NAME, "node")
        if bytes(destination_hash) != bytes(expected):
            return  # not a dacar.node announce — ignore (dacar is not a directory)
        self._keyring.register_single(announced_identity.hash, announced_identity.sig_pub_bytes)
        self.seeded += 1
        if self._on_save is not None:
            self._on_save(self._keyring)


def register_announce_handler(
    keyring: "object",
    on_save: Optional[Callable[["object"], None]] = None,
) -> DacarAnnounceHandler:
    """Register a :class:`DacarAnnounceHandler` with the live RNS transport.

    Called by every online command (``grant --publish``, ``sync``) after
    booting RNS, so passively-observed ``dacar.node`` announces seed the durable
    cache during the command's online window (work doc #5, design decision #4).
    """
    handler = DacarAnnounceHandler(keyring, on_save=on_save)
    RNS.Transport.register_announce_handler(handler)
    return handler

def discover_rfed_node(
    rns: "object",
    timeout: int = 30000,
) -> bytes:
    """Autodiscover an rfed node from its ``rfed.node`` announce.

    Listens for a validated ``rfed.node`` announce on the live RNS transport
    and returns that announce's destination hash — the rfed node's canonical
    identifier (the same hash ``--node <hash>`` accepts and
    :class:`~dacar.rfed.client.RFedClient` recalls to open a link).

    The rfed daemon is an external process (dacar ships only the client); it
    announces ``rfed.node`` and the ``rfed.channel.*`` service destinations
    under one shared identity. A ``dacar.node`` announce is a *different*
    thing — it is a dacar peer advertising its own signing identity (the
    announce invariant, §11.2.4), not an rfed transport node. Discovery
    therefore filters for ``rfed.node`` announces, not ``dacar.node``, and
    returns the announced destination hash directly (no derivation — the
    announce *is* the node hash).

    Args:
        rns: A booted Reticulum instance.
        timeout: Timeout in milliseconds (default: 30000).

    Returns:
        The ``rfed.node`` destination hash (16 bytes) of the discovered node.

    Raises:
        CliError: If no ``rfed.node`` announce is received within the timeout.
        RuntimeError: If RNS transport is not available.

    Example:
        >>> rns = boot(config_dir)
        >>> node_hash = discover_rfed_node(rns)  # wait for an rfed.node announce
    """
    from threading import Event
    from dacar.cli.commands import CliError

    transport = getattr(rns, "transport", None)
    if transport is None:
        raise RuntimeError("RNS transport not available for discovery")
    if not hasattr(transport, "add_announce_handler"):
        raise RuntimeError("RNS transport does not support announce handlers")

    timeout_s = max(0, timeout) / 1000.0
    found = Event()
    box: dict = {"hash": None}

    def on_announce(
        destination_hash: bytes,
        announced_identity: "object",
        app_data=None,
        *args,
        **kwargs,
    ) -> None:
        # Only consider rfed.node announces: the destination hash must match
        # what an "rfed.node" SINGLE destination under this identity would be
        # (nameHash = SHA-256("rfed.node")[:10]; destHash =
        # SHA-256(nameHash ‖ identityHash)[:16]). The rfed node announces
        # rfed.node + the rfed.channel.* services under one identity; only the
        # rfed.node hash is the canonical node identifier.
        expected = RNS.Destination.hash(announced_identity, "rfed", "node")
        if bytes(destination_hash) != bytes(expected):
            return  # not an rfed.node announce
        if box["hash"] is None:
            box["hash"] = bytes(destination_hash)
            found.set()

    transport.add_announce_handler(on_announce)
    try:
        # RNS dispatches announce callbacks on a daemon thread; Event.wait
        # returns True as soon as one rfed.node announce arrives, or False on
        # timeout — no signal.alrm (which is main-thread-only and broken in
        # nested CLI contexts).
        found.wait(timeout_s)
    finally:
        if hasattr(transport, "remove_announce_handler"):
            transport.remove_announce_handler(on_announce)

    if box["hash"] is None:
        raise CliError(
            f"no rfed.node announce received within {timeout}ms "
            "(ensure an rfed node is reachable and announcing)",
        )
    return box["hash"]
