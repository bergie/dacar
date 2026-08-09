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
from typing import Optional

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
