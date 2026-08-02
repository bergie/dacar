"""Shared headless RNS.Reticulum fixture for transport smoketests.

Starts one transport-disabled, no-interface Reticulum for the whole test process
so we can build real RNS Identities / Destinations / LXMF messages offline -- no
live network, deterministic. Safe to call from any number of TestCases
(idempotent); RNS's background threads mean we never tear it down.
"""

from __future__ import annotations

import os
import tempfile

import RNS

_started = False
_cfg_dir = None


def ensure_headless() -> None:
    """Ensure a headless RNS.Reticulum exists for this process."""
    global _started, _cfg_dir
    if _started:
        return
    if RNS.Reticulum.get_instance() is not None:
        _started = True
        return
    _cfg_dir = tempfile.mkdtemp(prefix="dacar-rns-")
    with open(os.path.join(_cfg_dir, "config"), "w") as f:
        f.write("[reticulum]\nenable_transport = False\nshare_instance = No\n\n[interfaces]\n")
    RNS.Reticulum(_cfg_dir)
    _started = True
