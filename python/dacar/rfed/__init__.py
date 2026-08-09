"""Self-contained RFed (Reticulum Federation) channel client.

A from-scratch Python port of the canonical ``@reticulum/core`` ``RFedClient``
(JS) and the ``RFed/SPEC.md`` "CANONICAL WIRE FORMAT" (Rust). There is no
published Python RFed client library, so Dacar ships one here. The subpackage
is structured to be extractable into its own published library later (out of
scope for the Dacar work item that introduced it).

It depends only on ``rns`` + ``msgpack`` (+ ``cryptography`` via ``rns``) — the
same stack the rest of the Python implementation uses. The pure codec modules
(:mod:`dacar.rfed.constants`, :mod:`dacar.rfed.channel`, :mod:`dacar.rfed._lxmf`,
:mod:`dacar.rfed.blob`, :mod:`dacar.rfed.stamp`) work **without a running
Reticulum**; only :class:`dacar.rfed.client.RFedClient`'s network methods need
a live transport (``RNS.Destination`` / ``RNS.Link`` creation).

Submodules:
- :mod:`dacar.rfed.constants` — wire-format constants.
- :mod:`dacar.rfed.channel`     — deterministic channel derivation.
- :mod:`dacar.rfed._lxmf`        — minimal canonical LXMF wire codec.
- :mod:`dacar.rfed.blob`         — Phase-0 RTID envelope (wrap/unwrap).
- :mod:`dacar.rfed.stamp`        — rfed PoW stamp contract.
- :mod:`dacar.rfed.client`      — ``RFedClient`` (subscribe/publish/pull/listen).
"""

from __future__ import annotations

__all__: list[str] = []  # submodules imported explicitly by callers
