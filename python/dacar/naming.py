"""RNS naming conventions for the Dacar policy plane (spec §8, §11).

These are pure, dependency-free constants. Two scopes:

* **RFED_TOPIC** is a *deployment-overridable default*. RFed is a broadcast
  (many-to-many) medium, so deployments sharing an RNS network SHOULD set a
  deployment-specific topic to isolate their policy feeds (verify-on-ingest
  limits cross-feed damage, but does not stop the bandwidth cost or the risk of
  shared root anchors).
* **CHALLENGE_DESTINATION** and **LXMF_DELIVERY_TITLE** are *fixed
  discriminators*. The §8 Challenge and §11.2 LXMF delivery are addressed
  point-to-point to a specific Identity, so RNS derives isolation from the
  destination *hash* (which embeds the target Identity), not from this name.

Both the pure core and the (optional) transport adapters reference these, so
the on-wire naming is defined in one place and stays consistent across language
implementations. Transport adapters accept overrides (e.g. ``topic=RFED_TOPIC``)
for deployment-specific values.
"""

from __future__ import annotations

#: The RNS App Name under which all Dacar services live (§8, §11).
APP_NAME = "dacar"

#: Aspects of the §8 Authoritative Challenge destination (App ``dacar``).
CHALLENGE_ASPECTS = ("auth", "v1")

#: The full dotted name of the §8 Authoritative Challenge destination.
CHALLENGE_DESTINATION = ".".join((APP_NAME, *CHALLENGE_ASPECTS))  # "dacar.auth.v1"

#: RFed topic for many-to-many CRDT convergence (§11.1). Deployment-overridable
#: default -- RFed is broadcast, so shared-network deployments SHOULD set a
#: distinct topic to isolate their feeds.
RFED_TOPIC = "dacar.policy.v1"

#: LXMF message title for targeted Delta delivery (§11.2).
LXMF_DELIVERY_TITLE = "dacar/sync/delta"
