"""RFed (Reticulum Federation) wire-format constants.

Mirrors the canonical wire format in ``RFed/SPEC.md`` ("CANONICAL WIRE FORMAT
— ULTIMATE AUTHORITY") and ``@reticulum/core``'s ``src/rfed/constants.js``.
These values are protocol-invariant: any change silently breaks
interoperability with the Rust ``rfed`` reference node and the JavaScript
``@reticulum/core`` ``RFedClient``.
"""

from __future__ import annotations

#: The 4-byte ASCII magic prefixing the RTID source-identity prelude inside the
#: channel EC envelope. Not length-prefixed, not little-endian — just ``RTID``.
MAGIC_RTID = b"RTID"

#: Length of the RTID magic prelude.
MAGIC_LENGTH = 4

#: Length of an Identity public-key bundle (X25519 ‖ Ed25519).
PUBLIC_KEY_LENGTH = 64

#: Length of a 16-byte channel/destination hash (``TRUNCATED_HASHLENGTH // 8``).
HASH_LENGTH = 16

#: Byte length of the full RTID prelude: magic(4) ‖ sender_pub(64).
PRELUDE_LENGTH = MAGIC_LENGTH + PUBLIC_KEY_LENGTH  # 68

#: Proof-of-work stamp expansion rounds for rfed channel messages.
#:
#: Deliberately **16** (different from LXMF propagation-node stamps' 1000 and
#: regular message stamps' 3000). Bumping it silently invalidates every cached
#: ``stamp_cost`` and every in-flight stamp, so it must never change without a
#: protocol-version bump.
STAMP_EXPAND_ROUNDS = 16

#: Size in bytes of an LXMF proof-of-work stamp (``HASHLENGTH // 8`` = 32).
STAMP_SIZE = 32

#: LXMF application + aspect name for a ``delivery`` destination.
LXMF_DELIVERY_NAME = "lxmf.delivery"

#: Modern split rfed destination names (SPEC §2). All share the node identity.
CHANNEL_SUBSCRIBE_NAME = "rfed.channel.subscribe"
CHANNEL_UNSUBSCRIBE_NAME = "rfed.channel.unsubscribe"
CHANNEL_PUBLISH_NAME = "rfed.channel.publish"
CHANNEL_PULL_NAME = "rfed.channel.pull"
#: The client's own inbound delivery destination name.
DELIVERY_NAME = "rfed.delivery"

#: ``/rfed/subscribe`` request path.
SUBSCRIBE_PATH = "/rfed/subscribe"
#: ``/rfed/unsubscribe`` request path.
UNSUBSCRIBE_PATH = "/rfed/unsubscribe"
#: ``/rfed/pull`` request path.
PULL_PATH = "/rfed/pull"

__all__ = [
    "MAGIC_RTID",
    "MAGIC_LENGTH",
    "PUBLIC_KEY_LENGTH",
    "HASH_LENGTH",
    "PRELUDE_LENGTH",
    "STAMP_EXPAND_ROUNDS",
    "STAMP_SIZE",
    "LXMF_DELIVERY_NAME",
    "CHANNEL_SUBSCRIBE_NAME",
    "CHANNEL_UNSUBSCRIBE_NAME",
    "CHANNEL_PUBLISH_NAME",
    "CHANNEL_PULL_NAME",
    "DELIVERY_NAME",
    "SUBSCRIBE_PATH",
    "UNSUBSCRIBE_PATH",
    "PULL_PATH",
]
