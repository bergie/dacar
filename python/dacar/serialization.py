"""MessagePack transport serialization (Dacar spec §5.3).

Dacar payloads are MessagePack arrays. Hashes and signatures travel as binary
(``bin``) and text fields as ``str``, which is exactly what the ``msgpack``
library produces with ``use_bin_type=True`` for packing and ``raw=False`` for
unpacking.
"""

from __future__ import annotations

import msgpack

#: Canonical packing options: bytes -> bin, ints -> compact unsigned.
_PACK_OPTS = {"use_bin_type": True}

#: Canonical unpacking options: bin -> bytes, str -> str.
_UNPACK_OPTS = {"raw": False, "strict_map_key": False}


def packb(obj: object) -> bytes:
    """Serialize ``obj`` to MessagePack bytes."""
    return msgpack.packb(obj, **_PACK_OPTS)


def unpackb(data: bytes) -> object:
    """Deserialize MessagePack ``data``."""
    return msgpack.unpackb(data, **_UNPACK_OPTS)
