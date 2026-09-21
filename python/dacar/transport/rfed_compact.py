"""Dacar compact inner format for RFed channels (§11.1.1).

For broadcasting Dacar Deltas over an RFed channel, the full LXMF envelope is
redundant — a §5.3 Delta is already self-addressed (Issuer Hash, field [0]),
self-timed (HLC, field [3]) and self-signed (Ed25519, field [7]) — and its
~111 bytes of framing push a typical 170-byte Delta past the 500-byte RNS
MTU. Dacar therefore reuses the rfed RTID prelude but carries the raw Delta
in place of the LXMF tail::

    plaintext    = "RTID"(4) ‖ sender_identity_pub(64) ‖ delta
    inner_blob   = EC_encrypt(channel_identity.X25519_pub, plaintext)
    rfed_payload = channel_hash(16) ‖ inner_blob ‖ stamp(32)?

The Delta's own signature is the authenticity check at verify-on-ingest
(§11.2, :meth:`dacar.delta.DeltaReceiver.apply_payload`); the prelude's
``sender_identity_pub`` only identifies the transport sender. RFed treats
``inner_blob`` opaquely, so this is a private agreement between Dacar
publishers and subscribers, invisible to the Rust/JS RFed nodes and to other
RFed channel applications (keyed by ``channel_hash``).

The generic RTID envelope, stamp contract, and ``RFedClient`` this builds on
live in the standalone ``rfed`` package
(https://github.com/bergie/rfed-python); this module holds only the
Dacar-specific compact format, extracted from the former
``dacar/rfed/blob.py`` when that client was released as its own pip package.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import RNS

from rfed.blob import RfedPayload
from rfed.channel import delivery_hash_for
from rfed.constants import MAGIC_LENGTH, MAGIC_RTID, PRELUDE_LENGTH
from rfed.stamp import generate_channel_stamp

__all__ = [
    "DecodedDacarDelta",
    "wrap_dacar_delta",
    "unwrap_dacar_delta",
]


@dataclass(frozen=True)
class DecodedDacarDelta:
    """A decoded Dacar compact inner format (§11.1.1) channel message.

    Unlike the generic rfed LXMF envelope, there is no envelope signature to
    verify here: the carried ``delta`` is self-signed (§5.3 field [7]) and is
    authenticated downstream by :meth:`dacar.delta.DeltaReceiver.apply_payload`
    (verify-on-ingest, §11.2). ``sender_identity`` is reconstructed from the
    RTID prelude's public key purely so the caller can attribute/seed it.
    """

    delta: bytes
    sender_pub: bytes
    sender_identity: RNS.Identity


def wrap_dacar_delta(
    *,
    channel_identity: RNS.Identity,
    sender_identity: RNS.Identity,
    delta: bytes,
    stamp_cost: Optional[int] = None,
) -> RfedPayload:
    """Wrap a §5.3 Delta in the Dacar compact inner format (§11.1.1).

    Builds ``plaintext = MAGIC_RTID ‖ sender_identity_pub(64) ‖ delta``,
    EC-encrypts it to the channel identity, and frames it with the channel
    hash + optional PoW stamp — identical framing to
    :func:`rfed.blob.wrap_channel_message` but carrying the raw Delta instead
    of an LXMF tail. The Delta's own Ed25519 signature (field [7]) is the
    authenticity check; no envelope signature is added, so this stays well
    under the 500-byte RNS MTU for a typical Delta.

    Parameters
    ----------
    channel_identity:
        The derived channel :class:`RNS.Identity` (holds the X25519 key the
        ``inner_blob`` is encrypted to).
    sender_identity:
        The publishing node's :class:`RNS.Identity`; supplies the prelude
        public key (and, for LXMF messages, the signature — unused here).
    delta:
        The raw §5.3 transport payload (already signed by the Issuer).
    stamp_cost:
        Cached PoW stamp cost advertised by the node (from the last
        :meth:`rfed.client.RFedClient.subscribe`). ``None``/``0`` ⇒ no stamp
        appended.
    """
    channel_hash = channel_identity.hash
    sender_pub = sender_identity.get_public_key()
    plaintext = MAGIC_RTID + sender_pub + bytes(delta)
    inner_blob = channel_identity.encrypt(plaintext)

    stamp: Optional[bytes] = None
    if stamp_cost and stamp_cost > 0:
        stamp, _ = generate_channel_stamp(channel_hash, inner_blob, stamp_cost)

    rfed_payload = (
        bytes(channel_hash) + bytes(inner_blob) + (bytes(stamp) if stamp else b"")
    )
    return RfedPayload(
        rfed_payload=rfed_payload,
        channel_hash=bytes(channel_hash),
        channel_delivery_hash=delivery_hash_for(channel_identity),
        inner_blob=bytes(inner_blob),
        stamp=stamp,
    )


def unwrap_dacar_delta(
    *, inner_blob: bytes, channel_identity: RNS.Identity
) -> DecodedDacarDelta:
    """Decrypt a Dacar compact inner format ``inner_blob`` (§11.1.1).

    Inverse of :func:`wrap_dacar_delta`: EC-decrypts with the channel
    identity, verifies the RTID magic, recovers the sender public key, and
    returns the carried ``delta`` bytes. The Delta is **not** signature-
    verified here — that is deferred to verify-on-ingest
    (:meth:`dacar.delta.DeltaReceiver.apply_payload`, §11.2), which
    authenticates the Delta's own Ed25519 signature (field [7]) against the
    Issuer Hash (field [0]) via the :class:`KeyResolver`. A forged or stale
    Delta is thus dropped before it can mutate the CRDT, exactly as for
    LXMF/optical delivery.
    """
    plaintext = channel_identity.decrypt(bytes(inner_blob))
    if plaintext is None:
        raise ValueError("rfed inner_blob EC-decryption failed (wrong channel?)")
    plaintext = bytes(plaintext)
    if len(plaintext) < PRELUDE_LENGTH:
        raise ValueError(
            f"rfed prelude plaintext too short: {len(plaintext)} bytes "
            f"(need at least {PRELUDE_LENGTH} for the RTID prelude)"
        )

    # Verify magic — receivers MUST refuse blobs without "RTID".
    magic = plaintext[:MAGIC_LENGTH]
    if magic != MAGIC_RTID:
        raise ValueError(
            f'rfed prelude magic mismatch: expected "RTID", got {magic!r}'
        )

    sender_pub = plaintext[MAGIC_LENGTH:PRELUDE_LENGTH]
    delta = plaintext[PRELUDE_LENGTH:]

    sender_identity = RNS.Identity(create_keys=False)
    sender_identity.load_public_key(sender_pub)

    return DecodedDacarDelta(
        delta=bytes(delta),
        sender_pub=bytes(sender_pub),
        sender_identity=sender_identity,
    )
