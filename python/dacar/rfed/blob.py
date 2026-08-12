"""rfed channel message envelope codec (the "RTID" prelude).

A channel message is a propagation-style LXMF message wrapped in the RTID
source-identity prelude, then EC-encrypted to the channel identity. The
resulting ``inner_blob`` is what rfed stores, syncs, and fans out verbatim —
rfed never decrypts or inspects it.

Layered wire format (``RFed/SPEC.md`` "CANONICAL WIRE FORMAT")::

    plaintext    = "RTID"(4) ‖ sender_identity_pub(64) ‖ LXMF_tail
    LXMF_tail    = source_hash(16) ‖ signature(64) ‖ msgpack_payload
    inner_blob   = EC_encrypt(channel_identity.X25519_pub, plaintext)
    rfed_payload = channel_hash(16) ‖ inner_blob ‖ stamp(32)

``source_hash`` is the sender's ``lxmf.delivery`` *destination* hash —
``truncated_hash(name_hash("lxmf.delivery") ‖ identity_hash)`` — NOT the bare
identity hash. Integrity is the LXMF Ed25519 signature; cache poisoning is
impossible because reaching the EC-decrypt step already required the channel
private key (i.e. an authorised subscriber).

Dacar compact inner format (§11.1)
--------------------------------
For broadcasting Dacar Deltas, the full LXMF envelope is redundant — a §5.3
Delta is already self-addressed (Issuer Hash, field [0]), self-timed (HLC,
field [3]) and self-signed (Ed25519, field [7]) — and its ~111 bytes of
framing push a typical 170-byte Delta past the 500-byte RNS MTU. Dacar
therefore reuses the RTID prelude but carries the raw Delta in place of the
LXMF tail (see :func:`wrap_dacar_delta` / :func:`unwrap_dacar_delta`)::

    plaintext    = "RTID"(4) ‖ sender_identity_pub(64) ‖ delta
    inner_blob   = EC_encrypt(channel_identity.X25519_pub, plaintext)
    rfed_payload = channel_hash(16) ‖ inner_blob ‖ stamp(32)?

The Delta's own signature is the authenticity check at verify-on-ingest
(§11.2, :meth:`DeltaReceiver.apply_payload`); the prelude's
``sender_identity_pub`` only identifies the transport sender. RFed treats
``inner_blob`` opaquely, so this is a private agreement between Dacar
publishers and subscribers, invisible to the Rust/JS RFed nodes and to other
RFed channel applications (keyed by ``channel_hash``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import RNS

from dacar.rfed._lxmf import DESTINATION_LENGTH, LxmfMessage
from dacar.rfed.channel import delivery_hash_for
from dacar.rfed.constants import (
    HASH_LENGTH,
    MAGIC_LENGTH,
    MAGIC_RTID,
    PRELUDE_LENGTH,
    STAMP_SIZE,
)
from dacar.rfed.stamp import generate_channel_stamp

__all__ = [
    "RfedPayload",
    "DecodedChannelMessage",
    "wrap_channel_message",
    "parse_fanout_payload",
    "parse_send_payload",
    "unwrap_channel_message",
    "DecodedDacarDelta",
    "wrap_dacar_delta",
    "unwrap_dacar_delta",
]


@dataclass(frozen=True)
class RfedPayload:
    """A fully-wrapped rfed SEND payload and its constituent parts."""

    rfed_payload: bytes
    channel_hash: bytes
    channel_delivery_hash: bytes
    inner_blob: bytes
    stamp: Optional[bytes]


@dataclass
class DecodedChannelMessage:
    """A decoded channel fanout message."""

    message: LxmfMessage
    sender_pub: bytes
    sender_identity: RNS.Identity
    source_hash: bytes
    signature_valid: bool


@dataclass(frozen=True)
class DecodedDacarDelta:
    """A decoded Dacar compact inner format (§11.1) channel message.

    Unlike :class:`DecodedChannelMessage`, there is no envelope signature to
    verify here: the carried ``delta`` is self-signed (§5.3 field [7]) and is
    authenticated downstream by :meth:`DeltaReceiver.apply_payload`
    (verify-on-ingest, §11.2). ``sender_identity`` is reconstructed from the
    RTID prelude's public key purely so the caller can attribute/seed it.
    """

    delta: bytes
    sender_pub: bytes
    sender_identity: RNS.Identity


def wrap_channel_message(
    *,
    channel_identity: RNS.Identity,
    sender_identity: RNS.Identity,
    sender_lxm_delivery_hash: bytes,
    lxm_message: LxmfMessage,
    stamp_cost: Optional[int] = None,
) -> RfedPayload:
    """Wrap an LXMF message into a rfed channel SEND payload.

    The LXMF message is serialised (signed by ``sender_identity``), the RTID
    prelude + sender public key are prepended to the LXMF tail, the whole thing
    is EC-encrypted to the channel identity, and the channel hash + optional PoW
    stamp are framed around it.

    ``lxm_message.destination_hash`` / ``source_hash`` are forced to the correct
    ``lxmf.delivery`` hashes (channel and sender respectively) so the classic
    "source_hash is the identity hash" bug cannot occur.
    """
    channel_hash = channel_identity.hash
    channel_delivery_hash = delivery_hash_for(channel_identity)

    # Force correct LXMF addressing: source_hash MUST be the sender's
    # lxmf.delivery destination hash, never the bare identity hash.
    lxm_message.destination_hash = bytes(channel_delivery_hash)
    lxm_message.source_hash = bytes(sender_lxm_delivery_hash)

    wire = lxm_message.serialize(sender_identity)
    sender_pub = sender_identity.get_public_key()
    # LXMF tail = wire after the destination hash: source ‖ signature ‖ payload.
    lxmf_tail = wire[DESTINATION_LENGTH:]

    plaintext = MAGIC_RTID + sender_pub + lxmf_tail
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
        channel_delivery_hash=bytes(channel_delivery_hash),
        inner_blob=bytes(inner_blob),
        stamp=stamp,
    )


def parse_fanout_payload(payload: bytes) -> tuple:
    """Split a fanout payload ``[ channel_hash(16) ‖ inner_blob ]``.

    The fanout hop carries no stamp (it was validated and stripped at ingest).
    """
    if len(payload) < HASH_LENGTH:
        raise ValueError(
            f"rfed fanout payload too short: {len(payload)} bytes "
            f"(need at least {HASH_LENGTH})"
        )
    return payload[:HASH_LENGTH], payload[HASH_LENGTH:]


def parse_send_payload(payload: bytes) -> tuple:
    """Split a SEND payload ``[ channel_hash(16) ‖ inner_blob ‖ stamp(32) ]``.

    Use when a stamp is known to be present (the node's ``stamp_cost`` is
    non-nil); use :func:`parse_fanout_payload` for the stamp-free fanout form.
    """
    min_len = HASH_LENGTH + STAMP_SIZE
    if len(payload) < min_len:
        raise ValueError(
            f"rfed SEND payload too short: {len(payload)} bytes "
            f"(need at least {min_len})"
        )
    return (
        payload[:HASH_LENGTH],
        payload[HASH_LENGTH : len(payload) - STAMP_SIZE],
        payload[len(payload) - STAMP_SIZE :],
    )


def unwrap_channel_message(
    *, inner_blob: bytes, channel_identity: RNS.Identity, channel_delivery_hash: bytes
) -> DecodedChannelMessage:
    """Decrypt and reconstruct an LXMF message from a channel ``inner_blob``.

    Inverse of :func:`wrap_channel_message`: EC-decrypts with the channel
    identity, verifies the RTID magic, extracts the embedded sender public key,
    and feeds the reconstructed LXMF wire block to
    :meth:`LxmfMessage.deserialize`. The sender identity is cached via
    :func:`RNS.Identity.remember` so subsequent messages from the same sender
    validate without the prelude (best-effort).

    The returned ``signature_valid`` is **the** integrity check: a forged
    ``sender_identity_pub`` produces a signature mismatch.
    """
    plaintext = channel_identity.decrypt(bytes(inner_blob))
    if plaintext is None:
        raise ValueError("rfed inner_blob EC-decryption failed (wrong channel?)")
    plaintext = bytes(plaintext)
    if len(plaintext) < PRELUDE_LENGTH + DESTINATION_LENGTH:
        raise ValueError(
            f"rfed prelude plaintext too short: {len(plaintext)} bytes"
        )

    # Verify magic — receivers MUST refuse blobs without "RTID".
    magic = plaintext[:MAGIC_LENGTH]
    if magic != MAGIC_RTID:
        raise ValueError(
            f'rfed prelude magic mismatch: expected "RTID", got {magic!r}'
        )

    sender_pub = plaintext[MAGIC_LENGTH:PRELUDE_LENGTH]
    lxmf_tail = plaintext[PRELUDE_LENGTH:]

    # Reconstruct the canonical LXMF block: dest_hash(16) ‖ source ‖ sig ‖ payload.
    full_wire = bytes(channel_delivery_hash) + lxmf_tail
    message = LxmfMessage.deserialize(full_wire, sender_pub)

    sender_identity = RNS.Identity(create_keys=False)
    sender_identity.load_public_key(sender_pub)

    # Cache the sender identity so future messages validate without the prelude.
    # Best-effort: decode must still succeed without it.
    try:
        RNS.Identity.remember(
            message.hash or message.source_hash,
            message.source_hash,
            sender_pub,
            None,
        )
    except Exception:
        pass

    return DecodedChannelMessage(
        message=message,
        sender_pub=bytes(sender_pub),
        sender_identity=sender_identity,
        source_hash=message.source_hash,
        signature_valid=message.signature_validated,
    )


# ---------------------------------------------------------------------------
# Dacar compact inner format (§11.1)
# ---------------------------------------------------------------------------


def wrap_dacar_delta(
    *,
    channel_identity: RNS.Identity,
    sender_identity: RNS.Identity,
    delta: bytes,
    stamp_cost: Optional[int] = None,
) -> RfedPayload:
    """Wrap a §5.3 Delta in the Dacar compact inner format (§11.1).

    Builds ``plaintext = MAGIC_RTID ‖ sender_identity_pub(64) ‖ delta``,
    EC-encrypts it to the channel identity, and frames it with the channel
    hash + optional PoW stamp — identical framing to :func:`wrap_channel_message`
    but carrying the raw Delta instead of an LXMF tail. The Delta's own Ed25519
    signature (field [7]) is the authenticity check; no envelope signature is
    added, so this stays well under the 500-byte RNS MTU for a typical Delta.

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
        :meth:`RFedClient.subscribe`). ``None``/``0`` ⇒ no stamp appended.
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
    """Decrypt a Dacar compact inner format ``inner_blob`` (§11.1).

    Inverse of :func:`wrap_dacar_delta`: EC-decrypts with the channel
    identity, verifies the RTID magic, recovers the sender public key, and
    returns the carried ``delta`` bytes. The Delta is **not** signature-
    verified here — that is deferred to verify-on-ingest
    (:meth:`DeltaReceiver.apply_payload`, §11.2), which authenticates the
    Delta's own Ed25519 signature (field [7]) against the Issuer Hash
    (field [0]) via the :class:`KeyResolver`. A forged or stale Delta is thus
    dropped before it can mutate the CRDT, exactly as for LXMF/optical delivery.
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
