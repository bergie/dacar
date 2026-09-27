/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Dacar compact inner format for RFed channels (spec §11.1.1, work doc #16
 * Phase 4b).
 *
 * For broadcasting Dacar Deltas over an RFed channel, the full LXMF envelope
 * is redundant — a §5.3 Delta is already self-addressed (Issuer Hash, field
 * [0]), self-timed (HLC, field [3]) and self-signed (Ed25519, field [7]) —
 * and its framing would push a typical Delta past the single-packet MDU.
 * Dacar reuses the rfed RTID prelude but carries the raw Delta in place of
 * the LXMF tail:
 *
 *     plaintext    = "RTID"(4) ‖ sender_identity_pub(64) ‖ delta
 *     inner_blob   = EC_encrypt(channel_identity.X25519_pub, plaintext)
 *     rfed_payload = channel_hash(16) ‖ inner_blob ‖ stamp(32)?
 *
 * The Delta's own signature is the authenticity check at verify-on-ingest
 * (§11.2, DeltaReceiver::handle_push/apply_payload); the prelude's
 * `sender_identity_pub` only identifies the transport sender. RFed treats
 * `inner_blob` opaquely, so this is a private agreement between Dacar
 * publishers and subscribers, invisible to the RFed nodes and to other RFed
 * channel applications (keyed by `channel_hash`).
 *
 * Wire-compatible with the Python (`dacar/transport/rfed_compact.py`) and
 * JavaScript (`src/transport/rfedSync.js`) implementations: the generic RTID
 * envelope, stamp contract, and channel derivation live in the standalone
 * `rfed/` library this module builds on (extractable the same way the Python
 * client became the `rfed` package).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "../rfed/Blob.h"
#include "../rfed/Channel.h"
#include "../rfed/Stamp.h"

#include "microReticulum/Bytes.h"
#include "microReticulum/Identity.h"

namespace Dacar {

	/*
	Wrap a §5.3 Delta in the Dacar compact inner format (§11.1.1).

	Builds `plaintext = MAGIC_RTID ‖ sender_identity_pub(64) ‖ delta`,
	EC-encrypts it to the channel identity, and frames it with the channel
	hash + optional PoW stamp. The Delta's own Ed25519 signature (field [7])
	is the authenticity check; no envelope signature is added, so this stays
	well under the 431-byte single-packet MDU for a typical Delta.

	`stamp_cost` is the cached PoW stamp cost advertised by the node (from
	the last RFedClient::subscribe). 0 means no stamp is appended.
	*/
	RFed::RfedPayload wrap_dacar_delta(
		const RNS::Identity& channel_identity,
		const RNS::Identity& sender_identity,
		const RNS::Bytes& delta,
		size_t stamp_cost = 0
	);

	/*
	A decoded Dacar compact inner format (§11.1.1) channel message.

	Unlike the generic rfed LXMF envelope, there is no envelope signature to
	verify here: the carried `delta` is self-signed (§5.3 field [7]) and is
	authenticated downstream by DeltaReceiver (verify-on-ingest, §11.2).
	`sender_identity` is reconstructed from the RTID prelude's public key
	purely so the caller can attribute/seed it.
	*/
	struct DecodedDacarDelta {
		RNS::Bytes delta;
		RNS::Bytes sender_pub;
		RNS::Identity sender_identity;
	};

	/*
	Decrypt a Dacar compact inner format `inner_blob` (§11.1.1). Inverse of
	wrap_dacar_delta: EC-decrypts with the channel identity, verifies the
	RTID magic, and extracts the embedded sender public key and Delta.
	Throws std::invalid_argument on decryption failure, short plaintext, or
	magic mismatch.
	*/
	DecodedDacarDelta unwrap_dacar_delta(
		const RNS::Bytes& inner_blob,
		const RNS::Identity& channel_identity
	);

}
