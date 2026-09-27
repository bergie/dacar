/*
 * rfed — rfed payload framing and the RTID prelude.
 *
 * A rfed SEND payload is `channel_hash(16) ‖ inner_blob ‖ stamp(32)?`; the
 * fanout hop carries `channel_hash(16) ‖ inner_blob` (the stamp was validated
 * and stripped at ingest). The `inner_blob` is what rfed stores, syncs, and
 * fans out verbatim — rfed never decrypts or inspects it. Applications may
 * carry any inner format: the plaintext after the RTID prelude is a private
 * agreement between publishers and subscribers of a channel (keyed by
 * `channel_hash`).
 *
 * The generic LXMF-tail channel-message codec (rfed-python's
 * `rfed.blob.wrap_channel_message`) is not part of this C++ port yet — the
 * launch consumer (Dacar's §11.1.1 compact Delta format) carries a raw Delta
 * in place of the LXMF tail and only needs the framing + prelude primitives
 * below. Port the LXMF tail alongside `LxmfMessage` when the spin-out
 * library needs the full surface.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Constants.h"

#include "microReticulum/Bytes.h"

namespace RFed {

	// A fully-wrapped rfed SEND payload and its constituent parts.
	struct RfedPayload {
		RNS::Bytes rfed_payload;
		RNS::Bytes channel_hash;
		RNS::Bytes channel_delivery_hash;
		RNS::Bytes inner_blob;
		RNS::Bytes stamp; // empty when no stamp was appended
	};

	// A split fanout payload: `[ channel_hash(16) ‖ inner_blob ]`.
	struct FanoutPayload {
		RNS::Bytes channel_hash;
		RNS::Bytes inner_blob;
	};

	// A split SEND payload: `[ channel_hash(16) ‖ inner_blob ‖ stamp(32) ]`.
	struct SendPayload {
		RNS::Bytes channel_hash;
		RNS::Bytes inner_blob;
		RNS::Bytes stamp;
	};

	/*
	Split a fanout payload. Throws std::invalid_argument when too short.
	*/
	FanoutPayload parse_fanout_payload(const RNS::Bytes& payload);

	/*
	Split a SEND payload known to carry a stamp. Throws
	std::invalid_argument when too short.
	*/
	SendPayload parse_send_payload(const RNS::Bytes& payload);

	/*
	Verify the RTID prelude of a decrypted channel-message plaintext and
	split off the sender's public-key bundle: `plaintext` must start with
	magic "RTID" followed by the 64-byte sender public key. Returns the
	remainder (the inner format's own tail) and writes the sender bundle to
	`sender_pub`. Throws std::invalid_argument on short plaintext or magic
	mismatch — receivers MUST refuse blobs without "RTID".
	*/
	RNS::Bytes verify_rtid_prelude(
		const RNS::Bytes& plaintext,
		RNS::Bytes& sender_pub
	);

}
