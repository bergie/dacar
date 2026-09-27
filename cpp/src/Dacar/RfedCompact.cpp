/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "RfedCompact.h"

#include <stdexcept>

namespace Dacar {

	RFed::RfedPayload wrap_dacar_delta(
		const RNS::Identity& channel_identity,
		const RNS::Identity& sender_identity,
		const RNS::Bytes& delta,
		size_t stamp_cost
	) {
		const RNS::Bytes channel_hash = channel_identity.hash();
		const RNS::Bytes sender_pub = sender_identity.get_public_key();
		const RNS::Bytes magic(RFed::MAGIC_RTID);
		const RNS::Bytes plaintext = magic + sender_pub + delta;
		const RNS::Bytes inner_blob = channel_identity.encrypt(plaintext);

		RNS::Bytes stamp;
		if (stamp_cost > 0) {
			stamp = RFed::generate_channel_stamp(channel_hash, inner_blob, stamp_cost);
		}

		RFed::RfedPayload payload;
		payload.channel_hash = channel_hash;
		payload.channel_delivery_hash = RFed::delivery_hash_for(channel_identity);
		payload.inner_blob = inner_blob;
		payload.stamp = stamp;
		payload.rfed_payload = channel_hash + inner_blob + stamp;
		return payload;
	}

	DecodedDacarDelta unwrap_dacar_delta(
		const RNS::Bytes& inner_blob,
		const RNS::Identity& channel_identity
	) {
		const RNS::Bytes plaintext = channel_identity.decrypt(inner_blob);
		if (!plaintext) {
			throw std::invalid_argument(
				"rfed inner_blob EC-decryption failed (wrong channel?)"
			);
		}
		RNS::Bytes sender_pub;
		const RNS::Bytes delta = RFed::verify_rtid_prelude(plaintext, sender_pub);

		DecodedDacarDelta decoded;
		decoded.delta = delta;
		decoded.sender_pub = sender_pub;
		decoded.sender_identity = RNS::Identity(false);
		decoded.sender_identity.load_public_key(sender_pub);
		return decoded;
	}

}
