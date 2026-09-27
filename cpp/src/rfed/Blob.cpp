/*
 * rfed — rfed payload framing and the RTID prelude.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Blob.h"

#include <cstring>
#include <stdexcept>

namespace RFed {

	FanoutPayload parse_fanout_payload(const RNS::Bytes& payload) {
		if (payload.size() < HASH_LENGTH) {
			throw std::invalid_argument(
				"rfed fanout payload too short: " + std::to_string(payload.size()) +
				" bytes (need at least " + std::to_string(HASH_LENGTH) + ")"
			);
		}
		FanoutPayload parsed;
		parsed.channel_hash = payload.left(HASH_LENGTH);
		parsed.inner_blob = payload.mid(HASH_LENGTH);
		return parsed;
	}

	SendPayload parse_send_payload(const RNS::Bytes& payload) {
		const size_t min_len = HASH_LENGTH + STAMP_SIZE;
		if (payload.size() < min_len) {
			throw std::invalid_argument(
				"rfed SEND payload too short: " + std::to_string(payload.size()) +
				" bytes (need at least " + std::to_string(min_len) + ")"
			);
		}
		SendPayload parsed;
		parsed.channel_hash = payload.left(HASH_LENGTH);
		parsed.inner_blob = payload.mid(HASH_LENGTH, payload.size() - HASH_LENGTH - STAMP_SIZE);
		parsed.stamp = payload.right(STAMP_SIZE);
		return parsed;
	}

	RNS::Bytes verify_rtid_prelude(const RNS::Bytes& plaintext, RNS::Bytes& sender_pub) {
		if (plaintext.size() < PRELUDE_LENGTH) {
			throw std::invalid_argument(
				"rfed prelude plaintext too short: " + std::to_string(plaintext.size()) + " bytes"
			);
		}
		if (memcmp(plaintext.data(), MAGIC_RTID, MAGIC_LENGTH) != 0) {
			throw std::invalid_argument("rfed prelude magic mismatch: expected \"RTID\"");
		}
		sender_pub = plaintext.mid(MAGIC_LENGTH, PUBLIC_KEY_LENGTH);
		return plaintext.mid(PRELUDE_LENGTH);
	}

}
