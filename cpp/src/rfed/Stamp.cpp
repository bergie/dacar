/*
 * rfed — channel proof-of-work stamp contract.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Stamp.h"

#include "Constants.h"

#include "microReticulum/Cryptography/Hashes.h"
#include "microReticulum/Cryptography/HKDF.h"
#include "microReticulum/Cryptography/Random.h"

#include <stdexcept>

namespace {

		// C++17 has no std::bit_width: 8 minus the highest set bit's position.
		size_t byte_bit_width(uint8_t byte) {
			size_t width = 0;
			while (byte) {
				width++;
				byte >>= 1;
			}
			return width;
		}

	} // namespace

	namespace RFed {

	size_t leading_zero_bits(const RNS::Bytes& data) {
		size_t value = 0;
		for (size_t i = 0; i < data.size(); i++) {
			const uint8_t byte = data[i];
			if (byte == 0) {
				value += 8;
				continue;
			}
			value += 8 - byte_bit_width(byte);
			break;
		}
		return value;
	}

	RNS::Bytes stamp_workblock(const RNS::Bytes& material, size_t expand_rounds) {
		RNS::Bytes workblock;
		for (size_t n = 0; n < expand_rounds; n++) {
			// The per-round counter is msgpack-packed (positive fixint below
			// 128 — i.e. the raw byte for rfed's round range).
			const uint8_t counter = (uint8_t)n;
			const RNS::Bytes counter_bytes(&counter, 1);
			const RNS::Bytes salt = RNS::Cryptography::sha256(material + counter_bytes);
			workblock = workblock + RNS::Cryptography::hkdf(256, material, salt);
		}
		return workblock;
	}

	StampContext channel_stamp_workblock(
		const RNS::Bytes& channel_hash,
		const RNS::Bytes& inner_blob,
		size_t expand_rounds
	) {
		const RNS::Bytes material = channel_hash + inner_blob;
		StampContext context;
		context.transient_id = RNS::Cryptography::sha256(material);
		context.workblock = stamp_workblock(context.transient_id, expand_rounds);
		return context;
	}

	size_t stamp_value(const RNS::Bytes& workblock, const RNS::Bytes& stamp) {
		return leading_zero_bits(RNS::Cryptography::sha256(workblock + stamp));
	}

	bool stamp_valid(const RNS::Bytes& stamp, size_t target_cost, const RNS::Bytes& workblock) {
		return stamp_value(workblock, stamp) >= target_cost;
	}

	RNS::Bytes generate_channel_stamp(
		const RNS::Bytes& channel_hash,
		const RNS::Bytes& inner_blob,
		size_t stamp_cost,
		size_t expand_rounds
	) {
		const StampContext context = channel_stamp_workblock(channel_hash, inner_blob, expand_rounds);
		// Random-trial search mirroring LXMF's LXStamper.generate_stamp.
		// Expected trials are ~2^stamp_cost; a generous hard budget (2^22)
		// fails fast on an unreachable cost instead of hanging an MCU.
		const uint32_t max_trials = 1UL << 22;
		for (uint32_t trial = 0; trial < max_trials; trial++) {
			const RNS::Bytes stamp = RNS::Cryptography::random(STAMP_SIZE);
			if (stamp_valid(stamp, stamp_cost, context.workblock)) {
				return stamp;
			}
		}
		throw std::runtime_error("rfed stamp search exhausted its trial budget");
	}

	bool validate_channel_stamp(
		const RNS::Bytes& channel_hash,
		const RNS::Bytes& inner_blob,
		const RNS::Bytes& stamp,
		size_t stamp_cost,
		size_t expand_rounds
	) {
		if (stamp.size() < STAMP_SIZE) {
			return false;
		}
		const StampContext context = channel_stamp_workblock(channel_hash, inner_blob, expand_rounds);
		return stamp_valid(stamp, stamp_cost, context.workblock);
	}

}
