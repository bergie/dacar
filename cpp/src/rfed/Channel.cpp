/*
 * rfed — deterministic rfed channel derivation.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Channel.h"

#include "microReticulum/Cryptography/Hashes.h"

#include <cstring>

#include <stdexcept>

namespace RFed {

	Channel derive_channel(const std::string& name) {
		if (name.empty()) {
			throw std::invalid_argument("rfed channel name must not be empty");
		}
		const RNS::Bytes seed = RNS::Cryptography::sha256(RNS::Bytes(name));
		RNS::Identity identity;
		// The channel keypair is "seed || seed" (the same 32-byte SHA-256(name)
		// scalar for both X25519 and Ed25519), matching the Rust reference and
		// the canonical Python vectors.
		//
		// The X25519 half must be RFC 7748-clamped first: microReticulum's
		// Curve25519::eval is the raw Montgomery ladder and leaves clamping to
		// the caller (as Curve25519::dh1 does), while Python RNS relies on the
		// `cryptography` package clamping internally. Without the clamp the two
		// implementations derive *different* channel public keys (and ECDH
		// secrets) from the same seed — bits 0..2 of the scalar would be used
		// by one side and ignored by the other.
		// Exclusive copy: RNS::Bytes copy construction SHARES the buffer, so
		// clamping in place through a plain copy would also corrupt the raw
		// seed used for the Ed25519 half.
		RNS::Bytes x25519_scalar;
		x25519_scalar.assign(seed.data(), seed.size());
		uint8_t* scalar = x25519_scalar.writable(x25519_scalar.size());
		scalar[0] &= 0xF8;
		scalar[31] = (scalar[31] & 0x7F) | 0x40;
		if (!identity.load_private_key(x25519_scalar + seed)) {
			throw std::invalid_argument("rfed channel identity could not load its seed");
		}
		Channel channel;
		channel.identity = identity;
		channel.channel_hash = identity.hash();
		return channel;
	}

	RNS::Bytes delivery_hash_for(const RNS::Identity& identity) {
		// name_hash = SHA-256("lxmf.delivery")[:10] (Identity::NAME_HASH_LENGTH/8);
		// delivery_hash = truncated_hash(name_hash ‖ identity_hash).
		const RNS::Bytes name_hash =
			RNS::Identity::full_hash(RNS::Bytes("lxmf.delivery"))
				.left(RNS::Type::Identity::NAME_HASH_LENGTH / 8);
		return RNS::Identity::truncated_hash(name_hash + identity.hash());
	}

}
