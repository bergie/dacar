/*
 * rfed — channel proof-of-work stamp contract.
 *
 * A rfed SEND payload ends with an optional 32-byte proof-of-work stamp bound
 * to the bytes it accompanies. The stamp material and value semantics are
 * fixed by RFed/SPEC.md "PoW STAMP CONTRACT":
 *
 *     material     = channel_hash(16) ‖ inner_blob
 *     transient_id = SHA-256(material)
 *     workblock    = LXStamper::stamp_workblock(transient_id, rounds = 16)
 *     value        = leading_zero_bits(SHA-256(workblock ‖ stamp))
 *     valid        = value >= stamp_cost
 *
 * The workblock, stamp generation, and validation semantics are the standard
 * LXMF ones — byte-compatible with Python LXMF's LXStamper and
 * @reticulum/core's lxmf/stamper.js — run at rfed's 16 expansion rounds. The
 * workblock is the memory-hard HKDF expansion: the concatenation of `rounds`
 * chunks of 256 bytes each, where chunk n is
 * HKDF-SHA256(ikm = transient_id, salt = SHA-256(transient_id ‖ msgpack(n)),
 * L = 256) — 4 KiB at rfed's rounds. Stamp generation mirrors LXMF's
 * random-trial search; validation is value-based, so the trial strategy does
 * not affect interoperability.
 *
 * `stamp_cost` is owned by the /rfed/subscribe reply: a cost of 0 means
 * stamping is disabled and no stamp is required or appended.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Constants.h"

#include "microReticulum/Bytes.h"

namespace RFed {

	// One computed channel-stamp context: the transient id and its
	// memory-hard workblock.
	struct StampContext {
		RNS::Bytes transient_id;
		RNS::Bytes workblock;
	};

	/*
	Leading zero bits of `data`: 8 per all-zero byte, then the leading zeros
	of the first non-zero byte.
	*/
	size_t leading_zero_bits(const RNS::Bytes& data);

	/*
	Build the memory-hard LXMF stamp workblock for `material`: the
	concatenation of `expand_rounds` chunks, each 256 bytes of HKDF-SHA256
	keyed on `material` and salted with SHA-256(material ‖ msgpack(n)). The
	per-round msgpack counter matches umsgpack.packb (positive fixint below
	128).
	*/
	RNS::Bytes stamp_workblock(
		const RNS::Bytes& material,
		size_t expand_rounds = STAMP_EXPAND_ROUNDS
	);

	/*
	Compute the transient id (SHA-256(channel_hash ‖ inner_blob)) and its
	workblock for a channel stamp.
	*/
	StampContext channel_stamp_workblock(
		const RNS::Bytes& channel_hash,
		const RNS::Bytes& inner_blob,
		size_t expand_rounds = STAMP_EXPAND_ROUNDS
	);

	/*
	Leading-zero-bit value: leadingZeroBits(SHA-256(workblock ‖ stamp)).
	*/
	size_t stamp_value(const RNS::Bytes& workblock, const RNS::Bytes& stamp);

	/*
	Validate a stamp against a target proof-of-work cost (LXMF semantics):
	`stamp_value(workblock, stamp) >= target_cost`.
	*/
	bool stamp_valid(const RNS::Bytes& stamp, size_t target_cost, const RNS::Bytes& workblock);

	/*
	Search for a valid 32-byte channel PoW stamp: random 32-byte trials over
	the workblock, accepted once stamp_value >= stamp_cost. Expected trials
	are ~2^stamp_cost (rfed costs such as 12 terminate in a few thousand).

	Throws std::runtime_error when no stamp is found within a generous trial
	budget (an unreachable cost should fail fast, not hang an MCU).
	*/
	RNS::Bytes generate_channel_stamp(
		const RNS::Bytes& channel_hash,
		const RNS::Bytes& inner_blob,
		size_t stamp_cost,
		size_t expand_rounds = STAMP_EXPAND_ROUNDS
	);

	/*
	Validate a channel PoW stamp against a required cost. Short stamps are
	invalid by definition.
	*/
	bool validate_channel_stamp(
		const RNS::Bytes& channel_hash,
		const RNS::Bytes& inner_blob,
		const RNS::Bytes& stamp,
		size_t stamp_cost,
		size_t expand_rounds = STAMP_EXPAND_ROUNDS
	);

}
