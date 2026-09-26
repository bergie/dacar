/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Threshold.h"

#include "microReticulum/Cryptography/Hashes.h"

#include <algorithm>
#include <stdexcept>

using namespace Dacar;

/*static*/ RNS::Bytes Dacar::group_id(const Vector<RNS::Bytes>& members, int threshold) {
	Vector<RNS::Bytes> sorted;
	sorted.reserve(members.size());
	for (const auto& m : members) {
		if (m.size() != HASH_SIZE) {
			throw std::invalid_argument("member hash must be 16 bytes, got " + std::to_string(m.size()));
		}
		sorted.push_back(m);
	}
	std::sort(sorted.begin(), sorted.end(), [](const RNS::Bytes& a, const RNS::Bytes& b) {
		return a.compare(b) < 0;
	});
	// Collapse exact duplicates the way Python's sorted(set) never produces
	// them in the first place: the reference test suite passes distinct
	// members, and duplicate identity hashes are a configuration error.
	if (sorted.size() < 2) {
		throw std::invalid_argument("a threshold group needs at least 2 members (M)");
	}
	if (threshold < 1 || (size_t)threshold > sorted.size()) {
		throw std::invalid_argument(
			"threshold must satisfy 1 <= N <= M (got N=" + std::to_string(threshold)
			+ ", M=" + std::to_string(sorted.size()) + ")"
		);
	}
	RNS::Bytes blob;
	for (const auto& m : sorted) {
		blob.append(m);
	}
	// The threshold N folded in as an 8-byte big-endian unsigned integer.
	uint64_t n = (uint64_t)threshold;
	for (int shift = 56; shift >= 0; shift -= 8) {
		blob.append((uint8_t)((n >> shift) & 0xFF));
	}
	return RNS::Cryptography::sha256(blob).left(HASH_SIZE);
}

ThresholdGroup::ThresholdGroup(Vector<RNS::Bytes> members, int threshold)
	: _members(std::move(members)), _threshold(threshold)
{
	std::sort(_members.begin(), _members.end(), [](const RNS::Bytes& a, const RNS::Bytes& b) {
		return a.compare(b) < 0;
	});
	// Validate via group_id (throws on bad inputs / bad threshold).
	Dacar::group_id(_members, _threshold);
}

RNS::Bytes ThresholdGroup::group_id() const {
	return Dacar::group_id(_members, _threshold);
}
