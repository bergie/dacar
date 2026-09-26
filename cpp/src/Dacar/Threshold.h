/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Threshold Trust Anchors: N-of-M identity groups (Dacar spec §4.1).
 *
 * A Threshold Group is a composite authority requiring consensus: an
 * Operation issued *by* the group MUST carry exactly N valid signatures from
 * N distinct members of the M-member set (§5.2).
 *
 * The Group ID is the SHA-256 hash of the ascending-sorted member hashes
 * concatenated with the threshold N as an 8-byte big-endian integer,
 * truncated to the first 16 bytes (§4.1). The Group ID is itself a 16-byte
 * value usable wherever an Issuer hash is expected.
 *
 * Scope (§4.1): in v1.0, Threshold Groups MAY ONLY act as Issuers. A Grantee
 * MUST be a single identity; granting permissions *to* a group is not
 * supported.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Namespace.h"

#include <vector>

namespace Dacar {

	/*
	Compute the 16-byte Group ID for a member set and threshold (§4.1).

	Members are 16-byte identity hashes, sorted ascending by raw byte value
	(equivalent to hex-alphabetical order). Throws std::invalid_argument for
	fewer than 2 members, wrong member length, or a threshold outside
	1 <= N <= M.
	*/
	RNS::Bytes group_id(const Vector<RNS::Bytes>& members, int threshold);

	class ThresholdGroup {

	public:
		ThresholdGroup() = default;
		~ThresholdGroup() = default;

		/*
		Construct an N-of-M group; members are normalized to sorted order and
		validated via group_id() (throws std::invalid_argument on bad input).
		*/
		ThresholdGroup(Vector<RNS::Bytes> members, int threshold);

		// The 16-byte Group ID (usable as an Issuer hash).
		RNS::Bytes group_id() const;

		// The M member identity hashes (16 bytes each), sorted ascending.
		const Vector<RNS::Bytes>& members() const { return _members; }

		// The consensus threshold N.
		int threshold() const { return _threshold; }

		// The number of members M.
		size_t size() const { return _members.size(); }

		bool operator == (const ThresholdGroup& other) const {
			return _threshold == other._threshold && _members == other._members;
		}

	private:
		Vector<RNS::Bytes> _members;
		int _threshold = 1;

	};

}
