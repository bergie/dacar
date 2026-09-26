/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Node configuration: trust anchors, salts, and thresholds (spec §4, §10).
 *
 * Every Dacar node is bootstrapped out-of-band with one or more Root Trust
 * Anchors (single identities or Threshold Groups), a Privacy Salt (plus up to
 * two Legacy Salts for rotation, §10), and optionally an Authoritative
 * Identity for Strict Consistency (§8).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Namespace.h"
#include "Threshold.h"

#include <set>
#include <vector>

namespace Dacar {

	// Default deletion horizon H (days), see §9.
	constexpr int DEFAULT_DELETION_HORIZON_DAYS = 180;

	class Config {

	public:
		Config() = default;
		~Config() = default;

		/*
		Static trust + privacy configuration for a Dacar service node.

		Throws std::invalid_argument on: an empty anchor set, wrong anchor /
		salt / authoritative-identity lengths, more than MAX_LEGACY_SALTS
		legacy salts, or a deletion horizon below 1 day.

		An empty authoritative_identity means "not configured".
		*/
		Config(
			Set<RNS::Bytes> root_trust_anchors,
			RNS::Bytes primary_salt = DEFAULT_SALT(),
			Vector<RNS::Bytes> legacy_salts = {},
			Vector<ThresholdGroup> threshold_groups = {},
			RNS::Bytes authoritative_identity = RNS::Bytes(),
			int deletion_horizon_days = DEFAULT_DELETION_HORIZON_DAYS
		);

		const Set<RNS::Bytes>& root_trust_anchors() const { return _root_trust_anchors; }
		const RNS::Bytes& primary_salt() const { return _primary_salt; }
		const Vector<RNS::Bytes>& legacy_salts() const { return _legacy_salts; }
		const Vector<ThresholdGroup>& threshold_groups() const { return _threshold_groups; }

		// Exactly one identity that signs Freshness Receipts (§8); an empty
		// Bytes means "not configured".
		const RNS::Bytes& authoritative_identity() const { return _authoritative_identity; }

		int deletion_horizon_days() const { return _deletion_horizon_days; }
		uint64_t deletion_horizon_ms() const {
			return (uint64_t)_deletion_horizon_days * 24ULL * 60ULL * 60ULL * 1000ULL;
		}

		// -- salts (§3.3, §10) ------------------------------------------------
		NamespaceHasher primary_hasher() const { return NamespaceHasher(_primary_salt); }

		std::vector<NamespaceHasher> legacy_hashers() const {
			std::vector<NamespaceHasher> hashers;
			for (const auto& salt : _legacy_salts) {
				hashers.emplace_back(salt);
			}
			return hashers;
		}

		// All configured hashers: Primary first, then Legacy in order (§10.2).
		std::vector<NamespaceHasher> hashers() const {
			std::vector<NamespaceHasher> hashers;
			hashers.reserve(1 + _legacy_salts.size());
			hashers.emplace_back(_primary_salt);
			for (const auto& salt : _legacy_salts) {
				hashers.emplace_back(salt);
			}
			return hashers;
		}

		// -- anchors & groups (§4) --------------------------------------------
		// Return true if `identity_hash` is a configured Root Trust Anchor.
		bool is_root_anchor(const RNS::Bytes& identity_hash) const {
			return _root_trust_anchors.find(identity_hash) != _root_trust_anchors.end();
		}

		// Return the Threshold Group with the given Group ID, or nullptr (§4.1).
		const ThresholdGroup* group_for(const RNS::Bytes& group_id) const;

	private:
		Set<RNS::Bytes> _root_trust_anchors;
		RNS::Bytes _primary_salt;
		Vector<RNS::Bytes> _legacy_salts;
		Vector<ThresholdGroup> _threshold_groups;
		RNS::Bytes _authoritative_identity;
		int _deletion_horizon_days = DEFAULT_DELETION_HORIZON_DAYS;

	};

}
