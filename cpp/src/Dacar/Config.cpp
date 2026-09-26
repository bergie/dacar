/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Config.h"

#include "microReticulum/Log.h"

#include <stdexcept>

using namespace Dacar;

Config::Config(
	Set<RNS::Bytes> root_trust_anchors,
	RNS::Bytes primary_salt,
	Vector<RNS::Bytes> legacy_salts,
	Vector<ThresholdGroup> threshold_groups,
	RNS::Bytes authoritative_identity,
	int deletion_horizon_days
) {
	if (root_trust_anchors.empty()) {
		throw std::invalid_argument("at least one Root Trust Anchor is required (§4.1)");
	}
	for (const auto& anchor : root_trust_anchors) {
		if (anchor.size() != HASH_SIZE) {
			throw std::invalid_argument(
				"trust anchor must be 16 bytes, got " + std::to_string(anchor.size())
			);
		}
	}
	_root_trust_anchors = std::move(root_trust_anchors);

	if (primary_salt.size() != SALT_SIZE) {
		throw std::invalid_argument(
			"primary_salt must be 32 bytes, got " + std::to_string(primary_salt.size())
		);
	}
	_primary_salt = primary_salt;

	if (legacy_salts.size() > MAX_LEGACY_SALTS) {
		throw std::invalid_argument(
			"at most 2 Legacy Salts are allowed (§10.2), got " + std::to_string(legacy_salts.size())
		);
	}
	for (const auto& salt : legacy_salts) {
		if (salt.size() != SALT_SIZE) {
			throw std::invalid_argument("each legacy salt must be 32 bytes");
		}
	}
	_legacy_salts = std::move(legacy_salts);

	_threshold_groups = std::move(threshold_groups);

	if (authoritative_identity && authoritative_identity.size() != HASH_SIZE) {
		throw std::invalid_argument(
			"authoritative identity must be 16 bytes, got " + std::to_string(authoritative_identity.size())
		);
	}
	_authoritative_identity = authoritative_identity;

	if (deletion_horizon_days < 1) {
		throw std::invalid_argument("deletion_horizon_days must be >= 1");
	}
	_deletion_horizon_days = deletion_horizon_days;

	// NB: the Python implementation emits a NullPrivacySaltWarning when the
	// fail-open default salt is used; the C++ port surfaces this via the log
	// warning below (once, at Config construction).
	if (_primary_salt == DEFAULT_SALT()) {
		static bool warned = false;
		if (!warned) {
			warned = true;
			WARNING(
				"Config started with the default null Privacy Salt: label hashes are "
				"fail-open (trivially dictionary-attackable, spec 3.3). Set a strong "
				"random primary_salt for any real deployment."
			);
		}
	}
}

const ThresholdGroup* Config::group_for(const RNS::Bytes& group_id) const {
	for (const auto& group : _threshold_groups) {
		if (group.group_id() == group_id) {
			return &group;
		}
	}
	return nullptr;
}
