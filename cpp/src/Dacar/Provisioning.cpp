/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Provisioning.h"

#if defined(RNS_USE_PROVISIONING)

using namespace Dacar;
namespace DacarConfig = Dacar::Provisioning::DacarConfig;

void Dacar::Provisioning::register_dacar_namespace(
	RNS::Provisioning::Provisioner& provisioner, StoreConfig& config
) {
	if (provisioner.registry().find(DacarConfig::Id)) {
		return; // already registered
	}

	provisioner.register_namespace("Dacar Config", DacarConfig::Id)

		.field_bytes("Primary Salt",
			DacarConfig::Field::PrimarySalt,
			(uint8_t)(RNS::Provisioning::FF_REBOOT_REQUIRED | RNS::Provisioning::FF_SECRET),
			RNS::Provisioning::fbytes_t(),
			SALT_SIZE,
			// setter
			[&config](const RNS::Provisioning::Value& v) {
				const auto& salt = v.as_bytes();
				if (salt.size() == SALT_SIZE) {
					config.primary_salt = salt;
					return true;
				}
				return false;
			},
			// getter
			[&config]() -> RNS::Provisioning::fbytes_t {
				return config.primary_salt;
			})

		.field_bytes_list("Legacy Salts",
			DacarConfig::Field::LegacySalts,
			(uint8_t)(RNS::Provisioning::FF_REBOOT_REQUIRED | RNS::Provisioning::FF_SECRET),
			RNS::Provisioning::fbytes_list_t(),
			SALT_SIZE,
			MAX_LEGACY_SALTS,
			[&config](const RNS::Provisioning::Value& v) {
				const auto& salts = v.as_bytes_list();
				config.legacy_salts.clear();
				for (const auto& salt : salts) {
					if (salt.size() != SALT_SIZE || config.legacy_salts.size() >= MAX_LEGACY_SALTS) {
						return false;
					}
					config.legacy_salts.push_back(salt);
				}
				return true;
			},
			[&config]() -> RNS::Provisioning::fbytes_list_t {
				return RNS::Provisioning::fbytes_list_t(config.legacy_salts.begin(), config.legacy_salts.end());
			})

		.field_bytes_list("Root Trust Anchors",
			DacarConfig::Field::Anchors,
			RNS::Provisioning::FF_LIVE_APPLY,
			RNS::Provisioning::fbytes_list_t(),
			HASH_SIZE,
			0, // unlimited
			[&config](const RNS::Provisioning::Value& v) {
				const auto& anchors = v.as_bytes_list();
				config.anchors.clear();
				for (const auto& anchor : anchors) {
					if (anchor.size() != HASH_SIZE) {
						return false;
					}
					config.anchors.push_back(anchor);
				}
				return true;
			},
			[&config]() -> RNS::Provisioning::fbytes_list_t {
				return RNS::Provisioning::fbytes_list_t(config.anchors.begin(), config.anchors.end());
			})

		.field_bytes("Authoritative Identity",
			DacarConfig::Field::Authoritative,
			RNS::Provisioning::FF_LIVE_APPLY,
			RNS::Provisioning::fbytes_t(),
			HASH_SIZE,
			[&config](const RNS::Provisioning::Value& v) {
				const auto& hash = v.as_bytes();
				if (hash.empty()) {
					config.authoritative = RNS::Bytes();
					return true;
				}
				if (hash.size() != HASH_SIZE) {
					return false;
				}
				config.authoritative = hash;
				return true;
			},
			[&config]() -> RNS::Provisioning::fbytes_t {
				return config.authoritative;
			})

		.field_int("Deletion Horizon Days",
			DacarConfig::Field::DeletionHorizonDays,
			RNS::Provisioning::FF_LIVE_APPLY,
			DEFAULT_DELETION_HORIZON_DAYS,
			1,
			3650,
			[&config](const RNS::Provisioning::Value& v) {
				int64_t days = v.as_int();
				if (days < 1 || days > 3650) {
					return false;
				}
				config.horizon_days = (int)days;
				return true;
			},
			[&config]() {
				return (int64_t)config.horizon_days;
			})

		.field_string("RFed Topic",
			DacarConfig::Field::RfedTopic,
			RNS::Provisioning::FF_LIVE_APPLY,
			RFED_TOPIC,
			64,
			[&config](const RNS::Provisioning::Value& v) {
				config.rfed_topic = v.as_string();
				return true;
			},
			[&config]() -> RNS::Provisioning::fstring_t {
				return config.rfed_topic;
			})

		.end();
}

#endif // RNS_USE_PROVISIONING
