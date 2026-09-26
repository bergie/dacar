/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * The `dacar` Provisioning namespace (work doc #16 Phase 2, MCU config).
 *
 * On MCU targets the §13.2 INI config is not the natural provisioning
 * surface; instead the Dacar configuration is exposed as a microReticulum
 * Provisioning namespace (id 100, in the third-party range above the
 * stack's builtin namespaces). The standard provisioning machinery then
 * provides draft/commit, flash persistence, and wire ops: salts and anchors
 * reach a node over BLE/USB/Web-Serial without a filesystem or CLI.
 *
 * Registered fields bind live to a StoreConfig (the same struct the INI
 * codec reads/writes), so native (INI) and MCU (provisioning) deployments
 * share one configuration model. Trust-affecting fields (anchors,
 * authoritative identity, horizon, topic) apply live: an anchor revocation
 * must not wait for a reboot. The salts are FF_SECRET and reboot-required —
 * a §10 rotation takes effect on the next boot, and the salt never leaves
 * the node via GET_STATE.
 *
 * Compiled only when RNS_USE_PROVISIONING is defined (microReticulum's
 * CMake and firmware builds define it).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Store.h"

#if defined(RNS_USE_PROVISIONING)

#include "microReticulum/Provisioning/Provisioning.h"

namespace Dacar { namespace Provisioning {

	// Permanent field ids — append only, never reuse a slot (see
	// microReticulum's provisioning id registry conventions).
	namespace DacarConfig {

		constexpr RNS::Provisioning::nid_t Id = 100;

		namespace Field {
			constexpr RNS::Provisioning::fid_t SchemaVersion = 0;   // reserved
			constexpr RNS::Provisioning::fid_t PrimarySalt = 1;     // Bytes(32), SECRET
			constexpr RNS::Provisioning::fid_t LegacySalts = 2;     // BytesList of 32-byte salts, SECRET
			constexpr RNS::Provisioning::fid_t Anchors = 3;         // BytesList of 16-byte hashes
			constexpr RNS::Provisioning::fid_t Authoritative = 4;   // Bytes(16), empty = unset
			constexpr RNS::Provisioning::fid_t DeletionHorizonDays = 5; // Int [1, 3650]
			constexpr RNS::Provisioning::fid_t RfedTopic = 6;       // String
		} // namespace Field

	} // namespace DacarConfig

	/*
	Register the `dacar` config namespace, binding every field live to
	`config` (setters mutate it, getters read it). Idempotent: a second
	call with the namespace already registered is a no-op (mirrors
	register_builtin_namespaces).
	*/
	void register_dacar_namespace(RNS::Provisioning::Provisioner& provisioner, StoreConfig& config);

} } // namespace Dacar::Provisioning

#endif // RNS_USE_PROVISIONING
