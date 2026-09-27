/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * RNS naming conventions for the Dacar policy plane (spec §8, §11).
 *
 * These are pure, dependency-free constants. Two scopes:
 *
 *   - RFED_TOPIC is a *deployment-overridable default*. RFed is a broadcast
 *     (many-to-many) medium, so deployments sharing an RNS network SHOULD set
 *     a deployment-specific topic to isolate their policy feeds.
 *   - CHALLENGE_DESTINATION, SYNC_DESTINATION, and LXMF_DELIVERY_TITLE are
 *     *fixed discriminators*: they are addressed point-to-point to a specific
 *     Identity, so RNS derives isolation from the destination hash, not from
 *     this name.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

namespace Dacar {

	// The RNS App Name under which all Dacar services live (§8, §11).
	constexpr const char* APP_NAME = "dacar";

	// Aspects of the §8 Authoritative Challenge destination (App "dacar").
	constexpr const char* CHALLENGE_ASPECTS[2] = {"auth", "v1"};

	// The full dotted name of the §8 Authoritative Challenge destination.
	constexpr const char* CHALLENGE_DESTINATION = "dacar.auth.v1";

	// Aspects of the direct-link Delta ingestion destination (§11, work doc
	// #16 Phase 4a). A constrained node exposes this destination so a peer can
	// push raw §5.3 Delta payloads to it over a Link request; the node ingests
	// them through verify-on-ingest (§11.2.4), which makes any transport
	// valid — the same precedent as optical Paper Messages (§11.3).
	constexpr const char* SYNC_ASPECTS[2] = {"sync", "v1"};

	// The full dotted name of the direct-link Delta ingestion destination.
	constexpr const char* SYNC_DESTINATION = "dacar.sync.v1";

	// RFed topic for many-to-many CRDT convergence (§11.1).
	// Deployment-overridable default — RFed is broadcast, so shared-network
	// deployments SHOULD set a distinct topic to isolate their feeds.
	constexpr const char* RFED_TOPIC = "dacar.policy.v1";

	// LXMF message title for targeted Delta delivery (§11.2).
	constexpr const char* LXMF_DELIVERY_TITLE = "dacar/sync/delta";

}
