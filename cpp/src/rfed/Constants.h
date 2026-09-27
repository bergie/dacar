/*
 * rfed — Reticulum Federation channel client (wire-format constants).
 *
 * Mirrors the canonical wire format in RFed/SPEC.md ("CANONICAL WIRE FORMAT —
 * ULTIMATE AUTHORITY") and the Python `rfed.constants` module. These values
 * are protocol-invariant: any change silently breaks interoperability with the
 * Rust rfed reference node, the Python `rfed` package, and the JavaScript
 * `@reticulum/rfed` client.
 *
 * This tree is deliberately standalone — it depends only on microReticulum
 * (and MsgPack for the client's request envelopes), never on the Dacar
 * library — so it can be lifted into its own PlatformIO/CMake library the
 * same way the Python client was spun out of Dacar as the `rfed` package.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include <cstddef>

namespace RFed {

	// The 4-byte ASCII magic prefixing the RTID source-identity prelude inside
	// the channel EC envelope. Not length-prefixed, not little-endian.
	constexpr const char* MAGIC_RTID = "RTID";

	// Length of the RTID magic prelude.
	constexpr size_t MAGIC_LENGTH = 4;

	// Length of an Identity public-key bundle (X25519 ‖ Ed25519).
	constexpr size_t PUBLIC_KEY_LENGTH = 64;

	// Length of a 16-byte channel/destination hash.
	constexpr size_t HASH_LENGTH = 16;

	// Byte length of the full RTID prelude: magic(4) ‖ sender_pub(64).
	constexpr size_t PRELUDE_LENGTH = MAGIC_LENGTH + PUBLIC_KEY_LENGTH;

	// Proof-of-work stamp expansion rounds for rfed channel messages.
	//
	// Deliberately 16 (LXMF propagation-node stamps use 1000, regular message
	// stamps 3000). Bumping it silently invalidates every cached stamp_cost
	// and every in-flight stamp — a protocol-version bump, never a patch.
	constexpr size_t STAMP_EXPAND_ROUNDS = 16;

	// Size in bytes of an LXMF proof-of-work stamp.
	constexpr size_t STAMP_SIZE = 32;

	// Modern split rfed destination names (SPEC §2). All share the node
	// identity: the destination is `rfed.<aspect>` under the node identity.
	constexpr const char* CHANNEL_SUBSCRIBE_NAME = "rfed.channel.subscribe";
	constexpr const char* CHANNEL_UNSUBSCRIBE_NAME = "rfed.channel.unsubscribe";
	constexpr const char* CHANNEL_PUBLISH_NAME = "rfed.channel.publish";
	constexpr const char* CHANNEL_PULL_NAME = "rfed.channel.pull";

	// The client's own inbound delivery destination name.
	constexpr const char* DELIVERY_NAME = "rfed.delivery";

	// Request paths served on the channel destinations.
	constexpr const char* SUBSCRIBE_PATH = "/rfed/subscribe";
	constexpr const char* UNSUBSCRIBE_PATH = "/rfed/unsubscribe";
	constexpr const char* PULL_PATH = "/rfed/pull";

	// Maximum publish payload size sent as a single fire-and-forget DATA
	// packet: the link MDU at the default 500 B RNS MTU (500 − 69 B link
	// overhead). Anything larger must go as a Resource over a link to the
	// publish destination — the node ingests both paths identically.
	constexpr size_t PUBLISH_DATA_MAX = 431;

	// Smallest rfed node error code (0xF0 ERROR_NO_IDENTITY — the link could
	// not be authenticated, re-identify on a fresh link; 0xF4
	// ERROR_INVALID_DATA — malformed request).
	constexpr int PULL_ERROR_CODE_MIN = 0xF0;

	// Default request round-trip timeout in seconds.
	constexpr double DEFAULT_REQUEST_TIMEOUT = 15.0;

	// Default link establishment timeout in seconds.
	constexpr double DEFAULT_ESTABLISH_TIMEOUT = 15.0;

	// Default path-request wait timeout in seconds.
	constexpr double DEFAULT_PATH_TIMEOUT = 15.0;

	// Extra slack beyond the RNS request timeout before the client gives up,
	// so a response arriving a hair after RNS's own timeout is still
	// collected.
	constexpr double DEFAULT_TIMEOUT_GRACE = 2.0;

}
