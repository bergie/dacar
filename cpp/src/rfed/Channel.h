/*
 * rfed — deterministic rfed channel derivation.
 *
 * A channel is a deterministic RNS Identity derived from a plain-text channel
 * name. Any party that knows the name independently arrives at the same
 * identity hash ("channel hash") and keypair, so senders can encrypt to the
 * channel and subscribers can decrypt — with no server-side registration
 * (RFed/SPEC.md §1):
 *
 *     seed          = SHA-256(channel_name)                 -> 32 bytes
 *     x25519_priv   = seed
 *     ed25519_priv  = seed
 *     x25519_pub    = X25519_public_key(seed)               -> 32 bytes
 *     ed25519_pub   = Ed25519_public_key(seed)              -> 32 bytes
 *     bundle        = x25519_pub ‖ ed25519_pub              -> 64 bytes
 *     channel_hash  = SHA-256(bundle)[0..16]                -> 16 bytes
 *
 * The channel's private-key bundle is `seed ‖ seed` (the same 32-byte
 * SHA-256(name) scalar used for both X25519 and Ed25519), matching the Rust
 * reference and the canonical Python vectors.
 *
 * Uses RNS only for cryptography primitives, so derivation works without a
 * running Reticulum — only Destination creation needs a live transport.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include <string>

#include "microReticulum/Bytes.h"
#include "microReticulum/Identity.h"

namespace RFed {

	/*
	A derived channel: the full Identity (both private keys — it can encrypt,
	decrypt, and derive its lxmf.delivery hash) and the 16-byte channel hash
	(the rfed routing label).
	*/
	struct Channel {
		RNS::Identity identity;
		RNS::Bytes channel_hash;
	};

	/*
	Derive a channel's deterministic Identity and 16-byte channel hash from a
	dot-separated channel name (e.g. "dacar.policy.v1").
	*/
	Channel derive_channel(const std::string& name);

	/*
	Compute the `lxmf.delivery` destination hash for an Identity: the 16-byte
	truncated SHA-256(name_hash("lxmf.delivery") ‖ identity_hash).

	For a channel message this is the LXMF destination hash the sender signs
	over (the channel's delivery address), NOT the bare channel identity hash.
	Confusing the two is the classic rfed bug — see RFed/SPEC.md "CANONICAL
	WIRE FORMAT" invariants.
	*/
	RNS::Bytes delivery_hash_for(const RNS::Identity& identity);

}
