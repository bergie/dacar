/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Verify-on-ingest: authenticating network Deltas by Ed25519 signature
 * (spec §11.2.4).
 *
 * The CRDT update itself (StateVector::apply) is a *pure* mutation that
 * trusts its caller; it deliberately performs no cryptography so the layering
 * stays simple and the hot path stays fast. Network-received Deltas instead
 * enter the state through StateVector::ingest, which MUST authenticate each
 * Operation against the claimed Issuer's public key(s) before it is allowed
 * to mutate state (spec §11.2.4: "The signature remains the sole source of
 * authorization authenticity").
 *
 * This module bridges an Issuer hash to the public-key material needed to
 * verify it:
 *
 *   - IssuerKeyset: M public keys + a threshold (1 for a single identity,
 *     N for a Threshold Group, §4.1).
 *   - Keyring:      a map-backed resolver for offline / test use.
 *   - verify_operation: resolve + verify, returning a plain bool.
 *
 * Authentication is *not* authorization. Verifying a signature proves the
 * Operation was genuinely issued by the claimed Issuer; whether that Issuer
 * is itself authorized (its authority traces to a Root Trust Anchor) is
 * resolved later by the Evaluation Engine (§7) against the converged state.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Operation.h"

#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace Dacar {

	// Ed25519 public keys are 32 raw bytes.
	constexpr size_t PUBLIC_KEY_SIZE = 32;

	class IssuerKeyset {

	public:
		IssuerKeyset() = default;
		~IssuerKeyset() = default;

		/*
		A single-identity Issuer has threshold == 1 and one member key; a
		Threshold Group Issuer (§4.1) has threshold == N and M >= N member
		keys. Throws std::invalid_argument on wrong key length, threshold < 1,
		or fewer member keys than the threshold.
		*/
		IssuerKeyset(Vector<RNS::Bytes> member_public_keys, int threshold = 1);

		// Keyset for a single-identity Issuer (threshold 1).
		static IssuerKeyset single(const RNS::Bytes& public_key) {
			return IssuerKeyset({public_key}, 1);
		}

		// Keyset for an N-of-M Threshold Group Issuer (§4.1).
		static IssuerKeyset group(Vector<RNS::Bytes> member_public_keys, int threshold) {
			return IssuerKeyset(std::move(member_public_keys), threshold);
		}

		const Vector<RNS::Bytes>& member_public_keys() const { return _member_public_keys; }
		int threshold() const { return _threshold; }

	private:
		Vector<RNS::Bytes> _member_public_keys;
		int _threshold = 1;

	};

	// Resolves a 16-byte Issuer hash to its verification keyset, or nullptr
	// when the Issuer is unknown (the Operation is then rejected as
	// unverifiable).
	using KeyResolver = std::function<const IssuerKeyset*(const RNS::Bytes&)>;

	class Keyring {

	public:
		Keyring() = default;
		~Keyring() = default;

		/*
		Map a 16-byte Issuer hash to its IssuerKeyset.

		Re-registering an existing hash replaces the keyset in place (insertion
		position is kept — Python dict / JS Map parity, so entries() ordering is
		stable across implementations; identities.msgpack (§13.7) serializes in
		that order).
		*/
		Keyring& register_keyset(const RNS::Bytes& issuer_hash, IssuerKeyset keyset);

		Keyring& register_single(const RNS::Bytes& issuer_hash, const RNS::Bytes& public_key) {
			return register_keyset(issuer_hash, IssuerKeyset::single(public_key));
		}

		Keyring& register_group(
			const RNS::Bytes& group_id,
			Vector<RNS::Bytes> member_public_keys,
			int threshold
		) {
			return register_keyset(group_id, IssuerKeyset::group(std::move(member_public_keys), threshold));
		}

		// Resolve an Issuer hash to its keyset, or nullptr when unknown.
		const IssuerKeyset* resolve(const RNS::Bytes& issuer_hash) const;

		// Remove an Issuer from the keyring. Returns true if it existed.
		bool forget(const RNS::Bytes& issuer_hash);

		// (issuer_hash, keyset) pairs for all registered Issuers, in
		// registration order (Python dict parity).
		Vector<std::pair<RNS::Bytes, IssuerKeyset>> entries() const;

		size_t size() const { return _entries.size(); }
		bool contains(const RNS::Bytes& issuer_hash) const { return _index.find(issuer_hash) != _index.end(); }

		// Make a Keyring directly usable as a KeyResolver.
		const IssuerKeyset* operator () (const RNS::Bytes& issuer_hash) const {
			return resolve(issuer_hash);
		}

	private:
		// Insertion-ordered entries (Python dict parity: identities.msgpack
		// §13.7 writes single-identity entries in registration order) plus a
		// hash -> position index for O(log n) lookups.
		Vector<std::pair<RNS::Bytes, IssuerKeyset>> _entries;
		Map<RNS::Bytes, size_t> _index;

	};

	/*
	Authenticate one Operation against its claimed Issuer (§5.2, §11.2.4).

	Returns true iff the Issuer hash is known to `resolver` AND the Operation
	carries a valid threshold signature from the resolved keyset. An unknown
	Issuer or any cryptographic failure yields false — the Operation MUST be
	dropped rather than merged.
	*/
	bool verify_operation(const Operation& operation, const KeyResolver& resolver);

}
