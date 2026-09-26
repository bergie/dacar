/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * The authorization Tuple and its canonical hash (Dacar spec §3.1, §6.1).
 *
 * A Tuple asserts that a Grantee holds a Relation over an Object, authorized
 * by an Issuer:
 *
 *     (Object, Relation, Grantee, Issuer)
 *
 * Because two different administrators granting identical permissions produce
 * two distinct Tuples, the Issuer is incorporated into the tuple identity
 * (§3.1).
 *
 * For Namespace Label Privacy (§3.3), the Relation and Object are stored
 * *only* as their 16-byte salted hashes. The Tuple Hash (§6.1) is SHA-256
 * over:
 *
 *     [16-byte Issuer] + [16-byte Grantee] + [16-byte Relation Hash]
 *     + [1-byte Wildcard Flag] + [1-byte Segment Count] + [Object Hashes]
 *
 * The Action byte and HLC timestamp are deliberately excluded, so a Grant
 * and its Revoke for the same permission resolve to the *same* Tuple Hash.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Namespace.h"

#include <vector>

namespace Dacar {

	// Maximum number of Object segments (the Segment Count field is one byte).
	constexpr size_t MAX_SEGMENTS = 0xFF;

	class Tuple {

	public:
		Tuple() = default;
		~Tuple() = default;

		/*
		Construct a hashed authorization relationship. Throws
		std::invalid_argument when any hash has the wrong length or the
		segment count exceeds MAX_SEGMENTS.
		*/
		Tuple(
			RNS::Bytes relation_hash,
			Vector<RNS::Bytes> object_hashes,
			bool wildcard,
			RNS::Bytes grantee,
			RNS::Bytes issuer
		);

		/*
		Build a Tuple by hashing plaintext labels with `hasher` (§3.3).
		*/
		static Tuple from_plaintext(
			const std::string& object_id,
			const std::string& relation,
			const RNS::Bytes& grantee,
			const RNS::Bytes& issuer,
			const NamespaceHasher& hasher
		);

		const RNS::Bytes& relation_hash() const { return _relation_hash; }
		const Vector<RNS::Bytes>& object_hashes() const { return _object_hashes; }
		bool wildcard() const { return _wildcard; }
		const RNS::Bytes& grantee() const { return _grantee; }
		const RNS::Bytes& issuer() const { return _issuer; }

		/*
		Return the canonical §6.1 binary pre-image (excludes Action + HLC).
		*/
		RNS::Bytes preimage() const;

		/*
		Return the 32-byte SHA-256 Tuple Hash (the CRDT map key).
		*/
		RNS::Bytes hash() const;

		// Alias for hash() (the stable CRDT identity).
		RNS::Bytes key() const { return hash(); }

		bool equals(const Tuple& other) const;
		bool operator == (const Tuple& other) const { return equals(other); }
		bool operator != (const Tuple& other) const { return !equals(other); }

	private:
		RNS::Bytes _relation_hash;
		Vector<RNS::Bytes> _object_hashes;
		bool _wildcard = false;
		RNS::Bytes _grantee;
		RNS::Bytes _issuer;

	};

}
