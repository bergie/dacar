/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Signed authorization Operations / Deltas (Dacar spec §5.2, §5.3).
 *
 * An Operation is a cryptographically signed instruction to Grant (Add) or
 * Revoke (Remove) a specific Tuple. Operations are the unit of CRDT mutation
 * and transport.
 *
 * For Threshold Group issuers (§4.1), an Operation carries exactly N
 * signatures from N distinct members of the M-set.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Tuple.h"

#include "microReticulum/Cryptography/Ed25519.h"

#include <vector>

namespace Dacar {

	// Ed25519 signatures are always 64 bytes.
	constexpr size_t SIGNATURE_SIZE = 64;

	// HLC timestamps travel as 64-bit big-endian unsigned integers.
	constexpr size_t HLC_BYTES = 8;

	enum class Action : uint8_t {
		REVOKE = 0x00, // Remove the Tuple from the Add set.
		GRANT  = 0x01, // Add the Tuple to the Add set.
	};

	class Operation {

	public:
		Operation() = default;
		~Operation() = default;

		/*
		A signed or not-yet-signed Grant/Revoke of a Tuple at a given HLC.
		Throws std::invalid_argument when the HLC exceeds 64 bits or any
		signature is not exactly SIGNATURE_SIZE bytes.
		*/
		Operation(Tuple tuple, Action action, uint64_t hlc, Vector<RNS::Bytes> signatures = {});

		// -- tuple accessors (delegate to the embedded Tuple) ---------------
		const Tuple& tuple() const { return _tuple; }
		const RNS::Bytes& issuer() const { return _tuple.issuer(); }
		const RNS::Bytes& grantee() const { return _tuple.grantee(); }
		const RNS::Bytes& relation_hash() const { return _tuple.relation_hash(); }
		const Vector<RNS::Bytes>& object_hashes() const { return _tuple.object_hashes(); }
		bool wildcard() const { return _tuple.wildcard(); }

		Action action() const { return _action; }
		uint64_t hlc() const { return _hlc; }
		const Vector<RNS::Bytes>& signatures() const { return _signatures; }

		// -- cryptography (§5.2) ---------------------------------------------
		/*
		Return the signature pre-image per the §5.2 binary layout:

		  issuer(16) + grantee(16) + action(1) + hlc(8) + relation_hash(16)
		  + wildcard(1) + segment_count(1) + object_hashes(S*16)
		*/
		RNS::Bytes preimage() const;

		/*
		Return a copy signed with one or more Ed25519 private keys. Each key
		produces one signature, in argument order. Pass a single key for a
		single-identity issuer, or N member keys for a Threshold Group issuer
		(§5.2). Throws std::invalid_argument when no key is given.
		*/
		Operation sign(const std::vector<RNS::Cryptography::Ed25519PrivateKey::Ptr>& private_keys) const;

		/*
		Verify a single-identity Operation against one raw 32-byte Ed25519
		public key (§5.2).
		*/
		bool verify(const RNS::Bytes& public_key) const;

		/*
		Verify a Threshold Group Operation (§5.2, §4.1). Requires exactly
		`threshold` signatures, each valid against a *distinct* member public
		key of the M-set. Duplicate signatures or signatures that verify
		against the same public key more than once are rejected.
		*/
		bool verify_threshold(const Vector<RNS::Bytes>& member_public_keys, int threshold) const;

		/*
		Verify against a resolved IssuerKeyset — the bridge used by
		verify-on-ingest (§11.2.4).
		*/
		bool verify_keyset(const class IssuerKeyset& keyset) const;

		// -- transport (§5.3) -------------------------------------------------
		/*
		Serialize to the 8-element MessagePack transport array (§5.3):

		  [issuer(16), grantee(16), action, hlc, relation_hash(16),
		   [segment_hashes], wildcard_bool, [sig_1, ..., sig_N]]

		Throws std::invalid_argument if unsigned.
		*/
		RNS::Bytes to_payload() const;

		/*
		Deserialize an 8-element MessagePack transport array (§5.3). Throws
		std::invalid_argument on malformed payloads.
		*/
		static Operation from_payload(const RNS::Bytes& data);

	private:
		Tuple _tuple;
		Action _action = Action::REVOKE;
		uint64_t _hlc = 0;
		Vector<RNS::Bytes> _signatures;

	};

}
