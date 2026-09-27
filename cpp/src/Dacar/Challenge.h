/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Strict Consistency Challenge / Freshness Receipts (spec §8).
 *
 * For destructive operations, eventual consistency is dangerous. A node
 * performs a local pre-check, then challenges a configured Authoritative
 * Identity over an RNS link (App Name `dacar`, Aspects `auth`, `v1`) for a
 * signed verdict evaluated against the server's absolute-latest CRDT state.
 *
 * To preserve Namespace Label Privacy (§3.3), the Challenge payload carries
 * only *hashed* hypotheses — never plaintext. The client hashes the request
 * across its Primary Salt and all Legacy Salts (§10); the server matches each
 * by its salt_id_tag and evaluates directly in hash space via
 * Engine::evaluate_hashes.
 *
 * The RNS transport is abstracted behind a `ChallengeTransport` callable
 * (challenge payload -> receipt payload; an empty return is a partition ->
 * immediately DENIED, §8.6), so the cryptographic and verdict logic is fully
 * testable without a live network. The RNS wiring lives in RnsChallenge.h.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Config.h"
#include "Crdt.h"
#include "Engine.h"
#include "Hlc.h"
#include "Namespace.h"

#include "microReticulum/Cryptography/Ed25519.h"

#include <functional>
#include <string>
#include <vector>

namespace Dacar {

	// Cryptographically secure challenge nonces are 32 bytes.
	constexpr size_t NONCE_SIZE = 32;

	// The binary verdict carried by a Freshness Receipt (§8.5).
	enum class Verdict : uint8_t {
		DENY  = 0x00,
		ALLOW = 0x01,
	};

	/*
	The complete evaluation context sent to the Authoritative Identity.
	Plaintext is held only on the client; to_payload() emits hashed
	hypotheses across the supplied salts (§8.3).
	*/
	class Challenge {

	public:
		/*
		Throws std::invalid_argument on a wrong-size grantee (16) or nonce
		(32), or an empty hasher list.
		*/
		Challenge(
			std::string object_id,
			std::string relation,
			RNS::Bytes grantee,
			RNS::Bytes nonce,
			std::vector<NamespaceHasher> hashers
		);
		~Challenge() = default;

		// Build a Challenge with a fresh random 32-byte nonce (or a
		// supplied one — the deterministic-test hook).
		static Challenge generate(
			const std::string& object_id,
			const std::string& relation,
			const RNS::Bytes& grantee,
			const std::vector<NamespaceHasher>& hashers,
			const RNS::Bytes& nonce = RNS::Bytes()
		);

		const std::string& object_id() const { return _object_id; }
		const std::string& relation() const { return _relation; }
		const RNS::Bytes& grantee() const { return _grantee; }
		const RNS::Bytes& nonce() const { return _nonce; }
		const std::vector<NamespaceHasher>& hashers() const { return _hashers; }

		// Serialize the hashed multi-salt challenge (§8.3):
		// [nonce(32), [[salt_id_tag, grantee, allow_rh, deny_rh, [obj...]], ...]]
		RNS::Bytes to_payload() const;

	private:
		std::string _object_id;
		std::string _relation;
		RNS::Bytes _grantee;
		RNS::Bytes _nonce;
		std::vector<NamespaceHasher> _hashers;

	};

	// One decoded per-salt hypothesis (§8.3 entry).
	struct ChallengeEntry {
		RNS::Bytes salt_id_tag;
		RNS::Bytes grantee_hash;
		RNS::Bytes allow_relation_hash;
		RNS::Bytes deny_relation_hash;
		Vector<RNS::Bytes> object_hashes;
	};

	// A decoded challenge: nonce, the (single) grantee, per-salt entries.
	struct DecodedChallenge {
		RNS::Bytes nonce;
		RNS::Bytes grantee;
		Vector<ChallengeEntry> entries;
	};

	/*
	Decode a §8.3 challenge payload. Plaintext is intentionally unrecoverable;
	the caller (the Authority) receives per-salt hashed hypotheses directly.
	Throws std::invalid_argument on malformed payloads.
	*/
	DecodedChallenge decode_challenge_payload(const RNS::Bytes& data);

	/*
	The Authoritative Identity's signed verdict (§8.5):

	  [verdict_status(1), server_hlc(8), nonce(32), ed25519_sig(64)]

	The signature covers the unpadded concatenation of the preceding three
	fields (verdict_status + server_hlc + nonce).
	*/
	class Receipt {

	public:
		/*
		Throws std::invalid_argument on a wrong-size nonce (32) or non-empty
		signature that is not 64 bytes.
		*/
		/*
		Default-constructible so callers can decode into a receipt via the
		tolerant client path. A default receipt carries an empty nonce and
		fails every verification by construction.
		*/
		Receipt() = default;
		~Receipt() = default;

		/*
		Throws std::invalid_argument on a wrong-size nonce (32) or non-empty
		signature that is not 64 bytes.
		*/
		Receipt(Verdict verdict, uint64_t server_hlc, RNS::Bytes nonce, RNS::Bytes signature = RNS::Bytes());

		Verdict verdict() const { return _verdict; }
		uint64_t server_hlc() const { return _server_hlc; }
		const RNS::Bytes& nonce() const { return _nonce; }
		const RNS::Bytes& signature() const { return _signature; }

		// The unpadded concatenation of the fields preceding the signature.
		RNS::Bytes preimage() const;

		// Return a copy signed with an Ed25519 private key.
		Receipt sign(const RNS::Cryptography::Ed25519PrivateKey::Ptr& private_key) const;

		// Verify against a raw 32-byte Ed25519 public key.
		bool verify(const RNS::Bytes& public_key) const;

		// Serialize (§8.5). Throws std::invalid_argument if unsigned.
		RNS::Bytes to_payload() const;

		// Deserialize (§8.5). Throws std::invalid_argument on malformed
		// payloads or an unknown verdict byte.
		static Receipt from_payload(const RNS::Bytes& data);

	private:
		Verdict _verdict = Verdict::DENY;
		uint64_t _server_hlc = 0;
		RNS::Bytes _nonce;
		RNS::Bytes _signature;

	};

	/*
	Transport callable: challenge payload -> receipt payload. Returning an
	empty RNS::Bytes (or throwing) is a partition -> immediately DENIED (§8).
	*/
	using ChallengeTransport = std::function<RNS::Bytes(const RNS::Bytes& challenge_payload)>;

	/*
	The Authoritative Identity: evaluates hashed requests against its own
	absolute-latest CRDT state and signs Freshness Receipts (§8.4).

	Pass a seeded Clock for deterministic receipts in tests (a clock whose
	last_ms lies in the future makes now() purely logical).
	*/
	class AuthoritativeServer {

	public:
		AuthoritativeServer(
			const Config& config,
			StateVector& state,
			RNS::Cryptography::Ed25519PrivateKey::Ptr private_key,
			Clock clock = Clock()
		)
			: _engine(config, state), _state(state), _config(config),
			  _private_key(private_key), _clock(clock)
		{}
		~AuthoritativeServer() = default;

		const Config& config() const { return _config; }
		StateVector& state() const { return _state; }

		/*
		Evaluate a hashed Challenge and return the signed Receipt payload
		(§8.4). Entries whose salt_id_tag matches no configured salt are
		unusable hypotheses; with no recognizable salt at all, allowance
		cannot be proven and the verdict is DENY. Throws
		std::invalid_argument on a malformed challenge payload.
		*/
		RNS::Bytes handle(const RNS::Bytes& challenge_payload);

	private:
		Engine _engine;
		StateVector& _state;
		const Config& _config;
		RNS::Cryptography::Ed25519PrivateKey::Ptr _private_key;
		Clock _clock;

	};

	/*
	The requesting node: performs the local pre-check and the challenge
	exchange (§8.1–§8.6). authorize() returns true only on a verified server
	ALLOW.
	*/
	class ChallengeClient {

	public:
		/*
		Throws std::invalid_argument when the Config has no Authoritative
		Identity configured (Strict Consistency requires one, §8).
		*/
		ChallengeClient(
			const Config& config,
			StateVector& state,
			RNS::Bytes authoritative_public_key,
			ChallengeTransport transport
		);
		~ChallengeClient() = default;

		// Run the full §8 flow for a plaintext request.
		bool authorize(const std::string& object_id, const std::string& relation, const RNS::Bytes& grantee);

	private:
		Engine _engine;
		StateVector& _state;
		const Config& _config;
		RNS::Bytes _public_key;
		ChallengeTransport _transport;

	};

}
