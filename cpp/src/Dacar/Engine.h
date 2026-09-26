/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * The evaluation engine (spec §7).
 *
 * Resolves a plaintext request (Object, Relation, Grantee) against the local
 * CRDT state and the recursive delegation graph, terminating at a Root Trust
 * Anchor.
 *
 * Resolution rules (§7.3):
 *
 *   1. If any valid active Deny Tuple exists, the request is DENIED.
 *   2. Else if any valid active Allow Tuple exists, the request is ALLOWED.
 *   3. Else the request is DENIED.
 *
 * "Valid" means the granting Issuer's authority traces back to a Root Trust
 * Anchor (directly, or recursively via the reserved "admin" relation).
 *
 * Namespace Label Privacy (§3.3) means the engine never compares plaintext
 * labels: it hashes the request with every configured salt (Primary +
 * Legacy, §10.2) and matches the resulting byte arrays against the hashed
 * Tuples in the state. The total-work bound (§7.2) is enforced *per request
 * across all salt tracks simultaneously* (§10.2).
 *
 * The core resolver also accepts pre-hashed hypotheses (evaluate_hashes),
 * which the Strict Consistency Challenge server (§8) uses to evaluate a
 * request that arrives already hashed, without ever recovering plaintext.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Config.h"
#include "Crdt.h"
#include "Namespace.h"

#include <map>
#include <vector>

namespace Dacar {

	// Maximum delegation hops in a single evaluation path (§7.2).
	constexpr int DEFAULT_MAX_DEPTH = 10;

	// Maximum evaluation steps (visited nodes) per request (§7.2).
	constexpr int DEFAULT_MAX_VISITED = 50;

	// The reserved relation that confers the authority to delegate (§3.2).
	constexpr const char* ADMIN_RELATION = "admin";

	/*
	A per-salt hypothesis (§7.1): the hasher that produced the hashes plus the
	hashed request — object segment hashes, the allow relation hash and the
	deny (explicit "-relation") relation hash.
	*/
	struct Hypothesis {
		NamespaceHasher hasher;
		Vector<RNS::Bytes> object_hashes;
		RNS::Bytes allow_relation_hash;
		RNS::Bytes deny_relation_hash;
	};

	class Engine {

	public:
		Engine(
			const Config& config,
			StateVector& state,
			int max_depth = DEFAULT_MAX_DEPTH,
			int max_visited = DEFAULT_MAX_VISITED
		)
			: _config(config), _state(state), _max_depth(max_depth), _max_visited(max_visited)
		{}
		~Engine() = default;

		const Config& config() const { return _config; }
		StateVector& state() const { return _state; }

		/*
		Return true if (object_id, relation, grantee) is ALLOWED.

		Hashes the plaintext request with every configured salt (§7.1, §10.2)
		and delegates to evaluate_hashes().
		*/
		bool evaluate(const std::string& object_id, const std::string& relation, const RNS::Bytes& grantee);

		/*
		Evaluate pre-hashed per-salt hypotheses (§7.3, §10.2).

		`hypotheses` carries one entry per salt. The total-work bound is
		shared across all hypotheses. Returns true iff resolution yields
		ALLOW.
		*/
		bool evaluate_hashes(const RNS::Bytes& grantee, const Vector<Hypothesis>& hypotheses);

	private:
		enum class Resolution { DENY, ALLOW, NONE };

		// Return true if `issuer` may delegate on the hypothesized object.
		bool authority(
			const RNS::Bytes& issuer,
			const Vector<Hypothesis>& hyps,
			int depth,
			const Vector<RNS::Bytes>& visited
		);

		Resolution resolve(
			const Vector<Hypothesis>& hyps,
			const RNS::Bytes& grantee,
			int depth,
			const Vector<RNS::Bytes>& visited
		);

		// Stable memo key for a (issuer, hypotheses) pair:
		// issuer || for each salt: id_tag || count || object hashes.
		RNS::Bytes memo_key(const RNS::Bytes& issuer, const Vector<Hypothesis>& hyps) const;

		const Config& _config;
		StateVector& _state;
		int _max_depth;
		int _max_visited;

		// Per-evaluate_hashes scratch state (kept as members to avoid
		// reallocating deep recursion frames; only positives are memoized,
		// matching the reference implementation).
		Map<RNS::Bytes, std::vector<const Tuple*>> _index;
		Map<RNS::Bytes, bool> _memo;
		int _counter = 0;

	};

}
