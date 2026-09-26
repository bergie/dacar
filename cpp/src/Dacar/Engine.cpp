/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Engine.h"

#include <string>

using namespace Dacar;

bool Engine::evaluate(const std::string& object_id, const std::string& relation, const RNS::Bytes& grantee) {
	// §7.1 hypothesis generation, duplicated for every configured salt (§10.2).
	Vector<Hypothesis> hypotheses;
	for (const auto& hasher : _config.hashers()) {
		auto [object_hashes, _wildcard] = hasher.hash_object(object_id);
		Hypothesis hyp;
		hyp.hasher = hasher;
		hyp.object_hashes = std::move(object_hashes);
		hyp.allow_relation_hash = hasher.hash_relation(relation);
		hyp.deny_relation_hash = hasher.hash_relation("-" + relation);
		hypotheses.push_back(std::move(hyp));
	}
	return evaluate_hashes(grantee, hypotheses);
}

bool Engine::evaluate_hashes(const RNS::Bytes& grantee, const Vector<Hypothesis>& hypotheses) {
	// Index active tuples by grantee for this request.
	_index.clear();
	for (const Tuple* t : _state.active_tuples()) {
		_index[t->grantee()].push_back(t);
	}
	_memo.clear();
	_counter = 0;
	return resolve(hypotheses, grantee, 0, {}) == Resolution::ALLOW;
}

RNS::Bytes Engine::memo_key(const RNS::Bytes& issuer, const Vector<Hypothesis>& hyps) const {
	// issuer || per salt: id_tag || count || object hashes. All hashes are
	// fixed 16-byte blobs, so the packed form is unambiguous.
	RNS::Bytes key;
	key.append(issuer);
	for (const auto& hyp : hyps) {
		key.append(hyp.hasher.id_tag());
		key.append((uint8_t)hyp.object_hashes.size());
		for (const auto& h : hyp.object_hashes) {
			key.append(h);
		}
	}
	return key;
}

bool Engine::authority(
	const RNS::Bytes& issuer,
	const Vector<Hypothesis>& hyps,
	int depth,
	const Vector<RNS::Bytes>& visited
) {
	if (_config.is_root_anchor(issuer)) {
		return true; // §7.2 terminal trust anchor
	}
	RNS::Bytes key = memo_key(issuer, hyps);
	auto it = _memo.find(key);
	if (it != _memo.end()) {
		return it->second;
	}
	if (depth >= _max_depth) {
		return false; // §7.2 recursion depth bound
	}
	for (const auto& v : visited) {
		if (v == issuer) {
			return false; // §7.2 cycle detection
		}
	}
	// Does `issuer` hold the reserved `admin` relation on the hypothesized
	// object? (§3.2, §7.2)
	Vector<Hypothesis> admin_hyps;
	admin_hyps.reserve(hyps.size());
	for (const auto& hyp : hyps) {
		Hypothesis admin;
		admin.hasher = hyp.hasher;
		admin.object_hashes = hyp.object_hashes;
		admin.allow_relation_hash = hyp.hasher.hash_relation(ADMIN_RELATION);
		admin.deny_relation_hash = hyp.hasher.hash_relation(std::string("-") + ADMIN_RELATION);
		admin_hyps.push_back(std::move(admin));
	}
	Vector<RNS::Bytes> next_visited = visited;
	next_visited.push_back(issuer);
	bool result = (resolve(admin_hyps, issuer, depth + 1, next_visited) == Resolution::ALLOW);
	if (result) {
		// Only positives are cached (path-independent); negatives may be
		// path-dependent through the shared work bound.
		_memo[key] = true;
	}
	return result;
}

Engine::Resolution Engine::resolve(
	const Vector<Hypothesis>& hyps,
	const RNS::Bytes& grantee,
	int depth,
	const Vector<RNS::Bytes>& visited
) {
	_counter++;
	if (_counter > _max_visited) {
		return Resolution::NONE; // §7.2 / §10.2 shared total-work bound
	}
	bool deny_valid = false;
	bool allow_valid = false;
	auto it = _index.find(grantee);
	if (it != _index.end()) {
		for (const Tuple* candidate : it->second) {
			for (const auto& hyp : hyps) {
				if (candidate->relation_hash() == hyp.deny_relation_hash) {
					if (covers(candidate->object_hashes(), candidate->wildcard(), hyp.object_hashes)) {
						if (authority(candidate->issuer(), hyps, depth, visited)) {
							deny_valid = true;
						}
					}
				}
				else if (candidate->relation_hash() == hyp.allow_relation_hash) {
					if (covers(candidate->object_hashes(), candidate->wildcard(), hyp.object_hashes)) {
						if (authority(candidate->issuer(), hyps, depth, visited)) {
							allow_valid = true;
						}
					}
				}
			}
		}
	}
	if (deny_valid) {
		return Resolution::DENY;
	}
	if (allow_valid) {
		return Resolution::ALLOW;
	}
	return Resolution::NONE;
}
