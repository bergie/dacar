/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Verifier.h"

#include <stdexcept>

using namespace Dacar;

IssuerKeyset::IssuerKeyset(Vector<RNS::Bytes> member_public_keys, int threshold)
	: _member_public_keys(std::move(member_public_keys)), _threshold(threshold)
{
	if (threshold < 1) {
		throw std::invalid_argument("threshold must be a positive integer");
	}
	for (const auto& k : _member_public_keys) {
		if (k.size() != PUBLIC_KEY_SIZE) {
			throw std::invalid_argument(
				"Ed25519 public keys are 32 raw bytes, got " + std::to_string(k.size())
			);
		}
	}
	if (_member_public_keys.size() < (size_t)_threshold) {
		throw std::invalid_argument("need at least `threshold` member public keys");
	}
}

Keyring& Keyring::register_keyset(const RNS::Bytes& issuer_hash, IssuerKeyset keyset) {
	auto it = _index.find(issuer_hash);
	if (it != _index.end()) {
		// Python dict semantics: overwrite the value, keep the position.
		_entries[it->second].second = std::move(keyset);
		return *this;
	}
	_index[issuer_hash] = _entries.size();
	_entries.emplace_back(issuer_hash, std::move(keyset));
	return *this;
}

const IssuerKeyset* Keyring::resolve(const RNS::Bytes& issuer_hash) const {
	auto it = _index.find(issuer_hash);
	if (it == _index.end()) {
		return nullptr;
	}
	return &_entries[it->second].second;
}

bool Keyring::forget(const RNS::Bytes& issuer_hash) {
	auto it = _index.find(issuer_hash);
	if (it == _index.end()) {
		return false;
	}
	// Keyrings are small; shifting keeps the positions in _index valid.
	size_t pos = it->second;
	_entries.erase(_entries.begin() + pos);
	_index.erase(it);
	for (auto& kv : _index) {
		if (kv.second > pos) {
			kv.second--;
		}
	}
	return true;
}

Vector<std::pair<RNS::Bytes, IssuerKeyset>> Keyring::entries() const {
	return _entries;
}

/*static*/ bool Dacar::verify_operation(const Operation& operation, const KeyResolver& resolver) {
	if (!resolver) {
		return false;
	}
	const IssuerKeyset* keyset = resolver(operation.issuer());
	if (keyset == nullptr) {
		return false;
	}
	return operation.verify_keyset(*keyset);
}
