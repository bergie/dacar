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
	_map[issuer_hash] = std::move(keyset);
	return *this;
}

const IssuerKeyset* Keyring::resolve(const RNS::Bytes& issuer_hash) const {
	auto it = _map.find(issuer_hash);
	if (it == _map.end()) {
		return nullptr;
	}
	return &it->second;
}

bool Keyring::forget(const RNS::Bytes& issuer_hash) {
	return _map.erase(issuer_hash) > 0;
}

Vector<std::pair<RNS::Bytes, IssuerKeyset>> Keyring::entries() const {
	return {_map.begin(), _map.end()};
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
