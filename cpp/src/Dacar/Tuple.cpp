/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Tuple.h"

#include "microReticulum/Cryptography/Hashes.h"

#include <stdexcept>

using namespace Dacar;

static void expectHashSize(const RNS::Bytes& value, const char* name) {
	if (value.size() != HASH_SIZE) {
		throw std::invalid_argument(std::string(name) + " must be 16 bytes, got " + std::to_string(value.size()));
	}
}

Tuple::Tuple(
	RNS::Bytes relation_hash,
	Vector<RNS::Bytes> object_hashes,
	bool wildcard,
	RNS::Bytes grantee,
	RNS::Bytes issuer
) {
	expectHashSize(relation_hash, "relation_hash");
	expectHashSize(grantee, "grantee");
	expectHashSize(issuer, "issuer");
	if (object_hashes.size() > MAX_SEGMENTS) {
		throw std::invalid_argument(
			"too many object segments (" + std::to_string(object_hashes.size()) + " > 255)"
		);
	}
	for (const auto& h : object_hashes) {
		expectHashSize(h, "object segment hash");
	}
	_relation_hash = relation_hash;
	_object_hashes = std::move(object_hashes);
	_wildcard = wildcard;
	_grantee = grantee;
	_issuer = issuer;
}

/*static*/ Tuple Tuple::from_plaintext(
	const std::string& object_id,
	const std::string& relation,
	const RNS::Bytes& grantee,
	const RNS::Bytes& issuer,
	const NamespaceHasher& hasher
) {
	RNS::Bytes relation_hash = hasher.hash_relation(relation);
	auto [object_hashes, wildcard] = hasher.hash_object(object_id);
	return Tuple(relation_hash, std::move(object_hashes), wildcard, grantee, issuer);
}

RNS::Bytes Tuple::preimage() const {
	// §6.1: Issuer + Grantee + Relation Hash + Wildcard Flag
	//       + Segment Count + Object Hashes. No Action, no HLC.
	RNS::Bytes out;
	out.append(_issuer);
	out.append(_grantee);
	out.append(_relation_hash);
	out.append(_wildcard ? 0x01 : 0x00);
	out.append((uint8_t)_object_hashes.size());
	for (const auto& h : _object_hashes) {
		out.append(h);
	}
	return out;
}

RNS::Bytes Tuple::hash() const {
	return RNS::Cryptography::sha256(preimage());
}

bool Tuple::equals(const Tuple& other) const {
	if (!(_relation_hash == other._relation_hash)) return false;
	if (!(_grantee == other._grantee)) return false;
	if (!(_issuer == other._issuer)) return false;
	if (_wildcard != other._wildcard) return false;
	if (_object_hashes.size() != other._object_hashes.size()) return false;
	for (size_t i = 0; i < _object_hashes.size(); i++) {
		if (!(_object_hashes[i] == other._object_hashes[i])) return false;
	}
	return true;
}
