/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Namespace.h"

#include <stdexcept>

using namespace Dacar;

/*static*/ const RNS::Bytes& Dacar::DEFAULT_SALT() {
	// NB: RNS::Bytes(size_t) only *reserves* capacity; writable() grows and
	// zero-fills the buffer, yielding exactly 32 null bytes.
	static RNS::Bytes* salt = nullptr;
	if (!salt) {
		salt = new RNS::Bytes();
		salt->writable(SALT_SIZE);
	}
	return *salt;
}

/*static*/ RNS::Bytes Dacar::hmac16(const RNS::Bytes& salt, const RNS::Bytes& message) {
	// HMAC-SHA256 keyed with the salt over the message (the constructor both
	// keys and feeds the initial message, matching Python's hmac.new(key, msg)).
	RNS::Cryptography::HMAC hmac(salt, message);
	return hmac.digest().left(HASH_SIZE);
}

/*static*/ std::vector<std::string> Dacar::split(const std::string& object_id) {
	// Python str.split(':') semantics: empty input -> one empty segment.
	std::vector<std::string> segments;
	std::string current;
	for (char c : object_id) {
		if (c == DELIMITER) {
			segments.push_back(current);
			current.clear();
		}
		else {
			current.push_back(c);
		}
	}
	segments.push_back(current);
	return segments;
}

NamespaceHasher::NamespaceHasher(const RNS::Bytes& salt) {
	if (salt.size() != SALT_SIZE) {
		throw std::invalid_argument("salt must be 32 bytes, got " + std::to_string(salt.size()));
	}
	_salt = salt;
}

RNS::Bytes NamespaceHasher::hash_relation(const std::string& relation) const {
	return hmac16(_salt, RNS::Bytes(relation.c_str(), relation.size()));
}

std::pair<Vector<RNS::Bytes>, bool> NamespaceHasher::hash_object(const std::string& object_id) const {
	// Parse: strip the terminal wildcard, then hash each remaining segment
	// individually (§3.3).
	bool wildcard = false;
	std::vector<std::string> segments;
	if (object_id.size() == 1 && object_id[0] == WILDCARD) {
		// Root wildcard: zero segments.
		wildcard = true;
	}
	else {
		segments = split(object_id);
		if (!segments.empty() && segments.back().size() == 1 && segments.back()[0] == WILDCARD) {
			wildcard = true;
			segments.pop_back();
		}
	}
	Vector<RNS::Bytes> hashes;
	hashes.reserve(segments.size());
	for (const auto& segment : segments) {
		hashes.push_back(hmac16(_salt, RNS::Bytes(segment.c_str(), segment.size())));
	}
	return {std::move(hashes), wildcard};
}

RNS::Bytes NamespaceHasher::id_tag() const {
	static const std::string tag("dacar.salt.id");
	return hmac16(_salt, RNS::Bytes(tag.c_str(), tag.size()));
}

/*static*/ bool Dacar::covers(
	const Vector<RNS::Bytes>& tuple_hashes,
	bool wildcard,
	const Vector<RNS::Bytes>& request_hashes
) {
	if (wildcard) {
		if (tuple_hashes.size() > request_hashes.size()) {
			return false;
		}
		for (size_t i = 0; i < tuple_hashes.size(); i++) {
			if (!(tuple_hashes[i] == request_hashes[i])) {
				return false;
			}
		}
		return true;
	}
	if (tuple_hashes.size() != request_hashes.size()) {
		return false;
	}
	for (size_t i = 0; i < tuple_hashes.size(); i++) {
		if (!(tuple_hashes[i] == request_hashes[i])) {
			return false;
		}
	}
	return true;
}
