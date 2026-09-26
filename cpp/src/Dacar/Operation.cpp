/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Operation.h"

#include "Hlc.h"
#include "Verifier.h"

#include <MsgPack.h>

#include <stdexcept>

using namespace Dacar;

Operation::Operation(Tuple tuple, Action action, uint64_t hlc, Vector<RNS::Bytes> signatures)
	: _tuple(std::move(tuple)), _action(action), _hlc(hlc), _signatures(std::move(signatures))
{
	if (_hlc > MAX_HLC) {
		throw std::invalid_argument("hlc must fit in 64 bits");
	}
	for (const auto& sig : _signatures) {
		if (sig.size() != SIGNATURE_SIZE) {
			throw std::invalid_argument(
				"each signature must be 64 bytes, got " + std::to_string(sig.size())
			);
		}
	}
}

RNS::Bytes Operation::preimage() const {
	// §5.2 binary layout.
	RNS::Bytes out;
	out.append(_tuple.issuer());
	out.append(_tuple.grantee());
	out.append((uint8_t)_action);
	for (int shift = 56; shift >= 0; shift -= 8) {
		out.append((uint8_t)((_hlc >> shift) & 0xFF));
	}
	out.append(_tuple.relation_hash());
	out.append(_tuple.wildcard() ? (uint8_t)0x01 : (uint8_t)0x00);
	out.append((uint8_t)_tuple.object_hashes().size());
	for (const auto& h : _tuple.object_hashes()) {
		out.append(h);
	}
	return out;
}

Operation Operation::sign(
	const std::vector<RNS::Cryptography::Ed25519PrivateKey::Ptr>& private_keys
) const {
	if (private_keys.empty()) {
		throw std::invalid_argument("at least one signing key is required");
	}
	RNS::Bytes preimg = preimage();
	Vector<RNS::Bytes> signatures;
	signatures.reserve(private_keys.size());
	for (const auto& key : private_keys) {
		signatures.push_back(key->sign(preimg));
	}
	return Operation(_tuple, _action, _hlc, std::move(signatures));
}

bool Operation::verify(const RNS::Bytes& public_key) const {
	if (_signatures.size() != 1) {
		return false;
	}
	return verify_threshold({public_key}, 1);
}

bool Operation::verify_threshold(
	const Vector<RNS::Bytes>& member_public_keys, int threshold
) const {
	if (threshold < 1 || _signatures.size() != (size_t)threshold) {
		return false;
	}
	if (member_public_keys.size() < (size_t)threshold) {
		return false;
	}
	RNS::Bytes preimg = preimage();
	std::vector<bool> used(member_public_keys.size(), false);
	size_t used_count = 0;
	for (const auto& sig : _signatures) {
		bool matched = false;
		for (size_t i = 0; i < member_public_keys.size(); i++) {
			if (used[i]) {
				continue;
			}
			auto key = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(member_public_keys[i]);
			if (key->verify(sig, preimg)) {
				used[i] = true;
				used_count++;
				matched = true;
				break;
			}
		}
		if (!matched) {
			return false;
		}
	}
	return used_count == (size_t)threshold;
}

bool Operation::verify_keyset(const IssuerKeyset& keyset) const {
	return verify_threshold(keyset.member_public_keys(), keyset.threshold());
}

RNS::Bytes Operation::to_payload() const {
	if (_signatures.empty()) {
		throw std::invalid_argument("Operation must be signed before payload serialization");
	}
	// §5.3 MessagePack array:
	// [issuer, grantee, action, hlc, relation_hash, [segment_hashes],
	//  wildcard_bool, [sig_1..sig_N]]
	MsgPack::Packer p;
	p.packArraySize(8);
	p.packBinary(_tuple.issuer().data(), _tuple.issuer().size());
	p.packBinary(_tuple.grantee().data(), _tuple.grantee().size());
	p.pack((uint8_t)_action);
	p.pack(_hlc);
	p.packBinary(_tuple.relation_hash().data(), _tuple.relation_hash().size());
	p.packArraySize(_tuple.object_hashes().size());
	for (const auto& h : _tuple.object_hashes()) {
		p.packBinary(h.data(), h.size());
	}
	p.pack(_tuple.wildcard());
	p.packArraySize(_signatures.size());
	for (const auto& sig : _signatures) {
		p.packBinary(sig.data(), sig.size());
	}
	return RNS::Bytes(p.data(), p.size());
}

/*static*/ Operation Operation::from_payload(const RNS::Bytes& data) {
	// NB: never feed empty data to MsgPack::Unpacker — feed() indexes the
	// element list unconditionally and would read out of bounds.
	if (!data) {
		throw std::invalid_argument("payload is empty");
	}
	MsgPack::Unpacker u;
	if (!u.feed(data.data(), data.size())) {
		throw std::invalid_argument("payload is not decodable MessagePack");
	}
	if (!u.isArray()) {
		throw std::invalid_argument("payload must be an 8-element MessagePack array");
	}
	if (u.unpackArraySize() != 8) {
		throw std::invalid_argument("payload must be an 8-element MessagePack array");
	}

	RNS::Bytes issuer;
	RNS::Bytes grantee;
	RNS::Bytes relation_hash;
	int32_t action = -1;
	uint64_t hlc = 0;
	bool wildcard = false;
	Vector<RNS::Bytes> object_hashes;
	Vector<RNS::Bytes> signatures;

	{
		MsgPack::bin_t<uint8_t> b;
		if (!u.deserialize(b) || b.size() != HASH_SIZE) {
			throw std::invalid_argument("issuer must be a 16-byte binary blob");
		}
		issuer.assign(b.data(), b.size());
	}
	{
		MsgPack::bin_t<uint8_t> b;
		if (!u.deserialize(b) || b.size() != HASH_SIZE) {
			throw std::invalid_argument("grantee must be a 16-byte binary blob");
		}
		grantee.assign(b.data(), b.size());
	}
	if (!u.deserialize(action) || (action != (int32_t)Action::GRANT && action != (int32_t)Action::REVOKE)) {
		throw std::invalid_argument("unknown action byte");
	}
	if (!u.deserialize(hlc)) {
		throw std::invalid_argument("hlc must be a uint64 integer");
	}
	{
		MsgPack::bin_t<uint8_t> b;
		if (!u.deserialize(b) || b.size() != HASH_SIZE) {
			throw std::invalid_argument("relation_hash must be a 16-byte binary blob");
		}
		relation_hash.assign(b.data(), b.size());
	}
	{
		if (!u.isArray()) {
			throw std::invalid_argument("object_hashes must be an array of 16-byte blobs");
		}
		size_t count = u.unpackArraySize();
		object_hashes.reserve(count);
		for (size_t i = 0; i < count; i++) {
			MsgPack::bin_t<uint8_t> b;
			if (!u.deserialize(b) || b.size() != HASH_SIZE) {
				throw std::invalid_argument("object_hashes[" + std::to_string(i) + "] must be 16 bytes");
			}
			object_hashes.emplace_back(b.data(), b.size());
		}
	}
	if (!u.deserialize(wildcard)) {
		throw std::invalid_argument("wildcard must be a boolean");
	}
	{
		if (!u.isArray()) {
			throw std::invalid_argument("signatures must be a non-empty array of 64-byte blobs");
		}
		size_t count = u.unpackArraySize();
		if (count == 0) {
			throw std::invalid_argument("signatures must be a non-empty array of 64-byte blobs");
		}
		signatures.reserve(count);
		for (size_t i = 0; i < count; i++) {
			MsgPack::bin_t<uint8_t> b;
			if (!u.deserialize(b) || b.size() != SIGNATURE_SIZE) {
				throw std::invalid_argument("signatures[" + std::to_string(i) + "] must be 64 bytes");
			}
			signatures.emplace_back(b.data(), b.size());
		}
	}

	return Operation(
		Tuple(std::move(relation_hash), std::move(object_hashes), wildcard, std::move(grantee), std::move(issuer)),
		(Action)action,
		hlc,
		std::move(signatures)
	);
}
