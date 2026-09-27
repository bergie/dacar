/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Challenge.h"

#include "microReticulum/Cryptography/Random.h"
#include "microReticulum/Log.h"

#include <MsgPack.h>

#include <stdexcept>

namespace Dacar {

// -- helpers ---------------------------------------------------------------------

namespace {

	void expectBlob(const RNS::Bytes& value, size_t length, const char* name) {
		if (value.size() != length) {
			throw std::invalid_argument(
				std::string(name) + " must be a " + std::to_string(length) + "-byte binary blob"
			);
		}
	}

} // namespace

// -- Challenge (§8.3) ------------------------------------------------------------

Challenge::Challenge(
	std::string object_id,
	std::string relation,
	RNS::Bytes grantee,
	RNS::Bytes nonce,
	std::vector<NamespaceHasher> hashers
)
	: _object_id(std::move(object_id)),
	  _relation(std::move(relation)),
	  _grantee(std::move(grantee)),
	  _nonce(std::move(nonce)),
	  _hashers(std::move(hashers))
{
	expectBlob(_grantee, HASH_SIZE, "grantee");
	expectBlob(_nonce, NONCE_SIZE, "nonce");
	if (_hashers.empty()) {
		throw std::invalid_argument("at least one salt hasher is required");
	}
}

/*static*/ Challenge Challenge::generate(
	const std::string& object_id,
	const std::string& relation,
	const RNS::Bytes& grantee,
	const std::vector<NamespaceHasher>& hashers,
	const RNS::Bytes& nonce
) {
	RNS::Bytes fresh = nonce;
	if (!fresh) {
		fresh = RNS::Cryptography::random(NONCE_SIZE);
	}
	return Challenge(object_id, relation, grantee, fresh, hashers);
}

RNS::Bytes Challenge::to_payload() const {
	MsgPack::Packer p;
	p.packArraySize(2);
	p.packBinary(_nonce.data(), _nonce.size());
	p.packArraySize(_hashers.size());
	for (const auto& hasher : _hashers) {
		const RNS::Bytes tag = hasher.id_tag();
		const RNS::Bytes allow = hasher.hash_relation(_relation);
		const RNS::Bytes deny = hasher.hash_relation("-" + _relation);
		auto objectHashes = hasher.hash_object(_object_id).first;
		p.packArraySize(5);
		p.packBinary(tag.data(), tag.size());
		p.packBinary(_grantee.data(), _grantee.size());
		p.packBinary(allow.data(), allow.size());
		p.packBinary(deny.data(), deny.size());
		p.packArraySize(objectHashes.size());
		for (const auto& segment : objectHashes) {
			p.packBinary(segment.data(), segment.size());
		}
	}
	return RNS::Bytes(p.data(), p.size());
}

DecodedChallenge decode_challenge_payload(const RNS::Bytes& data) {
	MsgPack::Unpacker u;
	if (!(data && u.feed(data.data(), data.size()) && u.isArray())) {
		throw std::invalid_argument("challenge payload must be a 2-element MessagePack array");
	}
	if (u.unpackArraySize() != 2) {
		throw std::invalid_argument("challenge payload must be a 2-element MessagePack array");
	}

	DecodedChallenge decoded;
	{
		MsgPack::bin_t<uint8_t> nonce;
		if (!u.deserialize(nonce)) {
			throw std::invalid_argument("nonce must be a 32-byte binary blob");
		}
		decoded.nonce = RNS::Bytes(nonce.data(), nonce.size());
		expectBlob(decoded.nonce, NONCE_SIZE, "nonce");
	}

	if (!u.isArray()) {
		throw std::invalid_argument("challenge entries must be an array");
	}
	const size_t entryCount = u.unpackArraySize();
	for (size_t i = 0; i < entryCount; i++) {
		if (!u.isArray() || u.unpackArraySize() != 5) {
			throw std::invalid_argument("each challenge entry must be a 5-element array");
		}
		ChallengeEntry entry;
		{
			MsgPack::bin_t<uint8_t> blob;
			if (!u.deserialize(blob)) {
				throw std::invalid_argument("salt_id_tag must be a 16-byte binary blob");
			}
			entry.salt_id_tag = RNS::Bytes(blob.data(), blob.size());
			expectBlob(entry.salt_id_tag, HASH_SIZE, "salt_id_tag");
			if (!u.deserialize(blob)) {
				throw std::invalid_argument("grantee_hash must be a 16-byte binary blob");
			}
			entry.grantee_hash = RNS::Bytes(blob.data(), blob.size());
			expectBlob(entry.grantee_hash, HASH_SIZE, "grantee_hash");
			if (!u.deserialize(blob)) {
				throw std::invalid_argument("allow_relation_hash must be a 16-byte binary blob");
			}
			entry.allow_relation_hash = RNS::Bytes(blob.data(), blob.size());
			expectBlob(entry.allow_relation_hash, HASH_SIZE, "allow_relation_hash");
			if (!u.deserialize(blob)) {
				throw std::invalid_argument("deny_relation_hash must be a 16-byte binary blob");
			}
			entry.deny_relation_hash = RNS::Bytes(blob.data(), blob.size());
			expectBlob(entry.deny_relation_hash, HASH_SIZE, "deny_relation_hash");
		}
		if (!u.isArray()) {
			throw std::invalid_argument("object_segment_hashes must be an array");
		}
		const size_t segmentCount = u.unpackArraySize();
		for (size_t s = 0; s < segmentCount; s++) {
			MsgPack::bin_t<uint8_t> blob;
			if (!u.deserialize(blob)) {
				throw std::invalid_argument("object segment hash must be a 16-byte binary blob");
			}
			entry.object_hashes.push_back(RNS::Bytes(blob.data(), blob.size()));
		}
		if (!decoded.grantee) {
			decoded.grantee = entry.grantee_hash;
		}
		else if (decoded.grantee != entry.grantee_hash) {
			throw std::invalid_argument("all challenge entries must share one grantee");
		}
		decoded.entries.push_back(entry);
	}
	if (!decoded.grantee) {
		throw std::invalid_argument("challenge must carry at least one entry");
	}
	return decoded;
}

// -- Receipt (§8.5) -----------------------------------------------------------------

Receipt::Receipt(Verdict verdict, uint64_t server_hlc, RNS::Bytes nonce, RNS::Bytes signature)
	: _verdict(verdict), _server_hlc(server_hlc), _nonce(std::move(nonce)), _signature(std::move(signature))
{
	expectBlob(_nonce, NONCE_SIZE, "nonce");
	if (_signature && _signature.size() != SIGNATURE_SIZE) {
		throw std::invalid_argument("signature must be 64 bytes");
	}
}

RNS::Bytes Receipt::preimage() const {
	// Unpadded concatenation: verdict_status(1) + server_hlc(8, big-endian) + nonce(32).
	RNS::Bytes out;
	uint8_t* buf = out.writable(1 + HLC_BYTES + _nonce.size());
	buf[0] = (uint8_t)_verdict;
	for (size_t i = 0; i < HLC_BYTES; i++) {
		buf[1 + i] = (uint8_t)(_server_hlc >> (8 * (HLC_BYTES - 1 - i)));
	}
	memcpy(buf + 1 + HLC_BYTES, _nonce.data(), _nonce.size());
	return out;
}

Receipt Receipt::sign(const RNS::Cryptography::Ed25519PrivateKey::Ptr& private_key) const {
	if (!private_key) {
		throw std::invalid_argument("a signing key is required");
	}
	return Receipt(_verdict, _server_hlc, _nonce, private_key->sign(preimage()));
}

bool Receipt::verify(const RNS::Bytes& public_key) const {
	if (_signature.size() != SIGNATURE_SIZE || public_key.size() != PUBLIC_KEY_SIZE) {
		return false;
	}
	auto key = RNS::Cryptography::Ed25519PublicKey::from_public_bytes(public_key);
	if (!key) {
		return false;
	}
	return key->verify(_signature, preimage());
}

RNS::Bytes Receipt::to_payload() const {
	if (_signature.size() != SIGNATURE_SIZE) {
		throw std::invalid_argument("Receipt must be signed before payload serialization");
	}
	MsgPack::Packer p;
	p.packArraySize(4);
	p.pack((uint8_t)_verdict);
	p.pack(_server_hlc);
	p.packBinary(_nonce.data(), _nonce.size());
	p.packBinary(_signature.data(), _signature.size());
	return RNS::Bytes(p.data(), p.size());
}

/*static*/ Receipt Receipt::from_payload(const RNS::Bytes& data) {
	MsgPack::Unpacker u;
	if (!(data && u.feed(data.data(), data.size()) && u.isArray())) {
		throw std::invalid_argument("receipt payload must be a 4-element MessagePack array");
	}
	if (u.unpackArraySize() != 4) {
		throw std::invalid_argument("receipt payload must be a 4-element MessagePack array");
	}
	uint8_t verdictByte = 0xFF;
	if (!u.deserialize(verdictByte) || (verdictByte != (uint8_t)Verdict::ALLOW && verdictByte != (uint8_t)Verdict::DENY)) {
		throw std::invalid_argument("unknown verdict byte");
	}
	uint64_t serverHlc = 0;
	if (!u.deserialize(serverHlc)) {
		throw std::invalid_argument("server_hlc must be a uint64 integer");
	}
	MsgPack::bin_t<uint8_t> nonce;
	if (!u.deserialize(nonce)) {
		throw std::invalid_argument("nonce must be a 32-byte binary blob");
	}
	MsgPack::bin_t<uint8_t> signature;
	if (!u.deserialize(signature)) {
		throw std::invalid_argument("signature must be a 64-byte binary blob");
	}
	return Receipt(
		(Verdict)verdictByte,
		serverHlc,
		RNS::Bytes(nonce.data(), nonce.size()),
		RNS::Bytes(signature.data(), signature.size())
	);
}

// -- AuthoritativeServer (§8.4) ------------------------------------------------------

RNS::Bytes AuthoritativeServer::handle(const RNS::Bytes& challenge_payload) {
	const DecodedChallenge decoded = decode_challenge_payload(challenge_payload);

	// Bind each decoded entry to a configured salt via its salt_id_tag (§8.4).
	Vector<Hypothesis> hypotheses;
	{
		std::vector<NamespaceHasher> hashers = _config.hashers();
		for (const auto& entry : decoded.entries) {
			for (const auto& hasher : hashers) {
				if (hasher.id_tag() == entry.salt_id_tag) {
					Hypothesis hypothesis;
					hypothesis.hasher = hasher;
					hypothesis.object_hashes = entry.object_hashes;
					hypothesis.allow_relation_hash = entry.allow_relation_hash;
					hypothesis.deny_relation_hash = entry.deny_relation_hash;
					hypotheses.push_back(hypothesis);
					break;
				}
			}
			// unknown salt -> hypothesis unusable, skip
		}
	}

	// No recognizable salt -> cannot prove allowance (§8.4).
	const bool allowed =
		!hypotheses.empty() && _engine.evaluate_hashes(decoded.grantee, hypotheses);

	const Verdict verdict = allowed ? Verdict::ALLOW : Verdict::DENY;
	return Receipt(verdict, _clock.now(), decoded.nonce).sign(_private_key).to_payload();
}

// -- ChallengeClient (§8.1–§8.6) ------------------------------------------------------

ChallengeClient::ChallengeClient(
	const Config& config,
	StateVector& state,
	RNS::Bytes authoritative_public_key,
	ChallengeTransport transport
)
	: _engine(config, state), _state(state), _config(config),
	  _public_key(std::move(authoritative_public_key)), _transport(std::move(transport))
{
	if (!_config.authoritative_identity()) {
		throw std::invalid_argument("Strict Consistency requires an Authoritative Identity (§8)");
	}
	if (_public_key.size() != PUBLIC_KEY_SIZE) {
		throw std::invalid_argument(
			"authoritative public key must be 32 bytes, got " + std::to_string(_public_key.size())
		);
	}
}

bool ChallengeClient::authorize(
	const std::string& object_id, const std::string& relation, const RNS::Bytes& grantee
) {
	// §8.1 Local pre-check: denied locally -> fail immediately.
	if (!_engine.evaluate(object_id, relation, grantee)) {
		return false;
	}
	// §8.2/§8.3 Challenge across Primary + Legacy salts.
	Challenge challenge = Challenge::generate(object_id, relation, grantee, _config.hashers());
	RNS::Bytes receiptPayload;
	try {
		receiptPayload = _transport(challenge.to_payload());
	}
	catch (...) {
		return false; // partition penalty (§8)
	}
	if (!receiptPayload) {
		return false; // partition penalty (§8)
	}
	Receipt receipt;
	try {
		receipt = Receipt::from_payload(receiptPayload);
	}
	catch (const std::invalid_argument&) {
		return false; // malformed receipt -> treated as DENY
	}
	// §8.5 Verify the nonce matches exactly and the signature is valid.
	if (receipt.nonce() != challenge.nonce() || !receipt.verify(_public_key)) {
		return false; // invalid sig / nonce -> treated as DENY
	}
	return receipt.verdict() == Verdict::ALLOW;
}

}
