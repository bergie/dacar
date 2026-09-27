/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Delta.h"

#include <MsgPack.h>

#include <string>

using namespace Dacar;

bool DeltaReceiver::apply_payload(const RNS::Bytes& payload, int64_t now_ms, int64_t max_future_ms) {
	if (!payload) {
		return false; // empty -> drop silently
	}
	Operation operation;
	try {
		operation = Operation::from_payload(payload);
	}
	catch (const std::invalid_argument&) {
		return false; // malformed -> drop silently
	}
	// Unknown Issuer, bad signature, stale (§9) or future-skewed (§12):
	// all rejected by the secure ingest path.
	return _state.ingest(operation, _resolver, now_ms, max_future_ms);
}

size_t DeltaReceiver::apply_payloads(const RNS::Bytes& payload, int64_t now_ms, int64_t max_future_ms) {
	MsgPack::Unpacker u;
	if (!payload || !u.feed(payload.data(), payload.size()) || !u.isArray()) {
		return 0; // malformed outer payload -> drop silently
	}
	size_t count = u.unpackArraySize();
	size_t applied = 0;
	for (size_t i = 0; i < count; i++) {
		MsgPack::bin_t<uint8_t> b;
		if (!u.deserialize(b)) {
			continue; // skip non-bin elements defensively
		}
		if (apply_payload(RNS::Bytes(b.data(), b.size()), now_ms, max_future_ms)) {
			applied++;
		}
	}
	return applied;
}

/*static*/ RNS::Bytes DeltaReceiver::pack_payloads(const Vector<RNS::Bytes>& operation_payloads) {
	MsgPack::Packer p;
	p.packArraySize(operation_payloads.size());
	for (const auto& payload : operation_payloads) {
		p.packBinary(payload.data(), payload.size());
	}
	return RNS::Bytes(p.data(), p.size());
}

RNS::Bytes DeltaReceiver::handle_push(const RNS::Bytes& request, int64_t now_ms, int64_t max_future_ms) {
	size_t applied = 0;
	if (request && apply_payload(request, now_ms, max_future_ms)) {
		applied = 1;
	}
	else if (request) {
		try {
			applied = apply_payloads(request, now_ms, max_future_ms);
		}
		catch (...) {
			applied = 0; // garbage must never crash a request handler
		}
	}
	return pack_ack(applied);
}

/*static*/ RNS::Bytes DeltaReceiver::pack_ack(size_t applied) {
	MsgPack::Packer p;
	p.packMapSize(1);
	p.pack(std::string("applied"));
	p.pack<uint32_t>((uint32_t)applied);
	return RNS::Bytes(p.data(), p.size());
}
