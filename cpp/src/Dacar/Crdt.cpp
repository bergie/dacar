/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Crdt.h"

#include "Hlc.h"

#include "microReticulum/Log.h"

#include <MsgPack.h>

#include <algorithm>
#include <stdexcept>

using namespace Dacar;

static uint64_t max_u64(uint64_t a, uint64_t b) {
	return (a > b) ? a : b;
}

StateVector::Entry& StateVector::entry_for(const Tuple& tuple) {
	RNS::Bytes tuple_hash = tuple.hash();
	auto it = _index.find(tuple_hash);
	if (it != _index.end()) {
		return _entries[it->second];
	}
	_entries.emplace_back();
	_entries.back().tuple = tuple;
	_index[tuple_hash] = _entries.size() - 1;
	return _entries.back();
}

bool StateVector::ingest(
	const Operation& operation,
	const KeyResolver& key_resolver,
	int64_t now_ms,
	int64_t max_future_ms
) {
	if (!verify_operation(operation, key_resolver)) {
		return false;
	}
	return apply(operation, now_ms, max_future_ms);
}

bool StateVector::apply(const Operation& operation, int64_t now_ms, int64_t max_future_ms) {
	auto [physical, _logical] = unpack(operation.hlc());
	uint64_t now = (now_ms < 0) ? physical_now_ms() : (uint64_t)now_ms;
	if (max_future_ms >= 0 && physical > now + (uint64_t)max_future_ms) {
		return false; // §12 timestamp manipulation mitigation
	}
	if (physical < (now > deletion_horizon_ms() ? now - deletion_horizon_ms() : 0)) {
		return false; // §9 intake rejection
	}
	Entry& entry = entry_for(operation.tuple());
	if (operation.action() == Action::GRANT) {
		entry.add_ts = entry.has_add ? max_u64(entry.add_ts, operation.hlc()) : operation.hlc();
		entry.has_add = true;
	}
	else {
		entry.remove_ts = entry.has_remove ? max_u64(entry.remove_ts, operation.hlc()) : operation.hlc();
		entry.has_remove = true;
	}
	return true;
}

void StateVector::merge(const StateVector& other) {
	for (const auto& other_entry : other._entries) {
		Entry& entry = entry_for(other_entry.tuple);
		if (other_entry.has_add) {
			entry.add_ts = entry.has_add ? max_u64(entry.add_ts, other_entry.add_ts) : other_entry.add_ts;
			entry.has_add = true;
		}
		if (other_entry.has_remove) {
			entry.remove_ts = entry.has_remove ? max_u64(entry.remove_ts, other_entry.remove_ts) : other_entry.remove_ts;
			entry.has_remove = true;
		}
	}
}

size_t StateVector::prune(int64_t now_ms) {
	uint64_t now = (now_ms < 0) ? physical_now_ms() : (uint64_t)now_ms;
	uint64_t cutoff = (now > deletion_horizon_ms()) ? now - deletion_horizon_ms() : 0;
	size_t pruned = 0;
	Vector<Entry> kept;
	kept.reserve(_entries.size());
	for (auto& entry : _entries) {
		if (entry.active()) {
			kept.push_back(std::move(entry));
			continue;
		}
		if (!entry.has_add || !entry.has_remove) {
			kept.push_back(std::move(entry));
			continue;
		}
		auto [add_phys, _a] = unpack(entry.add_ts);
		auto [remove_phys, _r] = unpack(entry.remove_ts);
		if (add_phys < cutoff && remove_phys < cutoff) {
			pruned++; // §9 pairwise deletion of both entries
		}
		else {
			kept.push_back(std::move(entry));
		}
	}
	if (pruned) {
		_entries = std::move(kept);
		_index.clear();
		for (size_t i = 0; i < _entries.size(); i++) {
			_index[_entries[i].tuple.hash()] = i;
		}
	}
	return pruned;
}

const StateVector::Entry* StateVector::get(const RNS::Bytes& tuple_hash) const {
	auto it = _index.find(tuple_hash);
	if (it == _index.end()) {
		return nullptr;
	}
	return &_entries[it->second];
}

bool StateVector::is_active(const RNS::Bytes& tuple_hash) const {
	const Entry* entry = get(tuple_hash);
	return (entry != nullptr) && entry->active();
}

std::vector<const Tuple*> StateVector::active_tuples() const {
	std::vector<const Tuple*> tuples;
	for (const auto& entry : _entries) {
		if (entry.active()) {
			tuples.push_back(&entry.tuple);
		}
	}
	return tuples;
}

RNS::Bytes StateVector::to_payload() const {
	// §13.4: rows in insertion order; the Tuple Hash is recoverable from the
	// first five fields and is not stored.
	MsgPack::Packer p;
	p.packArraySize(_entries.size());
	for (const auto& entry : _entries) {
		const Tuple& t = entry.tuple;
		p.packArraySize(7);
		p.packBinary(t.relation_hash().data(), t.relation_hash().size());
		p.packArraySize(t.object_hashes().size());
		for (const auto& h : t.object_hashes()) {
			p.packBinary(h.data(), h.size());
		}
		p.pack(t.wildcard());
		p.packBinary(t.grantee().data(), t.grantee().size());
		p.packBinary(t.issuer().data(), t.issuer().size());
		if (entry.has_add) {
			p.pack(entry.add_ts);
		}
		else {
			p.packNil();
		}
		if (entry.has_remove) {
			p.pack(entry.remove_ts);
		}
		else {
			p.packNil();
		}
	}
	return RNS::Bytes(p.data(), p.size());
}

/*static*/ StateVector StateVector::from_payload(
	const RNS::Bytes& data, int deletion_horizon_days
) {
	WARNING(
		"StateVector::from_payload is trusted-local-only: it performs no "
		"signature verification and must not be fed network bytes. For "
		"network convergence use DeltaReceiver::apply_payloads instead."
	);

	MsgPack::Unpacker u;
	if (!data || !u.feed(data.data(), data.size()) || !u.isArray()) {
		throw std::invalid_argument("state vector payload must be a MessagePack array");
	}
	size_t row_count = u.unpackArraySize();

	StateVector state(deletion_horizon_days);
	for (size_t row = 0; row < row_count; row++) {
		if (!u.isArray()) {
			throw std::invalid_argument("each state entry must be a 7-element array");
		}
		if (u.unpackArraySize() != 7) {
			throw std::invalid_argument("each state entry must be a 7-element array");
		}
		RNS::Bytes relation_hash;
		RNS::Bytes grantee;
		RNS::Bytes issuer;
		bool wildcard = false;
		Vector<RNS::Bytes> object_hashes;
		bool has_add = false;
		bool has_remove = false;
		uint64_t add_ts = 0;
		uint64_t remove_ts = 0;

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
					throw std::invalid_argument("each object segment hash must be 16 bytes");
				}
				object_hashes.emplace_back(b.data(), b.size());
			}
		}
		if (!u.deserialize(wildcard)) {
			throw std::invalid_argument("wildcard must be a boolean");
		}
		{
			MsgPack::bin_t<uint8_t> b;
			if (!u.deserialize(b) || b.size() != HASH_SIZE) {
				throw std::invalid_argument("grantee must be a 16-byte binary blob");
			}
			grantee.assign(b.data(), b.size());
		}
		{
			MsgPack::bin_t<uint8_t> b;
			if (!u.deserialize(b) || b.size() != HASH_SIZE) {
				throw std::invalid_argument("issuer must be a 16-byte binary blob");
			}
			issuer.assign(b.data(), b.size());
		}
		{
			// add_ts: uint64 or nil
			if (u.isNil()) {
				u.unpackNil();
			}
			else if (!u.deserialize(add_ts)) {
				throw std::invalid_argument("timestamps must be uint64 or nil");
			}
			else {
				has_add = true;
			}
		}
		{
			// remove_ts: uint64 or nil
			if (u.isNil()) {
				u.unpackNil();
			}
			else if (!u.deserialize(remove_ts)) {
				throw std::invalid_argument("timestamps must be uint64 or nil");
			}
			else {
				has_remove = true;
			}
		}

		Entry entry;
		entry.tuple = Tuple(
			std::move(relation_hash), std::move(object_hashes), wildcard, std::move(grantee), std::move(issuer)
		);
		entry.has_add = has_add;
		entry.add_ts = add_ts;
		entry.has_remove = has_remove;
		entry.remove_ts = remove_ts;
		state._index[entry.tuple.hash()] = state._entries.size();
		state._entries.push_back(std::move(entry));
	}
	return state;
}
