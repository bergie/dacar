/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * The authorization state: an LWW-Element-Set CRDT (spec §6).
 *
 * The global state maps a Tuple Hash to an HLC timestamp, split into an Add
 * set and a Remove set (classic LWW-Element-Set). A Tuple is *active* iff it
 * has an Add timestamp strictly greater than its Remove timestamp; ties
 * resolve to removed (Remove wins, §6.1).
 *
 * Storage is bounded by Time-Horizon Tombstone Pruning (§9): once a tuple has
 * resolved inactive *and* both its Add and Remove timestamps are older than
 * the deletion horizon, both entries are silently deleted. Incoming
 * Operations older than the horizon are rejected outright (intake rejection,
 * §9).
 *
 * Snapshot serialization (to_payload / from_payload) is TRUSTED-LOCAL-ONLY:
 * it carries no Ed25519 signature material and must never be fed network
 * bytes (see the warnings on each method). Network convergence runs every
 * signed Operation through ingest() or DeltaReceiver::apply_payloads().
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Config.h"
#include "Operation.h"
#include "Verifier.h"

#include <map>
#include <vector>

namespace Dacar {

	// Operations further than this into the future are rejected (§12).
	constexpr int64_t DEFAULT_MAX_FUTURE_MS = 24LL * 60LL * 60LL * 1000LL;

	class StateVector {

	public:
		/*
		An LWW-Element-Set entry: one Tuple with separate add/remove clocks.
		`has_add` / `has_remove` distinguish "no entry in that set" from a
		stored timestamp of zero.
		*/
		struct Entry {
			Tuple tuple;
			bool has_add = false;
			uint64_t add_ts = 0;
			bool has_remove = false;
			uint64_t remove_ts = 0;

			bool active() const {
				return has_add && (!has_remove || add_ts > remove_ts);
			}
		};

		explicit StateVector(int deletion_horizon_days = DEFAULT_DELETION_HORIZON_DAYS)
			: _deletion_horizon_days(deletion_horizon_days)
		{}
		~StateVector() = default;

		size_t size() const { return _entries.size(); }
		bool contains(const RNS::Bytes& tuple_hash) const {
			return _index.find(tuple_hash) != _index.end();
		}

		int deletion_horizon_days() const { return _deletion_horizon_days; }
		uint64_t deletion_horizon_ms() const {
			return (uint64_t)_deletion_horizon_days * 24ULL * 60ULL * 60ULL * 1000ULL;
		}

		/*
		Authenticate then apply a network-received Delta (§11.2.4, §5.2).

		This is the secure entry point for Operations received over any
	 transport (RFed, LXMF, optical sneakernet). The Operation's Ed25519
		signature(s) MUST verify against the public key(s) resolved for its
		claimed Issuer before the pure CRDT update (apply) is allowed to
		mutate state. Any authentication failure — unknown Issuer, bad
		signature, wrong threshold — drops the Operation (returns false).

		Returns true iff authenticated AND applied.

		Pass now_ms = -1 to use the current wall clock; max_future_ms = -1
		disables the §12 future-skew check.
		*/
		bool ingest(
			const Operation& operation,
			const KeyResolver& key_resolver,
			int64_t now_ms = -1,
			int64_t max_future_ms = DEFAULT_MAX_FUTURE_MS
		);

		/*
		Apply one Operation (Delta) to the appropriate set.

		Returns true if applied, false if rejected. An Operation is rejected
		when it projects too far into the future (§12) or is older than the
		deletion horizon (§9 intake rejection). The Operation's signature(s)
		are assumed already verified by the caller; this method performs the
		pure CRDT update.
		*/
		bool apply(
			const Operation& operation,
			int64_t now_ms = -1,
			int64_t max_future_ms = DEFAULT_MAX_FUTURE_MS
		);

		/*
		Merge another StateVector by taking the max HLC per set per tuple.

		WARNING: trusted-local-only — never feed network state. merge() trusts
		its argument completely and performs no signature verification, so it
		can inject or alter authorization state for any tuple. It also skips
		the §9 stale-horizon and §12 future-skew intake checks that apply() /
		ingest() enforce per-delta. Legitimate uses are confined to a node's
		own trusted state: CRDT unit testing and restoring a snapshot
		previously produced by to_payload() on the same node.
		*/
		void merge(const StateVector& other);

		/*
		Run Time-Horizon Tombstone Pruning (§9).

		Deletes BOTH the Add and Remove entries for any tuple that currently
		resolves to inactive AND whose Add and Remove timestamps are both
		older than the deletion horizon. Returns the number of tuples pruned.
		Pruning never alters the resolved access state or destroys active
		re-grants.
		*/
		size_t prune(int64_t now_ms = -1);

		// -- queries -----------------------------------------------------------
		const Entry* get(const RNS::Bytes& tuple_hash) const;
		bool is_active(const RNS::Bytes& tuple_hash) const;

		// Every currently active Tuple (pointers remain valid until the next
		// mutating call), in insertion order.
		std::vector<const Tuple*> active_tuples() const;

		// Every stored entry — including resolved (revoked) tombstones — in
		// insertion order. Unlike active_tuples() this also exposes revoked
		// tuples and their timestamps (management/inspection use).
		const Vector<Entry>& entries() const { return _entries; }

		// -- state-vector serialization (§13.4, trusted-local-only) -----------
		/*
		Serialize the full state vector as a MessagePack array of rows, one
		per Tuple, in insertion order. Each row is a 7-element array:

		  [relation_hash(16), [object_hashes], wildcard_bool, grantee(16),
		   issuer(16), add_ts | nil, remove_ts | nil]

		WARNING: trusted-local-only. The payload is an unauthenticated dump of
		this node's CRDT and carries no Ed25519 signature material; it exists
		for a node to snapshot its own state. It MUST NOT be accepted from the
		network — feed received bytes through DeltaReceiver::apply_payloads
		(signed §5.3 Operations) instead.
		*/
		RNS::Bytes to_payload() const;

		/*
		Deserialize a state vector produced by to_payload().

		WARNING: trusted-local-only — never feed network bytes (see
		to_payload). A log warning marks the contract, mirroring the Python
		implementation's TrustedLocalOnlyWarning.
		*/
		static StateVector from_payload(
			const RNS::Bytes& data,
			int deletion_horizon_days = DEFAULT_DELETION_HORIZON_DAYS
		);

	private:
		Entry& entry_for(const Tuple& tuple);

		// Insertion-ordered entries (Python dict parity: iteration, snapshots
		// and merges all observe insertion order) plus a hash -> position
		// index for O(log n) lookups. Tuple Hashes are not stored per entry;
		// they are recovered on demand.
		Vector<Entry> _entries;
		Map<RNS::Bytes, size_t> _index;
		int _deletion_horizon_days;

	};

}
