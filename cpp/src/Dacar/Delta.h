/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Transport-agnostic Delta receive boundary (spec §11.2.4).
 *
 * Every transport — RFed (§11.1), LXMF store-and-forward (§11.2), and optical
 * Paper Messages (§11.3) — funnels incoming bytes through one identical path:
 * decode the §5.3 Operation payload, authenticate it via verify-on-ingest
 * (§5.2 / §11.2.4), and merge it into the CRDT. DeltaReceiver is that shared
 * boundary. Malformed or unauthenticated Deltas are dropped silently rather
 * than propagated into state or crashing a transport callback.
 *
 * This keeps the (optional) transport adapters thin: an adapter only has to
 * hand received bytes to DeltaReceiver::apply_payload, regardless of whether
 * they arrived over RFed, LXMF, or a scanned QR code.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Crdt.h"

#include <vector>

namespace Dacar {

	class DeltaReceiver {

	public:
		/*
		Bound to one StateVector and a KeyResolver; every transport adapter
		shares a single instance so the receive policy (graceful
		malformed-drop, verify-on-ingest) lives in one place.
		*/
		DeltaReceiver(StateVector& state, KeyResolver key_resolver)
			: _state(state), _resolver(std::move(key_resolver))
		{}
		~DeltaReceiver() = default;

		/*
		Apply one wire-format Delta.

		Returns true iff the payload decoded, authenticated, and was applied
		to the CRDT. Malformed payloads are swallowed (return false) — a
		transport callback must never crash on arbitrary bytes. Signature and
		CRDT-level rejection (unknown Issuer, bad sig, stale/future) is
		delegated to StateVector::ingest.

		Pass now_ms = -1 to use the current wall clock; max_future_ms = -1
		disables the §12 future-skew check.
		*/
		bool apply_payload(
			const RNS::Bytes& payload,
			int64_t now_ms = -1,
			int64_t max_future_ms = DEFAULT_MAX_FUTURE_MS
		);

		/*
		Authenticate and apply a *batch* of Deltas (§11.1, §11.2.4).

		The secure alternative to StateVector::merge() for network sync.
		`payload` is a MessagePack array of §5.3 Operation payloads; each
		element is decoded and run through apply_payload, i.e. it is
		independently Ed25519/threshold-authenticated before it may touch
		state. A single forged, stale (§9), or future-skewed (§12) element is
		dropped without affecting the rest of the batch.

		Returns the number of Deltas authenticated AND applied. A malformed
		outer payload (not a MessagePack array, undecodable) yields 0 and is
		swallowed, so a transport callback can never crash on arbitrary
		bytes — exactly like apply_payload.

		WARNING: this is the *only* safe entry point for full-state / bulk
		convergence received over the network. StateVector::merge() /
		StateVector::from_payload() are trusted-local snapshot primitives
		that perform no signature verification and must not be fed network
		bytes.
		*/
		size_t apply_payloads(
			const RNS::Bytes& payload,
			int64_t now_ms = -1,
			int64_t max_future_ms = DEFAULT_MAX_FUTURE_MS
		);

		/*
		Encode a list of §5.3 Operation payloads as a batch (§11.1): a
		MessagePack array of already-signed payload byte-strings, suitable
		for publishing as one bulk sync message. Inverse of apply_payloads.
		*/
		static RNS::Bytes pack_payloads(const Vector<RNS::Bytes>& operation_payloads);

	private:
		StateVector& _state;
		KeyResolver _resolver;

	};

}
