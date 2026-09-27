/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * §8 Strict Consistency Challenge over real RNS Links.
 *
 * Optional microReticulum-dependent transport wiring around the pure,
 * fixture-tested §8 logic in Challenge.h:
 *
 *   - RnsChallengeServer exposes an Authoritative Identity on the
 *     `dacar.auth.v1` destination (App Name `dacar`, Aspects `auth`, `v1`),
 *     accepts Links, and answers Challenge requests with signed Freshness
 *     Receipts. Firmware gates its own actions the same way the reference
 *     use case does: extract the verified `remote_identity` hash from the
 *     Link request, run `Engine::evaluate`/`evaluate_hashes` locally, and
 *     act on the verdict (e.g. drive the buzzer GPIO on ALLOW).
 *   - RnsLinkTransport is the client-side ChallengeTransport: it sends the
 *     challenge payload over an established Link and pumps the Reticulum
 *     loop until the signed receipt arrives — returning empty Bytes on
 *     timeout/failure, which ChallengeClient treats as partition -> DENY.
 *   - establish_challenge_link opens a Link and pumps until ACTIVE.
 *
 * Wire compatibility with the Python implementation: microReticulum passes
 * request/response payloads verbatim inside its `[id, payload]` envelopes,
 * while Python RNS umsgpack-encodes `bytes` values as msgpack `bin`. Both
 * sides therefore bin-wrap the application payload before send and unwrap
 * on receive, so C++ peers interop with Python peers unchanged.
 *
 * Response generators are plain function pointers without capture context,
 * so the server registers itself as the process-wide authority — one Dacar
 * authority per node, matching the MCU deployment model.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Challenge.h"

#include "microReticulum/Destination.h"
#include "microReticulum/Link.h"
#include "microReticulum/Reticulum.h"

namespace Dacar {

	// The RNS request path used for the Challenge exchange.
	constexpr const char* CHALLENGE_REQUEST_PATH = "challenge";

	// Default Challenge round-trip timeout in seconds (partition -> §8 DENY).
	constexpr double DEFAULT_CHALLENGE_TIMEOUT = 15.0;

	// Extra slack beyond the RNS request timeout before the client gives up.
	constexpr double DEFAULT_TIMEOUT_GRACE = 2.0;

	// Default Link establishment timeout in seconds.
	constexpr double DEFAULT_ESTABLISH_TIMEOUT = 15.0;

	// The `auth.v1` aspects of the challenge destination, dot-joined (the
	// microReticulum Destination ctor takes one aspects string).
	constexpr const char* DACAR_CHALLENGE_ASPECTS = "auth.v1";

	/*
	Wrap a raw application payload as a msgpack `bin` value (Python `bytes`
	wire parity — see the header note).
	*/
	RNS::Bytes bin_wrap(const RNS::Bytes& payload);

	/*
	Unwrap a msgpack `bin`-wrapped payload. Returns the payload unchanged
	when it is not bin-wrapped (a C++ peer that sent verbatim bytes).
	*/
	RNS::Bytes bin_unwrap(const RNS::Bytes& payload);

	/*
	Authoritative endpoint: answers Challenge requests over RNS Links (§8).

	Creates the `dacar.auth.v1` destination for `identity`, enables Link
	acceptance, registers the Challenge request handler, and (by default)
	announces so clients can find it. A running RNS::Reticulum is assumed.

	Only one server may exist per process (see the header note); constructing
	a second replaces the registered authority.
	*/
	class RnsChallengeServer {

	public:
		RnsChallengeServer(
			RNS::Identity& identity,
			AuthoritativeServer& server,
			bool announce = true,
			RNS::Type::Destination::request_policies allow = RNS::Type::Destination::ALLOW_ALL
		);
		~RnsChallengeServer();

		RnsChallengeServer(const RnsChallengeServer&) = delete;
		RnsChallengeServer& operator = (const RnsChallengeServer&) = delete;

		RNS::Destination& destination() { return _destination; }
		RNS::Bytes destination_hash() const { return _destination.hash(); }

		// (Re)announce the destination so clients can resolve a path to it.
		void announce(const RNS::Bytes& app_data = RNS::Bytes());

	private:
		RNS::Destination _destination;

	};

	/*
	Client-side transport over an established Link: issues the Challenge
	request and pumps `reticulum.loop()` until the signed receipt arrives
	(or timeout). Returns empty Bytes on any failure — the §8 partition
	penalty (DENY).

	Single-flight per transport instance: the response bookkeeping is
	instance state, so do not share one transport across concurrent flows
	(the single-threaded pump model makes this a non-issue on MCU).
	*/
	class RnsLinkTransport {

	public:
		/*
		The Link is held by value (a shared handle): the transport keeps the
		link's underlying state referenced for the duration of the exchange
		even if the caller's own handle goes out of scope or the stack
		cleans up its tracking copies.
		*/
		RnsLinkTransport(
			const RNS::Link& link,
			RNS::Reticulum& reticulum,
			double timeout = DEFAULT_CHALLENGE_TIMEOUT,
			double grace = DEFAULT_TIMEOUT_GRACE
		)
			: _link(link), _reticulum(reticulum), _timeout(timeout), _grace(grace)
		{}

		RNS::Bytes operator () (const RNS::Bytes& challenge_payload) const;

	private:
		RNS::Link _link;
		RNS::Reticulum& _reticulum;
		double _timeout;
		double _grace;

	};

	/*
	Open an RNS Link to `destination` and pump until ACTIVE (§8.2). Returns
	the active Link, or an invalid Link ({Type::NONE}) if it could not be
	established within `timeout` (partition -> §8 DENY).

	The destination's path must already be known (announce received); use
	RNS::Transport::has_path / request_path to settle discovery first.
	*/
	RNS::Link establish_challenge_link(
		RNS::Reticulum& reticulum,
		const RNS::Destination& destination,
		double timeout = DEFAULT_ESTABLISH_TIMEOUT
	);

}
