/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "RnsChallenge.h"

#include "Naming.h"

#include <MsgPack.h>

#include <stdexcept>

namespace Dacar {

	// -- msgpack bin wrap/unwrap (Python bytes wire parity) ---------------------------

	RNS::Bytes bin_wrap(const RNS::Bytes& payload) {
		MsgPack::Packer p;
		p.packBinary(payload.data(), payload.size());
		return RNS::Bytes(p.data(), p.size());
	}

	RNS::Bytes bin_unwrap(const RNS::Bytes& payload) {
		if (!payload) {
			return payload;
		}
		MsgPack::Unpacker u;
		if (u.feed(payload.data(), payload.size()) && u.isBin()) {
			MsgPack::bin_t<uint8_t> bin;
			if (u.deserialize(bin)) {
				return RNS::Bytes(bin.data(), bin.size());
			}
		}
		// Not bin-wrapped (a C++ peer that sent verbatim bytes).
		return payload;
	}

	// -- server ------------------------------------------------------------------

	namespace {

		/*
		The process-wide authority. Response generators are plain function
		pointers without capture context; one Dacar authority per node
		matches the MCU deployment model.
		*/
		AuthoritativeServer* _challenge_authority = nullptr;

		RNS::Bytes challenge_response_generator(
			const RNS::Bytes& path,
			const RNS::Bytes& data,
			const RNS::Bytes& request_id,
			const RNS::Bytes& link_id,
			const RNS::Identity& remote_identity,
			double requested_at
		) {
			(void)path;
			(void)request_id;
			(void)link_id;
			(void)requested_at;
			if (_challenge_authority == nullptr) {
				return RNS::Bytes();
			}
			// Python clients send the challenge as a msgpack `bin` value.
			const RNS::Bytes payload = bin_unwrap(data);
			if (!payload) {
				return RNS::Bytes();
			}
			try {
				// The verified requester identity is the enforcement-seam
				// context (its hash is the Dacar Grantee for policy checks).
				const RNS::Bytes grantee = remote_identity ? remote_identity.hash() : RNS::Bytes();
				DEBUGF("challenge from grantee %s (%u bytes)", grantee.toHex().c_str(), payload.size());
				const RNS::Bytes receipt = _challenge_authority->handle(payload);
				// Python clients umsgpack-decode the response: wrap as bin.
				return bin_wrap(receipt);
			}
			catch (const std::exception&) {
				return RNS::Bytes(); // malformed challenge -> no response -> client DENY
			}
		}

	} // namespace

	RnsChallengeServer::RnsChallengeServer(
		RNS::Identity& identity,
		AuthoritativeServer& server,
		bool announce,
		RNS::Type::Destination::request_policies allow
	)
		: _destination(
			identity,
			RNS::Type::Destination::IN,
			RNS::Type::Destination::SINGLE,
			APP_NAME,
			DACAR_CHALLENGE_ASPECTS
		)
	{
		_challenge_authority = &server;
		_destination.accepts_links(true);
		_destination.register_request_handler(
			RNS::Bytes(CHALLENGE_REQUEST_PATH),
			challenge_response_generator,
			allow
		);
		if (announce) {
			_destination.announce();
		}
	}

	RnsChallengeServer::~RnsChallengeServer() {
		_challenge_authority = nullptr;
	}

	void RnsChallengeServer::announce(const RNS::Bytes& app_data) {
		_destination.announce(app_data);
	}

	// -- client --------------------------------------------------------------------

	namespace {

		/*
		Single-flight client bookkeeping. The Link request callbacks are
		plain function pointers; the single-threaded pump model means at
		most one challenge flow is in flight per process.
		*/
		volatile bool _request_done = false;
		volatile bool _request_ok = false;
		RNS::Bytes _request_response;

		void on_challenge_response(const RNS::RequestReceipt& receipt) {
			_request_response = const_cast<RNS::RequestReceipt&>(receipt).get_response();
			_request_ok = true;
			_request_done = true;
		}

		void on_challenge_failed(const RNS::RequestReceipt& receipt) {
			(void)receipt;
			_request_ok = false;
			_request_done = true;
		}

	} // namespace

	RNS::Bytes RnsLinkTransport::operator () (const RNS::Bytes& challenge_payload) const {
		if (!_link || _link.status() != RNS::Type::Link::ACTIVE) {
			return RNS::Bytes(); // link not ready -> partition -> DENY (§8)
		}
		_request_response.clear();
		_request_done = false;
		_request_ok = false;

		// Python servers umsgpack-decode the request payload: wrap as bin.
		const RNS::Bytes wrapped = bin_wrap(challenge_payload);
		const RNS::RequestReceipt receipt = const_cast<RNS::Link&>(_link).request(
			RNS::Bytes(CHALLENGE_REQUEST_PATH),
			wrapped,
			on_challenge_response,
			on_challenge_failed,
			nullptr,
			_timeout
		);
		if (!receipt) {
			return RNS::Bytes(); // could not send -> DENY
		}
		const double deadline = RNS::Utilities::OS::time() + _timeout + _grace;
		while (!_request_done) {
			_reticulum.loop();
			if (RNS::Utilities::OS::time() > deadline) {
				return RNS::Bytes(); // timed out -> partition -> DENY (§8)
			}
			RNS::Utilities::OS::sleep(0.02);
		}
		if (!_request_ok || !_request_response) {
			return RNS::Bytes(); // request failed -> DENY
		}
		return bin_unwrap(_request_response);
	}

	// -- link establishment (§8.2) -----------------------------------------------------

	namespace {

		volatile bool _link_established = false;

		void on_link_established(RNS::Link& link) {
			(void)link;
			_link_established = true;
		}

	} // namespace

	RNS::Link establish_challenge_link(
		RNS::Reticulum& reticulum,
		const RNS::Destination& destination,
		double timeout
	) {
		_link_established = false;
		RNS::Link link(destination, on_link_established);
		const double deadline = RNS::Utilities::OS::time() + timeout;
		while (!_link_established) {
			reticulum.loop();
			if (RNS::Utilities::OS::time() > deadline) {
				if (link && link.status() != RNS::Type::Link::CLOSED) {
					link.teardown();
				}
				return RNS::Link(RNS::Type::NONE); // partition -> §8 DENY
			}
			RNS::Utilities::OS::sleep(0.02);
		}
		return link;
	}

}
