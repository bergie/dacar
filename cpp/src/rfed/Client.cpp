/*
 * rfed — channel client implementation.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Client.h"

#include "microReticulum/Cryptography/Random.h"
#include "microReticulum/Log.h"
#include "microReticulum/Packet.h"
#include "microReticulum/Transport.h"
#include "microReticulum/Utilities/OS.h"

#include <MsgPack.h>

#include <stdexcept>

namespace RFed {

	// -- msgpack helpers (Python bytes wire parity) ---------------------------------

	namespace {

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
			// Not bin-wrapped (a peer that sent verbatim bytes).
			return payload;
		}

	} // namespace

	// -- signed channel payload -----------------------------------------------------

	RNS::Bytes signed_channel_payload(const RNS::Identity& identity, const RNS::Bytes& channel_hash) {
		// Python sends the list [channel_hash, pubkey, sig]; RNS umsgpack
		// embeds it as a msgpack array of three bin values in the request
		// envelope — pack exactly that shape here.
		const RNS::Bytes pubkey = identity.get_public_key();
		const RNS::Bytes sig = identity.sign(channel_hash);
		MsgPack::Packer p;
		p.packArraySize(3);
		p.packBinary(channel_hash.data(), channel_hash.size());
		p.packBinary(pubkey.data(), pubkey.size());
		p.packBinary(sig.data(), sig.size());
		return RNS::Bytes(p.data(), p.size());
	}

	SubscribeResult decode_subscribe_response(const RNS::Bytes& response) {
		SubscribeResult result;
		if (!response) {
			return result;
		}
		MsgPack::Unpacker u;
		if (!u.feed(response.data(), response.size())) {
			return result;
		}
		if (u.isBool()) {
			// Legacy node: a bare boolean, no advertised stamp cost.
			result.ok = u.unpackBool();
			return result;
		}
		if (u.isArray()) {
			const size_t count = u.unpackArraySize();
			if (count >= 1 && u.isBool()) {
				result.ok = u.unpackBool();
			}
			if (result.ok && count >= 2) {
				if (u.isNil()) {
					u.unpackNil(); // stamping disabled
				}
				else if (u.isUInt()) {
					// Generic deserialize: covers fixint through uint64.
					uint64_t cost = 0;
					if (u.deserialize(cost) && cost > 0) {
						result.has_stamp_cost = true;
						result.stamp_cost = (size_t)cost;
					}
				}
				else {
					// Unknown cost encoding — treat as disabled.
				}
			}
		}
		return result;
	}

	// -- single-flight request bookkeeping ----------------------------------------------

	namespace {

		/*
		The Link request callbacks are plain function pointers; the
		single-threaded pump model means at most one client flow is in
		flight per process (mirrors RnsChallenge).
		*/
		volatile bool _request_done = false;
		volatile bool _request_ok = false;
		RNS::Bytes _request_response;

		void on_request_response(const RNS::RequestReceipt& receipt) {
			_request_response = const_cast<RNS::RequestReceipt&>(receipt).get_response();
			_request_ok = true;
			_request_done = true;
		}

		void on_request_failed(const RNS::RequestReceipt& receipt) {
			(void)receipt;
			_request_ok = false;
			_request_done = true;
		}

		volatile bool _link_established = false;

		void on_link_established(RNS::Link& link) {
			(void)link;
			_link_established = true;
		}

		/*
		The inbound fanout packet callback is also a plain function pointer,
		so the process-wide client dispatches it (one client per node —
		the MCU deployment model). The trampoline itself is the friend
		declared on RFedClient (external linkage — not in this anonymous
		namespace).
		*/
		RFedClient* _active_client = nullptr;

	} // namespace

	void rfed_packet_trampoline(const RNS::Bytes& data, const RNS::Packet& packet) {
		(void)packet;
		if (_active_client != nullptr) {
			_active_client->_handle_fanout(data);
		}
	}

	// -- client -----------------------------------------------------------------------------

	RFedClient::RFedClient(RNS::Identity& identity, RNS::Reticulum& reticulum)
		: _identity(identity), _reticulum(reticulum), _delivery_destination(RNS::Type::NONE) {
		_active_client = this;
	}

	RFedClient::~RFedClient() {
		if (_active_client == this) {
			_active_client = nullptr;
		}
	}

	const Channel& RFedClient::channel(const std::string& name) {
		auto found = _channels.find(name);
		if (found != _channels.end()) {
			return found->second;
		}
		const Channel derived = derive_channel(name);
		found = _channels.emplace(name, derived).first;
		return found->second;
	}

	bool RFedClient::stamp_cost(const std::string& name, size_t& out_cost) const {
		const auto entry = _channels.find(name);
		if (entry == _channels.end()) {
			return false;
		}
		const std::string key = entry->second.channel_hash.toHex();
		const auto has = _has_stamp_cost.find(key);
		if (has == _has_stamp_cost.end() || !has->second) {
			return false;
		}
		out_cost = _stamp_costs.at(key);
		return true;
	}

	RNS::Link RFedClient::_establish_link(const RNS::Destination& destination, double timeout) {
		// A LINKREQUEST to a destination with no known route is broadcast and
		// silently dropped by multi-hop peers, so settle the path first:
		// send a path? request and pump until the node's path-response
		// announce populates the path table (rngit await_path pattern).
		if (!RNS::Transport::has_path(destination.hash())) {
			RNS::Transport::request_path(destination.hash());
			const double path_deadline = RNS::Utilities::OS::time() + DEFAULT_PATH_TIMEOUT;
			while (!RNS::Transport::has_path(destination.hash())) {
				_reticulum.loop();
				if (RNS::Utilities::OS::time() > path_deadline) {
					throw std::runtime_error(
						"no path to " + destination.hash().toHex() +
						" could be resolved (is the rfed node announcing and reachable?)"
					);
				}
				RNS::Utilities::OS::sleep(0.02);
			}
		}
		_link_established = false;
		RNS::Link link(destination, on_link_established);
		const double deadline = RNS::Utilities::OS::time() + timeout;
		while (!_link_established) {
			_reticulum.loop();
			if (RNS::Utilities::OS::time() > deadline) {
				if (link && link.status() != RNS::Type::Link::CLOSED) {
					link.teardown();
				}
				throw std::runtime_error(
					"rfed link to " + destination.hash().toHex() + " not established"
				);
			}
			RNS::Utilities::OS::sleep(0.02);
		}
		return link;
	}

	RNS::Bytes RFedClient::_request(
		RNS::Link& link,
		const char* path,
		const RNS::Bytes& data,
		double timeout
	) {
		if (!link || link.status() != RNS::Type::Link::ACTIVE) {
			return RNS::Bytes();
		}
		_request_response.clear();
		_request_done = false;
		_request_ok = false;
		const RNS::RequestReceipt receipt = link.request(
			RNS::Bytes(path),
			data,
			on_request_response,
			on_request_failed,
			nullptr,
			timeout
		);
		if (!receipt) {
			return RNS::Bytes(); // could not send
		}
		const double deadline = RNS::Utilities::OS::time() + timeout + DEFAULT_TIMEOUT_GRACE;
		while (!_request_done) {
			_reticulum.loop();
			if (RNS::Utilities::OS::time() > deadline) {
				return RNS::Bytes(); // timed out
			}
			RNS::Utilities::OS::sleep(0.02);
		}
		if (!_request_ok) {
			return RNS::Bytes();
		}
		return _request_response;
	}

	SubscribeResult RFedClient::subscribe(
		const RNS::Bytes& node_hash,
		const std::string& channel_name,
		double timeout
	) {
		const Channel& entry = channel(channel_name);
		const RNS::Identity node_identity = RNS::Identity::recall(node_hash);
		if (!node_identity) {
			throw std::runtime_error(
				"rfed node identity unknown for " + node_hash.toHex() + "; wait for its announce"
			);
		}
		// The node announces every rfed.* destination under one shared
		// identity: build the OUT subscribe destination from it.
		const RNS::Destination destination(
			node_identity, RNS::Type::Destination::OUT, RNS::Type::Destination::SINGLE,
			"rfed", "channel.subscribe"
		);
		RNS::Link link = _establish_link(destination, DEFAULT_ESTABLISH_TIMEOUT);
		link.identify(_identity);
		const RNS::Bytes response = _request(
			link, SUBSCRIBE_PATH, signed_channel_payload(_identity, entry.channel_hash), timeout
		);
		const SubscribeResult decoded = decode_subscribe_response(response);
		if (decoded.ok) {
			const std::string key = entry.channel_hash.toHex();
			_has_stamp_cost[key] = decoded.has_stamp_cost;
			_stamp_costs[key] = decoded.stamp_cost;
		}
		return decoded;
	}

	SubscribeResult RFedClient::unsubscribe(
		const RNS::Bytes& node_hash,
		const std::string& channel_name,
		double timeout
	) {
		const Channel& entry = channel(channel_name);
		const RNS::Identity node_identity = RNS::Identity::recall(node_hash);
		if (!node_identity) {
			throw std::runtime_error(
				"rfed node identity unknown for " + node_hash.toHex() + "; wait for its announce"
			);
		}
		const RNS::Destination destination(
			node_identity, RNS::Type::Destination::OUT, RNS::Type::Destination::SINGLE,
			"rfed", "channel.unsubscribe"
		);
		RNS::Link link = _establish_link(destination, DEFAULT_ESTABLISH_TIMEOUT);
		link.identify(_identity);
		const RNS::Bytes response = _request(
			link, UNSUBSCRIBE_PATH, signed_channel_payload(_identity, entry.channel_hash), timeout
		);
		return decode_subscribe_response(response);
	}

	bool RFedClient::send_publish(const RNS::Bytes& node_hash, const RNS::Bytes& rfed_payload) {
		if (rfed_payload.size() > PUBLISH_DATA_MAX) {
			ERRORF(
				"rfed publish payload %u bytes exceeds the %u-byte single-packet MDU "
				"(the Resource-over-link path is not part of this port)",
				rfed_payload.size(), PUBLISH_DATA_MAX
			);
			return false;
		}
		const RNS::Identity node_identity = RNS::Identity::recall(node_hash);
		if (!node_identity) {
			throw std::runtime_error(
				"rfed node identity unknown for " + node_hash.toHex() + "; wait for its announce"
			);
		}
		const RNS::Destination destination(
			node_identity, RNS::Type::Destination::OUT, RNS::Type::Destination::SINGLE,
			"rfed", "channel.publish"
		);
		if (!RNS::Transport::has_path(destination.hash())) {
			RNS::Transport::request_path(destination.hash());
			const double deadline = RNS::Utilities::OS::time() + DEFAULT_PATH_TIMEOUT;
			while (!RNS::Transport::has_path(destination.hash())) {
				_reticulum.loop();
				if (RNS::Utilities::OS::time() > deadline) {
					return false; // no route -> publish dropped
				}
				RNS::Utilities::OS::sleep(0.02);
			}
		}
		RNS::Packet packet(destination, rfed_payload);
		const RNS::PacketReceipt receipt = packet.receipt_send();
		return (bool)receipt;
	}

	PullPage RFedClient::pull(
		const RNS::Bytes& node_hash,
		const std::string& channel_name,
		double timeout,
		bool* ok,
		int* error_code
	) {
		PullPage page;
		if (ok != nullptr) *ok = false;
		if (error_code != nullptr) *error_code = -1;
		const Channel& entry = channel(channel_name);
		const RNS::Identity node_identity = RNS::Identity::recall(node_hash);
		if (!node_identity) {
			throw std::runtime_error(
				"rfed node identity unknown for " + node_hash.toHex() + "; wait for its announce"
			);
		}
		const RNS::Destination destination(
			node_identity, RNS::Type::Destination::OUT, RNS::Type::Destination::SINGLE,
			"rfed", "channel.pull"
		);
		RNS::Link link = _establish_link(destination, DEFAULT_ESTABLISH_TIMEOUT);
		link.identify(_identity);
		// Python sends raw request data (bytes) — umsgpack encodes it as bin.
		const RNS::Bytes response = _request(
			link, PULL_PATH, bin_wrap(entry.channel_hash), timeout
		);
		if (!response) {
			return page;
		}
		MsgPack::Unpacker u;
		if (!u.feed(response.data(), response.size())) {
			return page;
		}
		// A numeric response >= 0xF0 is a node error code (0xF0
		// ERROR_NO_IDENTITY — the link was not authenticated; 0xF4
		// ERROR_INVALID_DATA — malformed request).
		if (u.isUInt()) {
			// Generic deserialize: covers fixint through uint64.
			uint64_t code = 0;
			if (u.deserialize(code) && error_code != nullptr) {
				*error_code = (int)code;
			}
			return page;
		}
		if (!u.isArray()) {
			return page;
		}
		const size_t outer = u.unpackArraySize();
		if (outer < 2) {
			return page;
		}
		if (ok != nullptr) *ok = true;
		if (u.isArray()) {
			const size_t pairs = u.unpackArraySize();
			for (size_t i = 0; i < pairs; i++) {
				if (!u.isArray()) {
					continue; // skip malformed pairs defensively
				}
				const size_t fields = u.unpackArraySize();
				if (fields < 2) {
					continue;
				}
				MsgPack::bin_t<uint8_t> channel_hash;
				MsgPack::bin_t<uint8_t> blob;
				if (u.deserialize(channel_hash) && u.deserialize(blob)) {
					PullItem item;
					item.channel_hash = RNS::Bytes(channel_hash.data(), channel_hash.size());
					item.blob = RNS::Bytes(blob.data(), blob.size());
					page.items.push_back(item);
				}
			}
		}
		if (u.isBool()) {
			page.more_pending = u.unpackBool();
		}
		return page;
	}

	RNS::Bytes RFedClient::listen_raw(FanoutCallback on_fanout) {
		if (!_delivery_destination) {
			_delivery_destination = RNS::Destination(
				_identity, RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE,
				"rfed", "delivery"
			);
			_delivery_destination.set_packet_callback(rfed_packet_trampoline);
		}
		_fanout_callback = on_fanout;
		_delivery_destination.announce();
		return _delivery_destination.hash();
	}

	void RFedClient::_handle_fanout(const RNS::Bytes& data) {
		// A foreign/unparsable fanout packet, or one for a channel this
		// client is not subscribed to, is dropped — not fatal.
		try {
			const FanoutPayload parsed = parse_fanout_payload(data);
			const std::string needle = parsed.channel_hash.toHex();
			for (const auto& [name, entry] : _channels) {
				if (entry.channel_hash.toHex() == needle) {
					if (_fanout_callback) {
						_fanout_callback(name, entry.identity, parsed.inner_blob);
					}
					return;
				}
			}
		}
		catch (const std::exception&) {
			// dropped
		}
	}

}
