/*
 * rfed — channel client: subscribe, publish, receive, and pull against a
 * rfed federation node.
 *
 * Speaks the modern split rfed destinations (RFed/SPEC.md §2), all sharing
 * the node's single identity:
 *
 *   - `rfed.channel.subscribe`   — /rfed/subscribe request (caches stamp cost)
 *   - `rfed.channel.unsubscribe` — /rfed/unsubscribe request
 *   - `rfed.channel.publish`     — fire-and-forget publish (single DATA packet)
 *   - `rfed.channel.pull`        — /rfed/pull paging (caller-identified)
 *
 * Delivery arrives on the client's own inbound `rfed.delivery` destination as
 * a fanout payload `[ channel_hash(16) ‖ inner_blob ]`, split via
 * parse_fanout_payload and dispatched raw — the application performs the
 * channel-specific decrypt/decode (e.g. Dacar's §11.1.1 compact Delta format).
 * The generic LXMF-tail decode path is not part of this port yet (see Blob.h).
 *
 * RNS-transport-dependent: needs a running RNS::Reticulum. Construction is
 * offline-safe — destinations are created lazily inside each method.
 *
 * Threading model: microReticulum's callbacks are plain function pointers and
 * the MCU deployment pumps the stack from one thread (reticulum.loop()), so
 * request/link bookkeeping is single-flight process-wide state — do not run
 * concurrent client flows (matches the RnsChallenge transport model).
 *
 * Wire parity: Python clients umsgpack-encode `bytes` request values as
 * msgpack `bin`, and the node umsgpack-encodes structured responses, so this
 * client bin-wraps raw-byte request payloads and packs/unpacks msgpack
 * structures itself.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Blob.h"
#include "Channel.h"
#include "Constants.h"
#include "Stamp.h"

#include "microReticulum/Link.h"
#include "microReticulum/Reticulum.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace RFed {

	// A /rfed/subscribe (or unsubscribe) response. A node that does not
	// require stamps replies with a nil cost; 0 and nil both mean stamping
	// is disabled (`has_stamp_cost == false`).
	struct SubscribeResult {
		bool ok = false;
		bool has_stamp_cost = false;
		size_t stamp_cost = 0;
	};

	// One deferred-queue blob entry from /rfed/pull.
	struct PullItem {
		RNS::Bytes channel_hash;
		RNS::Bytes blob;
	};

	// One page of a /rfed/pull response; repeat while more_pending to drain
	// the queue.
	struct PullPage {
		std::vector<PullItem> items;
		bool more_pending = false;
	};

	// Callback for raw fanout deliveries:
	// on_fanout(channel_name, channel_identity, inner_blob).
	using FanoutCallback =
		std::function<void(const std::string&, const RNS::Identity&, const RNS::Bytes&)>;

	/*
	Build the `[channel_hash, pubkey, sig]` subscribe payload: msgpack array
	of three bin values, the channel hash signed with the subscriber
	identity. Matches the Rust verify_signed_payload contract and the JS
	signedChannelPayload.
	*/
	RNS::Bytes signed_channel_payload(const RNS::Identity& identity, const RNS::Bytes& channel_hash);

	/*
	Decode a /rfed/subscribe (or unsubscribe) response. Wire form is msgpack
	`[bool ok, uint stamp_cost | nil]`; legacy nodes reply with a bare bool.
	*/
	SubscribeResult decode_subscribe_response(const RNS::Bytes& response);

	/*
	A rfed channel client. One client per process (see the threading-model
	note in the header docs).
	*/
	class RFedClient {

	public:
		RFedClient(RNS::Identity& identity, RNS::Reticulum& reticulum);
		~RFedClient();

		RFedClient(const RFedClient&) = delete;
		RFedClient& operator = (const RFedClient&) = delete;

		/*
		A channel's derived identity, channel hash, and delivery hash
		(cached by name).
		*/
		const Channel& channel(const std::string& name);

		/*
		The cached PoW stamp cost advertised by the node for `name`.
		Returns false when stamping is disabled (or subscribe has not been
		called for the channel this session).
		*/
		bool stamp_cost(const std::string& name, size_t& out_cost) const;

		/*
		Subscribe to a channel on a node and cache the advertised PoW stamp
		cost. Opens an identified link to the node's rfed.channel.subscribe
		destination and sends /rfed/subscribe with the signed channel hash.
		Re-subscribing refreshes the cached stamp cost — do this at least
		once per session and after any publish rejection.
		*/
		SubscribeResult subscribe(
			const RNS::Bytes& node_hash,
			const std::string& channel_name,
			double timeout = DEFAULT_REQUEST_TIMEOUT
		);

		/*
		Remove a subscription. Same payload shape as subscribe().
		*/
		SubscribeResult unsubscribe(
			const RNS::Bytes& node_hash,
			const std::string& channel_name,
			double timeout = DEFAULT_REQUEST_TIMEOUT
		);

		/*
		Fire-and-forget SEND of a pre-wrapped rfed_payload (the general
		publish primitive, independent of the inner format):
		`channel_hash ‖ inner_blob ‖ stamp`. Payloads up to
		PUBLISH_DATA_PACKET_MAX (the largest payload that fits one plain
		tokenized packet at the default 500 B MTU) go out as a single DATA
		packet. Anything larger is advertised as a Resource over a link
		to the publish destination — the node ingests both paths identically.

		SEND is fire-and-forget for the DATA path (returns transport
		acceptance); the Resource path waits for the transfer to conclude and
		returns the transfer status. Neither is confirmation that the node
		stored the blob — an under-stamped blob is silently dropped by the
		node. Call subscribe() again to refresh the stamp cost if publishes
		seem dropped.
		*/
		bool send_publish(const RNS::Bytes& node_hash, const RNS::Bytes& rfed_payload);

		/*
		Pull one page of pending blobs for a channel (user-initiated paging).
		Opens an identified link to rfed.channel.pull and sends /rfed/pull
		with the channel hash; repeat while more_pending is true. The node
		answers error codes >= 0xF0 as msgpack integers — those set ok=false
		and more_pending=false with the code in error_code.
		*/
		PullPage pull(
			const RNS::Bytes& node_hash,
			const std::string& channel_name,
			double timeout = DEFAULT_REQUEST_TIMEOUT,
			bool* ok = nullptr,
			int* error_code = nullptr
		);

		/*
		Start listening for live fanout deliveries on this client's
		`rfed.delivery` destination. Each incoming fanout payload is split,
		matched against the subscribed channels, and dispatched raw:
		on_fanout(channel_name, channel_identity, inner_blob). Returns the
		rfed.delivery destination hash.
		*/
		RNS::Bytes listen_raw(FanoutCallback on_fanout);

	private:
		RNS::Identity _identity;
		RNS::Reticulum& _reticulum;
		std::map<std::string, Channel> _channels;
		std::map<std::string, bool> _has_stamp_cost;
		std::map<std::string, size_t> _stamp_costs;
		RNS::Destination _delivery_destination;
		FanoutCallback _fanout_callback;

		RNS::Link _establish_link(const RNS::Destination& destination, double timeout);
		bool _send_publish_resource(
			const RNS::Destination& destination,
			const RNS::Bytes& payload,
			double timeout
		);
		RNS::Bytes _request(
			RNS::Link& link,
			const char* path,
			const RNS::Bytes& data,
			double timeout
		);
		void _handle_fanout(const RNS::Bytes& data);

		friend void rfed_packet_trampoline(const RNS::Bytes& data, const RNS::Packet& packet);
	};

}
