/*
 * Dacar C++ port — rfed compact-format wrap/unwrap CLI tool.
 *
 * Manual cross-implementation verification helper (mirrors the role of
 * challenge_authority for the §8 flow): the C++ side wraps or unwraps a
 * Dacar compact-format (§11.1.1) channel payload, and the output is fed
 * through the canonical Python implementation's
 * dacar.transport.rfed_compact for the reverse direction:
 *
 *     # C++ wraps, Python unwraps:
 *     rfed_wrap_tool wrap dacar.policy.v1 <delta-hex> | ... python unwrap
 *     # Python wraps (fixture in FixturesGen.h), C++ unwraps:
 *     covered by the test_rfed_compact Unity suite.
 *
 * Not wired into ctest: needs no network, but validates only with a
 * cooperating Python invocation.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Dacar/RfedCompact.h"

#include "microReticulum/Log.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

namespace {

	RNS::Bytes fromHex(const std::string& hex) {
		RNS::Bytes b;
		b.assignHex(hex.c_str());
		return b;
	}

} // namespace

int main(int argc, char** argv) {
	// Keep stdout clean: the payload hex is the tool's output contract.
	RNS::loglevel(RNS::LOG_CRITICAL);
	if (argc < 4) {
		std::cerr << "usage: rfed_wrap_tool wrap <channel-name> <delta-hex> [stamp-cost]\n"
		             "       rfed_wrap_tool unwrap <channel-name> <rfed-payload-hex>"
		          << std::endl;
		return 1;
	}
	const std::string mode = argv[1];
	const std::string channel_name = argv[2];
	try {
		const RFed::Channel channel = RFed::derive_channel(channel_name);
		if (mode == "wrap") {
			const RNS::Bytes delta = fromHex(argv[3]);
			size_t stamp_cost = 0;
			if (argc >= 5) {
				stamp_cost = (size_t)std::stoul(argv[4]);
			}
			const RNS::Identity sender = channel.identity; // tool-only: sender = channel
			const RFed::RfedPayload wrapped = Dacar::wrap_dacar_delta(
				channel.identity, sender, delta, stamp_cost);
			std::cout << wrapped.rfed_payload.toHex() << std::endl;
		}
		else if (mode == "unwrap") {
			const RNS::Bytes rfed_payload = fromHex(argv[3]);
			const RFed::FanoutPayload parsed = RFed::parse_fanout_payload(rfed_payload);
			const Dacar::DecodedDacarDelta decoded =
				Dacar::unwrap_dacar_delta(parsed.inner_blob, channel.identity);
			std::cout << decoded.delta.toHex() << std::endl;
			std::cerr << "sender_pub: " << decoded.sender_pub.toHex() << std::endl;
		}
		else {
			std::cerr << "unknown mode: " << mode << std::endl;
			return 1;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "error: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}
