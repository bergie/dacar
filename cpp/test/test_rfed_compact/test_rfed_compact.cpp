/*
 * Dacar C++ port — Dacar compact RFed inner-format tests (§11.1.1, work doc
 * #16 Phase 4b).
 *
 * Every wrapped-payload fixture was produced by the canonical Python
 * implementation (EC encryption is randomized, so the stored ciphertext is
 * deterministic to *decrypt*): the C++ side verifies the Python→C++ direction
 * byte-exactly and wraps/unwraps its own payloads locally. The C++→Python
 * direction is verified with the rfed_wrap_tool against the Python CLI.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include <unity.h>

#include "TestUtil.h"

#include "Dacar/Naming.h"
#include "Dacar/RfedCompact.h"
#include "rfed/Client.h"

#include <stdexcept>

using namespace Dacar;
using namespace DacarTest;

void setUp(void) {}
void tearDown(void) {}

// The fixture's channel and sender identities, derived from their names the
// same way the Python generator derived them.
static RFed::Channel fixtureChannel() {
	return RFed::derive_channel(DacarFixtures::RFED_COMPACT_CASES[0].channel_name);
}

static RFed::Channel fixtureSender() {
	return RFed::derive_channel(DacarFixtures::RFED_COMPACT_CASES[0].sender_name);
}

void testUnwrapsPythonWrappedDelta() {
	const auto& c = DacarFixtures::RFED_COMPACT_CASES[0];
	const RFed::Channel channel = fixtureChannel();
	// The derived channel identity must match the fixture's recorded key
	// material — the sender prelude was encrypted to exactly this keypair.
	const RNS::Bytes delta = bytesFromHex(c.delta_hex);
	const RNS::Bytes inner_blob = bytesFromHex(c.inner_blob_hex);
	const RNS::Bytes rfed_payload = bytesFromHex(c.rfed_payload_hex);

	// The rfed payload framing: channel_hash(16) ‖ inner_blob (no stamp).
	const RFed::FanoutPayload parsed = RFed::parse_fanout_payload(rfed_payload);
	TEST_ASSERT_TRUE(parsed.channel_hash == channel.channel_hash);
	TEST_ASSERT_TRUE(parsed.inner_blob == inner_blob);

	const DecodedDacarDelta decoded = unwrap_dacar_delta(inner_blob, channel.identity);
	TEST_ASSERT_TRUE(decoded.delta == delta);
	TEST_ASSERT_TRUE(decoded.sender_pub == bytesFromHex(c.sender_pub_hex));
	TEST_ASSERT_TRUE(decoded.sender_identity.hash() == fixtureSender().identity.hash());
}

void testWrapUnwrapRoundtrip() {
	const RFed::Channel channel = fixtureChannel();
	const RFed::Channel sender = fixtureSender();
	const RNS::Bytes delta = bytesFromHex(DacarFixtures::RFED_COMPACT_CASES[0].delta_hex);

	const RFed::RfedPayload wrapped = wrap_dacar_delta(
		channel.identity, sender.identity, delta);
	TEST_ASSERT_TRUE(wrapped.channel_hash == channel.channel_hash);
	TEST_ASSERT_TRUE(wrapped.channel_delivery_hash ==
		RFed::delivery_hash_for(channel.identity));
	TEST_ASSERT_EQUAL_size_t(0, wrapped.stamp.size());
	TEST_ASSERT_EQUAL_size_t(
		RFed::HASH_LENGTH + wrapped.inner_blob.size(), wrapped.rfed_payload.size());

	const RFed::FanoutPayload parsed = RFed::parse_fanout_payload(wrapped.rfed_payload);
	const DecodedDacarDelta decoded = unwrap_dacar_delta(parsed.inner_blob, channel.identity);
	TEST_ASSERT_TRUE(decoded.delta == delta);
	TEST_ASSERT_TRUE(decoded.sender_pub == sender.identity.get_public_key());
}

void testStampedWrapCarriesValidatingStamp() {
	const RFed::Channel channel = fixtureChannel();
	const RFed::Channel sender = fixtureSender();
	const RNS::Bytes delta = bytesFromHex(DacarFixtures::RFED_COMPACT_CASES[0].delta_hex);

	const RFed::RfedPayload wrapped = wrap_dacar_delta(
		channel.identity, sender.identity, delta, 12);
	TEST_ASSERT_EQUAL_size_t(RFed::STAMP_SIZE, wrapped.stamp.size());
	TEST_ASSERT_EQUAL_size_t(
		RFed::HASH_LENGTH + wrapped.inner_blob.size() + RFed::STAMP_SIZE,
		wrapped.rfed_payload.size());
	// The appended stamp validates against the SEND-form framing.
	TEST_ASSERT_TRUE(RFed::validate_channel_stamp(
		wrapped.channel_hash, wrapped.inner_blob, wrapped.stamp, 12));
	// The SEND payload splits into exactly the constituent parts.
	const RFed::SendPayload parsed = RFed::parse_send_payload(wrapped.rfed_payload);
	TEST_ASSERT_TRUE(parsed.channel_hash == wrapped.channel_hash);
	TEST_ASSERT_TRUE(parsed.inner_blob == wrapped.inner_blob);
	TEST_ASSERT_TRUE(parsed.stamp == wrapped.stamp);
}

void testUnwrapRejectsWrongChannelAndGarbage() {
	const RFed::Channel channel = fixtureChannel();
	const RFed::Channel other = RFed::derive_channel("dacar.policy.v1");
	const RNS::Bytes inner_blob = bytesFromHex(
		DacarFixtures::RFED_COMPACT_CASES[0].inner_blob_hex);

	// Decrypting with a foreign channel key fails (or decrypts to garbage
	// that fails the magic check — both are rejections).
	TEST_ASSERT_THROW(unwrap_dacar_delta(inner_blob, other.identity), std::invalid_argument);
	// Garbage blobs are rejected.
	TEST_ASSERT_THROW(unwrap_dacar_delta(RNS::Bytes("garbage-not-a-token"), channel.identity),
		std::invalid_argument);
	TEST_ASSERT_THROW(unwrap_dacar_delta(RNS::Bytes(), channel.identity), std::invalid_argument);
}

void testDefaultTopicDerivesThePolicyChannel() {
	// The deployment default topic (Dacar/Naming.h RFED_TOPIC) hashes to the
	// first fixture channel: the Python and C++ sides agree on the channel
	// identity for the shared default.
	const RFed::Channel channel = RFed::derive_channel(Dacar::RFED_TOPIC);
	TEST_ASSERT_EQUAL_STRING(
		DacarFixtures::RFED_CHANNEL_CASES[0].channel_hash_hex,
		channel.channel_hash.toHex().c_str());
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testUnwrapsPythonWrappedDelta);
	RUN_TEST(testWrapUnwrapRoundtrip);
	RUN_TEST(testStampedWrapCarriesValidatingStamp);
	RUN_TEST(testUnwrapRejectsWrongChannelAndGarbage);
	RUN_TEST(testDefaultTopicDerivesThePolicyChannel);
	return UNITY_END();
}

int main(void) {
	return runUnityTests();
}

#ifdef ARDUINO
void setup() {
	delay(2000);
	runUnityTests();
}
void loop() {}
#endif

void app_main() {
	runUnityTests();
}
