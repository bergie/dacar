/*
 * Dacar C++ port — §8 RNS transport unit tests (work doc #16 Phase 3).
 *
 * The FULL §8 Link flow (announce -> Link -> challenge -> signed receipt)
 * runs in the two-process UDP interop test (tools/challenge_udp_test.cpp +
 * tools/challenge_authority.cpp) — a single Reticulum stack cannot deliver
 * data packets to itself (Transport's packet-hash dedup filters looped-back
 * traffic). This suite covers the in-process pieces: stack bring-up, the
 * §8 wire wrap/unwrap convention, and the partition -> DENY defaults.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include <unity.h>

#include "TestUtil.h"

#include "Dacar/RnsChallenge.h"

#include <microStore/Adapters/UniversalFileSystem.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#include <unistd.h>

using namespace Dacar;
using namespace DacarTest;

static std::string temp_dir;

static RNS::Bytes fillBytes(size_t size, uint8_t fill = 0) {
	RNS::Bytes out;
	memset(out.writable(size), fill, size);
	return out;
}

static RNS::Bytes hashFromByte(uint8_t fill) {
	return fillBytes(16, fill);
}

static const char* FIXTURE_SALT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

void setUp(void) {}
void tearDown(void) {}

static RNS::Reticulum reticulum = RNS::Reticulum({RNS::Type::NONE});

void testStackStarts() {
	char tmpl[] = "/tmp/dacar-rns-challenge-XXXXXX";
	char* dir = ::mkdtemp(tmpl);
	TEST_ASSERT_NOT_NULL(dir);
	temp_dir = dir;

	// On native, microStore's PosixFileSystem resolves paths relative to the
	// process CWD (its basepath only applies to ESP32 LittleFS). Chdir into
	// the scratch dir so Reticulum's ./config etc. stay contained.
	TEST_ASSERT_EQUAL_INT(0, ::chdir(dir));

	static microStore::Adapters::UniversalFileSystem filesystem;
	RNS::Utilities::OS::register_filesystem(filesystem);

	reticulum = RNS::Reticulum();
	reticulum.transport_enabled(true);
	reticulum.start();
	TEST_ASSERT_TRUE(reticulum);
}

void testWireBinWrapUnwrap() {
	// Python RNS umsgpack-encodes `bytes` payloads as msgpack bin; the C++
	// adapters wrap on send and unwrap on receive.
	const RNS::Bytes payload("challenge-bytes");
	const RNS::Bytes wrapped = bin_wrap(payload);
	TEST_ASSERT_TRUE(wrapped.size() == payload.size() + 2);  // bin8 header
	TEST_ASSERT_EQUAL_INT(0xC4, wrapped.data()[0]);
	TEST_ASSERT_TRUE(bin_unwrap(wrapped) == payload);
	// Verbatim (non-bin) payloads pass through unchanged.
	TEST_ASSERT_TRUE(bin_unwrap(payload) == payload);
	TEST_ASSERT_FALSE(bin_unwrap(RNS::Bytes()));
}

void testDestinationNaming() {
	// The destination hash derives from app name + aspects + identity: the
	// authority's `dacar.auth.v1` aspects, dot-joined in the microReticulum
	// ctor, produce the hash Python RNS computes for the same name.
	RNS::Identity identity = RNS::Identity();
	const RNS::Destination authority(identity, RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE, APP_NAME, DACAR_CHALLENGE_ASPECTS);
	TEST_ASSERT_EQUAL_UINT32(HASH_SIZE, authority.hash().size());

	// A different aspect set yields a different hash.
	const RNS::Destination other(identity, RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE, APP_NAME, "other.v1");
	TEST_ASSERT_FALSE(authority.hash() == other.hash());
}

void testTransportDeniesWhenLinkDown() {
	// A transport over an invalid (never established) Link returns empty
	// Bytes -> the ChallengeClient treats it as a partition -> DENY (§8).
	RNS::Link dead({RNS::Type::NONE});
	RnsLinkTransport transport(dead, reticulum, 0.5, 0.1);
	const RNS::Bytes receipt = transport(bytesFromHex("90"));
	TEST_ASSERT_FALSE(receipt);

	Dacar::Set<RNS::Bytes> anchors{hashFromByte(0x01)};
	Config config(anchors, bytesFromHex(FIXTURE_SALT_HEX), {}, {}, hashFromByte(0x01));
	StateVector state(config.deletion_horizon_days());
	ChallengeClient client(config, state, fillBytes(PUBLIC_KEY_SIZE, 0x22), transport);
	TEST_ASSERT_FALSE(client.authorize("buzzer", "sound", hashFromByte(0x03)));
}

void testEstablishLinkTimesOut() {
	// No path to a bogus destination -> the link cannot establish within
	// the (short) timeout -> invalid Link (§8.2 -> DENY).
	const RNS::Identity ghost = RNS::Identity();
	const RNS::Destination ghostDestination(ghost, RNS::Type::Destination::OUT, RNS::Type::Destination::SINGLE, APP_NAME, DACAR_CHALLENGE_ASPECTS);
	const RNS::Link link = establish_challenge_link(reticulum, ghostDestination, 0.5);
	TEST_ASSERT_FALSE(link);
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testStackStarts);
	RUN_TEST(testWireBinWrapUnwrap);
	RUN_TEST(testDestinationNaming);
	RUN_TEST(testTransportDeniesWhenLinkDown);
	RUN_TEST(testEstablishLinkTimesOut);
	return UNITY_END();
}

int main(void) {
	int result = runUnityTests();
	if (!temp_dir.empty()) {
		::chdir("/tmp");
		::system(("rm -rf '" + temp_dir + "'").c_str());
	}
	return result;
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
