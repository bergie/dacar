/*
 * Dacar C++ port — Config and naming tests (§4, §10; §8/§11 naming).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include <unity.h>

#include "TestUtil.h"

#include <stdexcept>

using namespace Dacar;
using namespace DacarTest;

void setUp(void) {}
void tearDown(void) {}

static const char* FIXTURE_SALT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* FIXTURE_LEGACY_HEX = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100";

static RNS::Bytes anchorId() {
	RNS::Bytes id(16);
	memset(id.writable(16), 1, 16);
	return id;
}

void testRequiresAtLeastOneAnchor() {
	TEST_ASSERT_THROW(Config(Dacar::Set<RNS::Bytes>{}), std::invalid_argument);
}

void testAnchorLengthValidated() {
	RNS::Bytes bad(15);
	memset(bad.writable(15), 1, 15);
	TEST_ASSERT_THROW(Config({bad}), std::invalid_argument);
}

void testIsRootAnchor() {
	RNS::Bytes a = anchorId();
	RNS::Bytes b(16);
	memset(b.writable(16), 2, 16);
	Config config({a, b});
	TEST_ASSERT_TRUE(config.is_root_anchor(a));
	TEST_ASSERT_TRUE(config.is_root_anchor(b));
	RNS::Bytes other(16);
	memset(other.writable(16), 3, 16);
	TEST_ASSERT_FALSE(config.is_root_anchor(other));
}

void testAuthoritativeIdentityValidated() {
	RNS::Bytes bad(15);
	memset(bad.writable(15), 9, 15);
	TEST_ASSERT_THROW(
		Config({anchorId()}, bytesFromHex(FIXTURE_SALT_HEX), {}, {}, bad),
		std::invalid_argument
	);
	// A valid one round-trips; the empty default means "not configured".
	Config with_auth(
		{anchorId()}, bytesFromHex(FIXTURE_SALT_HEX), {}, {}, bytesFromHex("01010101010101010101010101010101")
	);
	TEST_ASSERT_TRUE(with_auth.authoritative_identity());
	Config without_auth({anchorId()}, bytesFromHex(FIXTURE_SALT_HEX));
	TEST_ASSERT_FALSE(without_auth.authoritative_identity());
}

void testSaltLengthValidated() {
	TEST_ASSERT_THROW(Config({anchorId()}, RNS::Bytes("short")), std::invalid_argument);
	// Legacy salts are validated too.
	TEST_ASSERT_THROW(
		Config({anchorId()}, bytesFromHex(FIXTURE_SALT_HEX), {RNS::Bytes("short")}),
		std::invalid_argument
	);
}

void testLegacyCapEnforced() {
	RNS::Bytes s0 = bytesFromHex(FIXTURE_SALT_HEX);
	RNS::Bytes s1 = bytesFromHex(FIXTURE_LEGACY_HEX);
	RNS::Bytes s2(32);
	memset(s2.writable(32), 3, 32);
	TEST_ASSERT_THROW(Config({anchorId()}, s0, {s1, s2, s0}), std::invalid_argument);
	// Two legacy salts are allowed.
	Config config({anchorId()}, s0, {s1, s2});
	TEST_ASSERT_EQUAL_size_t(2, config.legacy_salts().size());
}

void testPrimaryAndLegacyHashersOrdered() {
	RNS::Bytes s0 = bytesFromHex(FIXTURE_SALT_HEX);
	RNS::Bytes s1 = bytesFromHex(FIXTURE_LEGACY_HEX);
	Config config({anchorId()}, s0, {s1});
	auto hashers = config.hashers();
	TEST_ASSERT_EQUAL_size_t(2, hashers.size());
	TEST_ASSERT_TRUE(hashers[0].salt() == s0);
	TEST_ASSERT_TRUE(hashers[1].salt() == s1);
	TEST_ASSERT_TRUE(config.primary_hasher().salt() == s0);
	TEST_ASSERT_EQUAL_size_t(1, config.legacy_hashers().size());
}

void testGroupForLookup() {
	auto members = bytesVecFromHex(DacarFixtures::GROUP_CASES[0].members_hex);
	ThresholdGroup g(members, 1);
	Config config({g.group_id()}, bytesFromHex(FIXTURE_SALT_HEX), {}, {g});
	TEST_ASSERT_NOT_NULL(config.group_for(g.group_id()));
	RNS::Bytes other(16);
	memset(other.writable(16), 7, 16);
	TEST_ASSERT_NULL(config.group_for(other));
}

void testHorizonValidated() {
	TEST_ASSERT_THROW(Config({anchorId()}, bytesFromHex(FIXTURE_SALT_HEX), {}, {}, RNS::Bytes(), 0), std::invalid_argument);
	Config config({anchorId()});
	TEST_ASSERT_EQUAL_INT(DEFAULT_DELETION_HORIZON_DAYS, config.deletion_horizon_days());
	TEST_ASSERT_EQUAL_UINT64(
		(uint64_t)DEFAULT_DELETION_HORIZON_DAYS * 24ULL * 60ULL * 60ULL * 1000ULL,
		config.deletion_horizon_ms()
	);
}

void testNamingConstants() {
	TEST_ASSERT_EQUAL_STRING("dacar", APP_NAME);
	TEST_ASSERT_EQUAL_STRING("dacar.auth.v1", CHALLENGE_DESTINATION);
	TEST_ASSERT_EQUAL_STRING("auth", CHALLENGE_ASPECTS[0]);
	TEST_ASSERT_EQUAL_STRING("v1", CHALLENGE_ASPECTS[1]);
	TEST_ASSERT_EQUAL_STRING("dacar.policy.v1", RFED_TOPIC);
	TEST_ASSERT_EQUAL_STRING("dacar/sync/delta", LXMF_DELIVERY_TITLE);
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testRequiresAtLeastOneAnchor);
	RUN_TEST(testAnchorLengthValidated);
	RUN_TEST(testIsRootAnchor);
	RUN_TEST(testAuthoritativeIdentityValidated);
	RUN_TEST(testSaltLengthValidated);
	RUN_TEST(testLegacyCapEnforced);
	RUN_TEST(testPrimaryAndLegacyHashersOrdered);
	RUN_TEST(testGroupForLookup);
	RUN_TEST(testHorizonValidated);
	RUN_TEST(testNamingConstants);
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
