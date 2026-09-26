/*
 * Dacar C++ port — Threshold Group tests (§4.1).
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

void testGroupIdsMatchCanonical() {
	for (const auto& c : DacarFixtures::GROUP_CASES) {
		auto members = bytesVecFromHex(c.members_hex);
		TEST_ASSERT_EQUAL_STRING(c.gid_hex, group_id(members, c.threshold).toHex().c_str());
	}
}

void testOrderInvariance() {
	// GROUP_CASES[0] and [1] are the same member set in different order.
	TEST_ASSERT_EQUAL_STRING(
		DacarFixtures::GROUP_CASES[0].gid_hex, DacarFixtures::GROUP_CASES[1].gid_hex
	);
	TEST_ASSERT_EQUAL_STRING(
		DacarFixtures::GROUP_CASES[3].gid_hex, DacarFixtures::GROUP_CASES[4].gid_hex
	);
}

void testThresholdChangesId() {
	TEST_ASSERT_TRUE(
		strcmp(DacarFixtures::GROUP_CASES[0].gid_hex, DacarFixtures::GROUP_CASES[2].gid_hex) != 0
	);
}

void testValidation() {
	auto members = bytesVecFromHex(DacarFixtures::GROUP_CASES[0].members_hex);
	// A group needs at least 2 members.
	TEST_ASSERT_THROW(group_id({members[0]}, 1), std::invalid_argument);
	// Member hashes must be 16 bytes.
	RNS::Bytes bad(15);
	memset(bad.writable(15), 1, 15);
	TEST_ASSERT_THROW(group_id({bad, members[0]}, 1), std::invalid_argument);
	// 1 <= N <= M.
	TEST_ASSERT_THROW(group_id(members, 0), std::invalid_argument);
	TEST_ASSERT_THROW(group_id(members, 3), std::invalid_argument);
	// ThresholdGroup validates via the same path.
	TEST_ASSERT_THROW(ThresholdGroup(members, 3), std::invalid_argument);
}

void testMembersStoredSorted() {
	auto members = bytesVecFromHex(DacarFixtures::GROUP_CASES[4].members_hex);
	ThresholdGroup g(members, 2);
	const auto& sorted = g.members();
	for (size_t i = 1; i < sorted.size(); i++) {
		TEST_ASSERT_TRUE(sorted[i - 1].compare(sorted[i]) < 0);
	}
	// Group ID of the normalized group matches the fixture.
	TEST_ASSERT_EQUAL_STRING(
		DacarFixtures::GROUP_CASES[4].gid_hex, g.group_id().toHex().c_str()
	);
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testGroupIdsMatchCanonical);
	RUN_TEST(testOrderInvariance);
	RUN_TEST(testThresholdChangesId);
	RUN_TEST(testValidation);
	RUN_TEST(testMembersStoredSorted);
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
