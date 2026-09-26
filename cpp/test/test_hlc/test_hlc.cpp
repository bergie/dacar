/*
 * Dacar C++ port — Hybrid Logical Clock tests (§5.1).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include <unity.h>

#include "TestUtil.h"

#include <stdexcept>

using namespace Dacar;

void setUp(void) {}
void tearDown(void) {}

void testPackUnpackMatchesCanonical() {
	for (const auto& c : DacarFixtures::HLC_CASES) {
		TEST_ASSERT_EQUAL_UINT64(c.packed, pack(c.physical, c.logical));
		auto [phys, logical] = unpack(c.packed);
		TEST_ASSERT_EQUAL_UINT64(c.physical, phys);
		TEST_ASSERT_EQUAL_UINT64(c.logical, logical);
	}
}

void testLayoutIs48Plus16() {
	// 48-bit physical in the high half, 16-bit logical in the low half.
	TEST_ASSERT_EQUAL_UINT64(MAX_PHYSICAL, unpack(pack(MAX_PHYSICAL, 0)).first);
	TEST_ASSERT_EQUAL_UINT64(MAX_LOGICAL, unpack(pack(0, MAX_LOGICAL)).second);
	TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, pack(MAX_PHYSICAL, MAX_LOGICAL));
}

void testOutOfRangeThrows() {
	TEST_ASSERT_THROW(pack(MAX_PHYSICAL + 1, 0), std::invalid_argument);
	TEST_ASSERT_THROW(pack(0, MAX_LOGICAL + 1), std::invalid_argument);
}

void testClockMonotonic() {
	Clock clock;
	uint64_t previous = 0;
	for (int i = 0; i < 1000; i++) {
		uint64_t now = clock.now();
		TEST_ASSERT_GREATER_OR_EQUAL_UINT64(previous, now);
		previous = now;
	}
}

void testObservePreservesHappensBefore() {
	Clock clock;
	// Absorb a remote HLC from the physical future: the local clock must
	// move past it.
	uint64_t remote = pack(physical_now_ms() + 60'000, 5);
	uint64_t observed = clock.observe(remote);
	TEST_ASSERT_GREATER_THAN_UINT64(remote, observed);
	// Any subsequent local event stays after the observation.
	TEST_ASSERT_GREATER_OR_EQUAL_UINT64(observed, clock.now());
	// Absorbing an old remote HLC still advances the logical counter.
	uint64_t before = clock.now();
	uint64_t old_remote = pack(1000, 1);
	uint64_t after_old = clock.observe(old_remote);
	TEST_ASSERT_GREATER_THAN_UINT64(before, after_old);
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testPackUnpackMatchesCanonical);
	RUN_TEST(testLayoutIs48Plus16);
	RUN_TEST(testOutOfRangeThrows);
	RUN_TEST(testClockMonotonic);
	RUN_TEST(testObservePreservesHappensBefore);
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
