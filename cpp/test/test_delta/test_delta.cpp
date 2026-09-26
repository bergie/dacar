/*
 * Dacar C++ port — Delta receive boundary tests (§11.2.4).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include <unity.h>

#include "TestUtil.h"

#include <string>

using namespace Dacar;
using namespace DacarTest;

void setUp(void) {}
void tearDown(void) {}

static RNS::Bytes opPayload(size_t index) {
	return bytesFromHex(DacarFixtures::OP_CASES[index].payload_hex);
}

static Keyring fixtureKeyring() {
	Keyring ring;
	for (size_t i = 0; i < DacarFixtures::OP_CASE_COUNT; i++) {
		const auto& c = DacarFixtures::OP_CASES[i];
		ring.register_keyset(
			bytesFromHex(c.issuer_hex),
			IssuerKeyset(bytesVecFromHex(c.member_pubs_hex), c.threshold)
		);
	}
	return ring;
}

void testBatchEncodingMatchesCanonical() {
	for (size_t i = 0; i < DacarFixtures::BATCH_CASE_COUNT; i++) {
		const auto& c = DacarFixtures::BATCH_CASES[i];
		auto payloads = bytesVecFromHex(c.payloads_hex);
		TEST_ASSERT_EQUAL_STRING(
			c.expected_hex, DeltaReceiver::pack_payloads(payloads).toHex().c_str()
		);
	}
}

void testValidSignedDeltaIsApplied() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	// Fixture ops carry a 2023-era HLC: pass the op's own physical time as
	// the wall clock so the §9 intake rejection does not drop them.
	Operation first = Operation::from_payload(opPayload(0));
	int64_t now = (int64_t)(first.hlc() >> 16);
	TEST_ASSERT_TRUE(receiver.apply_payload(opPayload(0), now));
	TEST_ASSERT_EQUAL_size_t(1, state.size());
	// Applying the same delta again is an idempotent no-op on state size.
	TEST_ASSERT_TRUE(receiver.apply_payload(opPayload(0), now));
	TEST_ASSERT_EQUAL_size_t(1, state.size());
	// A second distinct valid delta applies too.
	TEST_ASSERT_TRUE(receiver.apply_payload(opPayload(3), now));
	TEST_ASSERT_EQUAL_size_t(2, state.size());
}

void testForgedDeltaIsDropped() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	std::string hex(DacarFixtures::OP_CASES[0].payload_hex);
	hex[hex.size() - 1] = (hex[hex.size() - 1] == '0') ? '1' : '0';
	TEST_ASSERT_FALSE(receiver.apply_payload(bytesFromHex(hex.c_str())));
	TEST_ASSERT_EQUAL_size_t(0, state.size());
}

void testUnknownIssuerIsDropped() {
	StateVector state;
	DeltaReceiver receiver(state, Keyring());
	TEST_ASSERT_FALSE(receiver.apply_payload(opPayload(0)));
	TEST_ASSERT_EQUAL_size_t(0, state.size());
}

void testMalformedPayloadIsSwallowed() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	TEST_ASSERT_FALSE(receiver.apply_payload(RNS::Bytes("not-msgpack")));
	TEST_ASSERT_FALSE(receiver.apply_payload(RNS::Bytes()));
	TEST_ASSERT_EQUAL_size_t(0, state.size());
}

void testBatchOfValidDeltasAllApplied() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	auto payloads = bytesVecFromHex(DacarFixtures::BATCH_CASES[0].payloads_hex);
	RNS::Bytes batch = DeltaReceiver::pack_payloads(payloads);
	Operation first = Operation::from_payload(opPayload(0));
	int64_t now = (int64_t)(first.hlc() >> 16);
	TEST_ASSERT_EQUAL_size_t(payloads.size(), receiver.apply_payloads(batch, now));
	TEST_ASSERT_EQUAL_size_t(payloads.size(), state.size());
}

void testForgedElementDroppedRestApplied() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	Dacar::Vector<RNS::Bytes> payloads = bytesVecFromHex(DacarFixtures::BATCH_CASES[0].payloads_hex);
	// Corrupt the signature of the first payload (last byte).
	std::string hex(DacarFixtures::OP_CASES[0].payload_hex);
	hex[hex.size() - 1] = (hex[hex.size() - 1] == '0') ? '1' : '0';
	payloads[0] = bytesFromHex(hex.c_str());
	RNS::Bytes batch = DeltaReceiver::pack_payloads(payloads);
	Operation first = Operation::from_payload(opPayload(0));
	int64_t now = (int64_t)(first.hlc() >> 16);
	TEST_ASSERT_EQUAL_size_t(payloads.size() - 1, receiver.apply_payloads(batch, now));
}

void testUnknownIssuerElementDropped() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	// Replace the second element's issuer registration by using a payload
	// whose issuer is not in the keyring: op 3 uses issuer HASHES[0] which
	// IS registered, so use an empty keyring but feed batch element 0 only.
	Dacar::Vector<RNS::Bytes> payloads{opPayload(0), opPayload(1)};
	RNS::Bytes batch = DeltaReceiver::pack_payloads(payloads);
	Operation first = Operation::from_payload(opPayload(0));
	int64_t now = (int64_t)(first.hlc() >> 16);
	TEST_ASSERT_EQUAL_size_t(2, receiver.apply_payloads(batch, now));

	StateVector state2;
	DeltaReceiver receiver2(state2, Keyring());
	TEST_ASSERT_EQUAL_size_t(0, receiver2.apply_payloads(batch));
}

void testMalformedOuterPayloadIsSwallowed() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	TEST_ASSERT_EQUAL_size_t(0, receiver.apply_payloads(RNS::Bytes("garbage")));
	// A valid msgpack non-array value.
	TEST_ASSERT_EQUAL_size_t(0, receiver.apply_payloads(bytesFromHex("C40101")));
	TEST_ASSERT_EQUAL_size_t(0, state.size());
}

void testFutureSkewedElementRejected() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	DeltaReceiver receiver(state, ring);
	// Decoded op 0 carries a 2023-era HLC; with now far in the future it is
	// stale (§9 intake rejection). now = hlc_physical + far beyond horizon.
	Operation op = Operation::from_payload(opPayload(0));
	uint64_t stale_now = (op.hlc() >> 16) + 400ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
	TEST_ASSERT_FALSE(receiver.apply_payload(opPayload(0), (int64_t)stale_now));
	TEST_ASSERT_EQUAL_size_t(0, state.size());
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testBatchEncodingMatchesCanonical);
	RUN_TEST(testValidSignedDeltaIsApplied);
	RUN_TEST(testForgedDeltaIsDropped);
	RUN_TEST(testUnknownIssuerIsDropped);
	RUN_TEST(testMalformedPayloadIsSwallowed);
	RUN_TEST(testBatchOfValidDeltasAllApplied);
	RUN_TEST(testForgedElementDroppedRestApplied);
	RUN_TEST(testUnknownIssuerElementDropped);
	RUN_TEST(testMalformedOuterPayloadIsSwallowed);
	RUN_TEST(testFutureSkewedElementRejected);
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
