/*
 * Dacar C++ port — verify-on-ingest tests (§11.2.4).
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

static RNS::Bytes opPayload(size_t index) {
	return bytesFromHex(DacarFixtures::OP_CASES[index].payload_hex);
}

void testIssuerKeysetSingle() {
	IssuerKeyset k = IssuerKeyset::single(bytesFromHex(DacarFixtures::KEYS[0].public_hex));
	TEST_ASSERT_EQUAL_INT(1, k.threshold());
	TEST_ASSERT_EQUAL_size_t(1, k.member_public_keys().size());
	// Bad key length rejected.
	TEST_ASSERT_THROW(
		IssuerKeyset({RNS::Bytes(31)}, 1), std::invalid_argument
	);
	// Threshold below one rejected.
	TEST_ASSERT_THROW(
		IssuerKeyset({bytesFromHex(DacarFixtures::KEYS[0].public_hex)}, 0), std::invalid_argument
	);
	// Fewer keys than threshold rejected.
	TEST_ASSERT_THROW(
		IssuerKeyset({bytesFromHex(DacarFixtures::KEYS[0].public_hex)}, 2), std::invalid_argument
	);
}

void testIssuerKeysetGroup() {
	auto pubs = bytesVecFromHex(DacarFixtures::OP_CASES[5].member_pubs_hex);
	IssuerKeyset k = IssuerKeyset::group(pubs, 2);
	TEST_ASSERT_EQUAL_INT(2, k.threshold());
	TEST_ASSERT_EQUAL_size_t(3, k.member_public_keys().size());
}

void testKeyring() {
	Keyring ring;
	RNS::Bytes issuer = bytesFromHex(DacarFixtures::OP_CASES[0].issuer_hex);
	RNS::Bytes pub = bytesFromHex(DacarFixtures::KEYS[0].public_hex);
	ring.register_single(issuer, pub);
	TEST_ASSERT_TRUE(ring.contains(issuer));
	TEST_ASSERT_EQUAL_size_t(1, ring.size());
	const IssuerKeyset* resolved = ring.resolve(issuer);
	TEST_ASSERT_NOT_NULL(resolved);
	TEST_ASSERT_EQUAL_INT(1, resolved->threshold());
	// Unknown issuer resolves to nullptr.
	RNS::Bytes unknown(16);
	memset(unknown.writable(16), 0xAB, 16);
	TEST_ASSERT_NULL(ring.resolve(unknown));
	// The Keyring is directly usable as a KeyResolver.
	TEST_ASSERT_NULL(ring(unknown));
	TEST_ASSERT_NOT_NULL(ring(issuer));
	// Forgetting a known issuer returns true once.
	TEST_ASSERT_TRUE(ring.forget(issuer));
	TEST_ASSERT_FALSE(ring.forget(issuer));
	// Group registration.
	auto pubs = bytesVecFromHex(DacarFixtures::OP_CASES[5].member_pubs_hex);
	RNS::Bytes gid = bytesFromHex(DacarFixtures::OP_CASES[5].issuer_hex);
	ring.register_group(gid, pubs, 2);
	TEST_ASSERT_EQUAL_INT(2, ring.resolve(gid)->threshold());
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

void testVerifyOperation() {
	Keyring ring = fixtureKeyring();
	for (size_t i = 0; i < DacarFixtures::OP_CASE_COUNT; i++) {
		Operation op = Operation::from_payload(opPayload(i));
		TEST_ASSERT_TRUE(verify_operation(op, ring));
	}
	// Tampered operation rejected.
	Operation op = Operation::from_payload(opPayload(0));
	std::string hex(DacarFixtures::OP_CASES[0].payload_hex);
	hex[hex.size() - 1] = (hex[hex.size() - 1] == '0') ? '1' : '0';
	Operation tampered = Operation::from_payload(bytesFromHex(hex.c_str()));
	TEST_ASSERT_FALSE(verify_operation(tampered, ring));
	// Unknown issuer rejected.
	Keyring empty;
	TEST_ASSERT_FALSE(verify_operation(op, empty));
}

void testIngestAppliesOnlyAuthenticatedDeltas() {
	Keyring ring = fixtureKeyring();
	StateVector state;
	// Valid single-identity delta applied. Fixture ops carry a 2023-era HLC,
	// so pass an explicit wall clock (the op's own physical time); with the
	// real clock the §9 intake rejection would (correctly) drop them.
	Operation valid = Operation::from_payload(opPayload(0));
	int64_t now = (int64_t)(valid.hlc() >> 16);
	TEST_ASSERT_TRUE(state.ingest(valid, ring, now));
	TEST_ASSERT_EQUAL_size_t(1, state.size());
	// Applying the same delta again is an idempotent no-op on state size.
	TEST_ASSERT_TRUE(state.ingest(valid, ring, now));
	TEST_ASSERT_EQUAL_size_t(1, state.size());
	// Forged delta not applied.
	std::string hex(DacarFixtures::OP_CASES[0].payload_hex);
	hex[hex.size() - 1] = (hex[hex.size() - 1] == '0') ? '1' : '0';
	Operation forged = Operation::from_payload(bytesFromHex(hex.c_str()));
	TEST_ASSERT_FALSE(state.ingest(forged, ring, now));
	// Unknown issuer not applied.
	TEST_ASSERT_FALSE(state.ingest(valid, Keyring(), now));
	TEST_ASSERT_EQUAL_size_t(1, state.size());
	// Valid threshold delta applied.
	Operation group_op = Operation::from_payload(opPayload(5));
	TEST_ASSERT_TRUE(state.ingest(group_op, ring, (int64_t)(group_op.hlc() >> 16)));
	TEST_ASSERT_EQUAL_size_t(2, state.size());
}

void testApplyTrustedPathDoesNotVerify() {
	// apply() trusts its caller — no key resolution, no cryptography.
	StateVector state;
	Operation op = Operation::from_payload(opPayload(0));
	TEST_ASSERT_TRUE(state.apply(op, op.hlc() >> 16));
	TEST_ASSERT_EQUAL_size_t(1, state.size());
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testIssuerKeysetSingle);
	RUN_TEST(testIssuerKeysetGroup);
	RUN_TEST(testKeyring);
	RUN_TEST(testVerifyOperation);
	RUN_TEST(testIngestAppliesOnlyAuthenticatedDeltas);
	RUN_TEST(testApplyTrustedPathDoesNotVerify);
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
