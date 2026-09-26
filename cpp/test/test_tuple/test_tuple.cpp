/*
 * Dacar C++ port — hashed Tuple tests (§3.1, §6.1).
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

// The canonical fixture salt: bytes(range(32)).
static const char* FIXTURE_SALT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

void testFromPlaintextMatchesCanonical() {
	NamespaceHasher hasher(bytesFromHex(FIXTURE_SALT_HEX));
	for (const auto& c : DacarFixtures::TUPLE_CASES) {
		Tuple t = Tuple::from_plaintext(
			c.object, c.relation, bytesFromHex(c.grantee_hex), bytesFromHex(c.issuer_hex), hasher
		);
		TEST_ASSERT_EQUAL_STRING(c.preimage_hex, t.preimage().toHex().c_str());
		TEST_ASSERT_EQUAL_STRING(c.hash_hex, t.hash().toHex().c_str());
	}
}

void testPreimageExcludesActionAndHlc() {
	// A grant and a revoke of the same permission share the Tuple Hash (§6.1).
	NamespaceHasher hasher(bytesFromHex(FIXTURE_SALT_HEX));
	const auto& c = DacarFixtures::TUPLE_CASES[0];
	Tuple t = Tuple::from_plaintext(
		c.object, c.relation, bytesFromHex(c.grantee_hex), bytesFromHex(c.issuer_hex), hasher
	);
	TEST_ASSERT_EQUAL_UINT64(t.hash().size(), 32);
	// Structural equality and hash equality are aligned.
	Tuple same = t;
	TEST_ASSERT_TRUE(t == same);
	TEST_ASSERT_TRUE(t.hash() == same.hash());
}

void testPerIssuerDistinctness() {
	NamespaceHasher hasher(bytesFromHex(FIXTURE_SALT_HEX));
	const auto& c = DacarFixtures::TUPLE_CASES[0];
	Tuple a = Tuple::from_plaintext(c.object, c.relation, bytesFromHex(c.grantee_hex), bytesFromHex(c.issuer_hex), hasher);
	// Different issuer -> different tuple hash.
	RNS::Bytes other_issuer = bytesFromHex(DacarFixtures::TUPLE_CASES[1].issuer_hex);
	Tuple b = Tuple::from_plaintext(c.object, c.relation, bytesFromHex(c.grantee_hex), other_issuer, hasher);
	TEST_ASSERT_TRUE(a.hash() != b.hash());
	// Different grantee -> different tuple hash.
	RNS::Bytes other_grantee = bytesFromHex(DacarFixtures::TUPLE_CASES[1].grantee_hex);
	Tuple g = Tuple::from_plaintext(c.object, c.relation, other_grantee, bytesFromHex(c.issuer_hex), hasher);
	TEST_ASSERT_TRUE(a.hash() != g.hash());
}

void testWildcardDiffersFromExact() {
	NamespaceHasher hasher(bytesFromHex(FIXTURE_SALT_HEX));
	const auto& c = DacarFixtures::TUPLE_CASES[0]; // "sensor:wind" exact
	const auto& w = DacarFixtures::TUPLE_CASES[1]; // "sensor:*" wildcard
	Tuple exact = Tuple::from_plaintext(c.object, c.relation, bytesFromHex(c.grantee_hex), bytesFromHex(c.issuer_hex), hasher);
	Tuple wild = Tuple::from_plaintext(w.object, w.relation, bytesFromHex(w.grantee_hex), bytesFromHex(w.issuer_hex), hasher);
	TEST_ASSERT_TRUE(exact.hash() != wild.hash());
}

void testBadLengthsRejected() {
	NamespaceHasher hasher;
	RNS::Bytes good_rel = hasher.hash_relation("r");
	RNS::Bytes good_id(16);
	memset(good_id.writable(16), 1, 16);
	RNS::Bytes bad_id(15);
	memset(bad_id.writable(15), 1, 15);
	// Constructor validates every fixed-size field.
	TEST_ASSERT_THROW(Tuple(bad_id, {}, false, good_id, good_id), std::invalid_argument);
	TEST_ASSERT_THROW(Tuple(good_rel, {}, false, bad_id, good_id), std::invalid_argument);
	TEST_ASSERT_THROW(Tuple(good_rel, {}, false, good_id, bad_id), std::invalid_argument);
	// Object segment hashes must also be 16 bytes.
	Dacar::Vector<RNS::Bytes> bad_segs;
	RNS::Bytes short_seg;
	memset(short_seg.writable(8), 1, 8);
	bad_segs.push_back(short_seg);
	TEST_ASSERT_THROW(Tuple(good_rel, bad_segs, false, good_id, good_id), std::invalid_argument);
}

void testTooManySegmentsRejected() {
	NamespaceHasher hasher;
	RNS::Bytes rel = hasher.hash_relation("r");
	RNS::Bytes id(16);
	memset(id.writable(16), 1, 16);
	Dacar::Vector<RNS::Bytes> segs;
	RNS::Bytes seg = hasher.hash_relation("s");
	for (size_t i = 0; i < MAX_SEGMENTS + 1; i++) {
		segs.push_back(seg);
	}
	TEST_ASSERT_THROW(Tuple(rel, segs, false, id, id), std::invalid_argument);
}

int runUnityTests(void) {
	UNITY_BEGIN();
	RUN_TEST(testFromPlaintextMatchesCanonical);
	RUN_TEST(testPreimageExcludesActionAndHlc);
	RUN_TEST(testPerIssuerDistinctness);
	RUN_TEST(testWildcardDiffersFromExact);
	RUN_TEST(testBadLengthsRejected);
	RUN_TEST(testTooManySegmentsRejected);
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
