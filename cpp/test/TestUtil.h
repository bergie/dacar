/*
 * Dacar C++ port — shared Unity test helpers.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Dacar.h"
#include "fixtures/FixturesGen.h"

#include <string>
#include <vector>

// Unity has no exception assertion; provide one for the C++ port's
// validation-contract tests.
#define TEST_ASSERT_THROW(expr, exc_type) \
	do { \
		bool dacar_threw_ = false; \
		try { (void)(expr); } \
		catch (const exc_type&) { dacar_threw_ = true; } \
		catch (...) {} \
		TEST_ASSERT_TRUE(dacar_threw_); \
	} while (0)

namespace DacarTest {

	// Decode a lowercase hex string into Bytes.
	inline RNS::Bytes bytesFromHex(const char* hex) {
		RNS::Bytes b;
		if (hex && hex[0]) {
			b.assignHex(hex);
		}
		return b;
	}

	// Split a ';'-joined string into its (non-empty) parts.
	inline std::vector<std::string> splitJoined(const char* joined) {
		std::vector<std::string> parts;
		if (!joined || !joined[0]) {
			return parts;
		}
		std::string s(joined);
		size_t start = 0;
		while (true) {
			size_t pos = s.find(';', start);
			parts.push_back(s.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
			if (pos == std::string::npos) {
				break;
			}
			start = pos + 1;
		}
		return parts;
	}

	// Decode a ';'-joined hex string into a vector of Bytes.
	inline Dacar::Vector<RNS::Bytes> bytesVecFromHex(const char* joined) {
		Dacar::Vector<RNS::Bytes> out;
		for (const auto& part : splitJoined(joined)) {
			RNS::Bytes b;
			b.assignHex(part.c_str());
			out.push_back(b);
		}
		return out;
	}

	// Parse a ';'-joined list of integers.
	inline std::vector<int> intVecFromJoined(const char* joined) {
		std::vector<int> out;
		for (const auto& part : splitJoined(joined)) {
			out.push_back(std::stoi(part));
		}
		return out;
	}

	// Fixture Ed25519 keys: private key handles from seeds.
	inline RNS::Cryptography::Ed25519PrivateKey::Ptr keyFromSeed(const RNS::Bytes& seed) {
		return RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(seed);
	}

	// Apply a fixture StateStep against a state using the given hashers
	// (index 0 = primary salt, 1.. = legacy salts). Mirrors the generator's
	// run_state(): apply() is the trusted local path (no signatures).
	inline bool applyStep(
		Dacar::StateVector& state,
		const DacarFixtures::StateStep& step,
		const std::vector<Dacar::NamespaceHasher>& hashers
	) {
		Dacar::Operation op(
			Dacar::Tuple::from_plaintext(
				step.object, step.relation,
				DacarTest::bytesFromHex(step.grantee_hex),
				DacarTest::bytesFromHex(step.issuer_hex),
				hashers[step.salt_index]
			),
			(Dacar::Action)step.action,
			step.hlc
		);
		return state.apply(op, step.now_ms);
	}

	// Build the hasher list for a fixture case (primary + legacy salts).
	inline std::vector<Dacar::NamespaceHasher> hashersFor(const char* salt_hex, const char* legacy_hex) {
		std::vector<Dacar::NamespaceHasher> hashers;
		hashers.emplace_back(DacarTest::bytesFromHex(salt_hex));
		for (const auto& b : DacarTest::bytesVecFromHex(legacy_hex)) {
			hashers.emplace_back(b);
		}
		return hashers;
	}

}
