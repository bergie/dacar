/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Namespace Label Privacy (Dacar spec §3.3).
 *
 * To prevent label disclosure over public transports, Dacar never transmits
 * or stores Object or Relation strings in plaintext. Every string label is
 * hashed with HMAC-SHA256, keyed with the node's Privacy Salt, and strictly
 * truncated to the first 16 bytes.
 *
 * Objects are split by ':' into segments, each hashed individually. The
 * terminal suffix wildcard '*' is stripped *before* hashing and carried
 * instead as a boolean flag on the Tuple (§3.3).
 *
 * WARNING (§3.3): an unset Privacy Salt defaults to 32 null bytes, which is
 * *fail-open on privacy* — the hashes become trivially dictionary-attackable.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Containers.h"
#include "microReticulum/Bytes.h"
#include "microReticulum/Cryptography/HMAC.h"

#include <string>
#include <utility>
#include <vector>

namespace Dacar {

	// Object segments are delimited by this character (§3.3).
	constexpr const char DELIMITER = ':';

	// The terminal suffix wildcard character (§3.3).
	constexpr const char WILDCARD = '*';

	// Privacy Salts are 32 bytes of cryptographically secure random data.
	constexpr size_t SALT_SIZE = 32;

	// All label hashes (and RNS.Identity hashes) are 16 bytes.
	constexpr size_t HASH_SIZE = 16;

	// Maximum number of concurrently-configured Legacy Salts (§10.2).
	constexpr size_t MAX_LEGACY_SALTS = 2;

	// The fail-open default salt when none is configured (§3.3 WARNING):
	// 32 null bytes.
	const RNS::Bytes& DEFAULT_SALT();

	/*
	HMAC-SHA256(salt, message) truncated to 16 bytes (§3.3 hashing primitive).
	*/
	RNS::Bytes hmac16(const RNS::Bytes& salt, const RNS::Bytes& message);

	/*
	Split an object string into its colon-delimited segments. Matches Python
	str.split(':'): an empty string yields a single empty segment.
	*/
	std::vector<std::string> split(const std::string& object_id);

	class NamespaceHasher {

	public:
		/*
		Construct a hasher bound to exactly one salt (§3.3). The default
		argument binds the fail-open null salt; see DEFAULT_SALT().

		Throws std::invalid_argument if salt is not exactly SALT_SIZE bytes.
		*/
		explicit NamespaceHasher(const RNS::Bytes& salt = DEFAULT_SALT());
		~NamespaceHasher() = default;

		NamespaceHasher(const NamespaceHasher&) = default;
		NamespaceHasher& operator = (const NamespaceHasher&) = default;

		const RNS::Bytes& salt() const { return _salt; }

		/*
		Hash a whole relation string (§3.3). Explicit denies include the '-'
		prefix in the string itself, exactly like every other label.
		*/
		RNS::Bytes hash_relation(const std::string& relation) const;

		/*
		Return (segment_hashes, wildcard) for an object string (§3.3):

		  "*"           -> ({}, true)            (root wildcard)
		  "sensor:*"    -> ({h(sensor)}, true)
		  "sensor:wind" -> ({h(sensor), h(wind)}, false)

		A non-terminal '*' is treated as a literal segment.
		*/
		std::pair<Vector<RNS::Bytes>, bool> hash_object(const std::string& object_id) const;

		/*
		A 16-byte tag identifying this salt (§8.3 salt_id_tag): HMAC-SHA256 of
		"dacar.salt.id" keyed with the salt, truncated to 16 bytes. An Authority
		matches hypothesized requests to the salt that produced them without
		ever exchanging the salt itself.
		*/
		RNS::Bytes id_tag() const;

		bool operator == (const NamespaceHasher& other) const { return _salt == other._salt; }
		bool operator != (const NamespaceHasher& other) const { return _salt != other._salt; }

	private:
		RNS::Bytes _salt;

	};

	/*
	Does a Tuple's hashed Object cover a request's exact hashed Object? (§3.3)

	A match succeeds if the Tuple is wildcarded and its hashes are a *prefix*
	of the request hashes, or if the two hash arrays are identical. Request
	hashes are always exact (a request never carries its own wildcard).
	*/
	bool covers(
		const Vector<RNS::Bytes>& tuple_hashes,
		bool wildcard,
		const Vector<RNS::Bytes>& request_hashes
	);

}
