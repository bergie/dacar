/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Container aliases for the Dacar C++ port.
 *
 * MCUs are the primary target (ESP32, nRF52 — see the microReticulum
 * firmware), so every container that stores Dacar's Bytes payloads (hashes,
 * signatures, CRDT rows) uses microReticulum's ContainerAllocator. On
 * constrained builds that routes Dacar's allocations through the same TLSF
 * pool (or PSRAM pool) the rest of the RNS stack uses, so policy state
 * shares one bounded, observable memory budget instead of fragmenting the
 * system heap (work doc #16, "MCU-specific design considerations").
 *
 * Transient containers of non-Bytes types (e.g. lists of NamespaceHasher)
 * keep plain std:: containers.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "microReticulum/Utilities/Memory.h"

#include <functional>
#include <map>
#include <set>
#include <vector>

namespace Dacar {

	// microReticulum's pool-backed allocator (falls back to the global heap
	// where no pool is configured — see Utilities/Memory.cpp).
	template <typename T>
	using ContainerAllocator = RNS::Utilities::Memory::ContainerAllocator<T>;

	// Vector of blobs (hashes, signatures, payloads).
	template <typename T>
	using Vector = std::vector<T, ContainerAllocator<T>>;

	// Map keyed or valued with blobs (CRDT index, keyring, engine memo).
	template <typename Key, typename Value>
	using Map = std::map<
		Key,
		Value,
		std::less<Key>,
		ContainerAllocator<std::pair<const Key, Value>>
	>;

	// Set of blobs (root trust anchors).
	template <typename Key>
	using Set = std::set<Key, std::less<Key>, ContainerAllocator<Key>>;

}
