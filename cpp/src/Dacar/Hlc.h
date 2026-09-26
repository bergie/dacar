/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Hybrid Logical Clocks (Dacar spec §5.1).
 *
 * An HLC is packed into a single 64-bit unsigned integer, transmitted
 * big-endian on the wire:
 *
 *   - high 48 bits: physical time (Unix epoch, milliseconds)
 *   - low 16 bits : logical counter
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include <stdint.h>

#include <utility>

namespace Dacar {

	constexpr int PHYSICAL_BITS = 48;
	constexpr int LOGICAL_BITS = 16;

	constexpr uint64_t LOGICAL_MASK = 0xFFFF;                 // 2^16 - 1
	constexpr uint64_t MAX_PHYSICAL = 0x0000FFFFFFFFFFFF;     // 2^48 - 1
	constexpr uint64_t MAX_LOGICAL = LOGICAL_MASK;            // 2^16 - 1
	constexpr uint64_t MAX_HLC = 0xFFFFFFFFFFFFFFFF;          // 2^64 - 1

	/*
	Pack a physical timestamp (ms) and logical counter into one uint64 HLC.
	Throws std::invalid_argument if either component exceeds its bit width.
	*/
	uint64_t pack(uint64_t physical_ms, uint64_t logical);

	/*
	Unpack an HLC into (physical_ms, logical).
	Throws std::invalid_argument if the HLC exceeds 64 bits (always false for
	uint64_t; retained for parity with the reference implementations).
	*/
	std::pair<uint64_t, uint64_t> unpack(uint64_t hlc);

	/*
	Current wall-clock time in milliseconds since the Unix epoch.
	*/
	uint64_t physical_now_ms();

	class Clock {

	public:
		Clock(uint64_t last_ms = 0, uint64_t logical = 0)
			: _last_ms(last_ms), _logical(logical)
		{}
		~Clock() = default;

		uint64_t last_ms() const { return _last_ms; }
		uint64_t logical() const { return _logical; }

		/*
		Advance the clock from a local event and return the new HLC. Produces
		monotonically non-decreasing HLCs. Throws std::overflow_error if the
		logical counter saturates within a single millisecond.
		*/
		uint64_t now();

		/*
		Absorb a remote HLC observed during sync, return the new local HLC,
		preserving the happens-before relation.
		*/
		uint64_t observe(uint64_t remote_hlc);

	private:
		uint64_t _last_ms;
		uint64_t _logical;

	};

}
