/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Hlc.h"

#include "microReticulum/Utilities/OS.h"

#include <stdexcept>

using namespace Dacar;

/*static*/ uint64_t Dacar::pack(uint64_t physical_ms, uint64_t logical) {
	if (physical_ms > MAX_PHYSICAL) {
		throw std::invalid_argument("physical_ms must fit in 48 bits");
	}
	if (logical > MAX_LOGICAL) {
		throw std::invalid_argument("logical must fit in 16 bits");
	}
	return (physical_ms << LOGICAL_BITS) | logical;
}

/*static*/ std::pair<uint64_t, uint64_t> Dacar::unpack(uint64_t hlc) {
	return {(hlc >> LOGICAL_BITS), (hlc & LOGICAL_MASK)};
}

/*static*/ uint64_t Dacar::physical_now_ms() {
	// RNS::OS::ltime() is epoch milliseconds on native platforms and
	// millis()-since-boot plus the (persisted, provisionable) time offset on
	// Arduino targets — the same clock microReticulum itself uses, so HLCs
	// track RNS's notion of wall time. On MCUs without a sane offset the
	// clock is boot-relative; §12's ±24h future-skew check then relies on a
	// roughly sane wall clock (work doc #16, "Clock").
	return RNS::Utilities::OS::ltime();
}

uint64_t Clock::now() {
	uint64_t phys = physical_now_ms();
	if (phys > _last_ms) {
		_last_ms = phys;
		_logical = 0;
	}
	else {
		if (_logical >= MAX_LOGICAL) {
			throw std::overflow_error("HLC logical counter exhausted for this millisecond");
		}
		_logical += 1;
	}
	return pack(_last_ms, _logical);
}

uint64_t Clock::observe(uint64_t remote_hlc) {
	auto [rphys, rlog] = unpack(remote_hlc);
	uint64_t phys = physical_now_ms();
	if (phys > _last_ms && phys > rphys) {
		_last_ms = phys;
		_logical = 0;
	}
	else if (rphys > _last_ms) {
		_last_ms = rphys;
		if (rlog >= MAX_LOGICAL) {
			throw std::overflow_error("HLC logical counter exhausted absorbing remote HLC");
		}
		_logical = rlog + 1;
	}
	else if (_last_ms > rphys) {
		if (_logical >= MAX_LOGICAL) {
			throw std::overflow_error("HLC logical counter exhausted for this millisecond");
		}
		_logical += 1;
	}
	else { // equal physical timestamps
		uint64_t m = (_logical > rlog) ? _logical : rlog;
		if (m >= MAX_LOGICAL) {
			throw std::overflow_error("HLC logical counter exhausted for this millisecond");
		}
		_logical = m + 1;
	}
	return pack(_last_ms, _logical);
}
