"""Hybrid Logical Clocks (Dacar spec §5.1).

An HLC is packed into a single 64-bit unsigned integer, transmitted
big-endian on the wire:

  * high 48 bits: physical time (Unix epoch, milliseconds)
  * low 16 bits : logical counter
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Tuple as _Tuple

PHYSICAL_BITS = 48
LOGICAL_BITS = 16

LOGICAL_MASK = (1 << LOGICAL_BITS) - 1  # 0xFFFF
MAX_PHYSICAL = (1 << PHYSICAL_BITS) - 1  # 2^48 - 1
MAX_LOGICAL = LOGICAL_MASK  # 2^16 - 1
MAX_HLC = (1 << (PHYSICAL_BITS + LOGICAL_BITS)) - 1  # 2^64 - 1


def pack(physical_ms: int, logical: int) -> int:
    """Pack a physical timestamp (ms) and logical counter into one uint64 HLC."""
    if not 0 <= physical_ms <= MAX_PHYSICAL:
        raise ValueError(f"physical_ms must fit in {PHYSICAL_BITS} bits, got {physical_ms}")
    if not 0 <= logical <= MAX_LOGICAL:
        raise ValueError(f"logical must fit in {LOGICAL_BITS} bits, got {logical}")
    return (physical_ms << LOGICAL_BITS) | logical


def unpack(hlc: int) -> _Tuple[int, int]:
    """Unpack an HLC into ``(physical_ms, logical)``."""
    if not 0 <= hlc <= MAX_HLC:
        raise ValueError(f"hlc must fit in 64 bits, got {hlc}")
    return (hlc >> LOGICAL_BITS, hlc & LOGICAL_MASK)


def physical_now_ms() -> int:
    """Current wall-clock time in milliseconds since the Unix epoch."""
    return time.time_ns() // 1_000_000


@dataclass
class Clock:
    """A process-local Lamport-style HLC generator.

    Produces monotonically non-decreasing HLCs and can absorb remote HLCs
    observed during sync while preserving the happens-before relation.
    """

    _last_ms: int = 0
    _logical: int = 0

    def now(self) -> int:
        """Advance the clock from a local event and return the new HLC."""
        phys = physical_now_ms()
        if phys > self._last_ms:
            self._last_ms = phys
            self._logical = 0
        else:
            self._logical += 1
        return pack(self._last_ms, self._logical)

    def observe(self, remote_hlc: int) -> int:
        """Absorb a remote HLC observed during sync, return the new local HLC."""
        rphys, rlog = unpack(remote_hlc)
        phys = physical_now_ms()
        if phys > self._last_ms and phys > rphys:
            self._last_ms = phys
            self._logical = 0
        elif rphys > self._last_ms:
            self._last_ms = rphys
            self._logical = rlog + 1
        elif self._last_ms > rphys:
            self._logical += 1
        else:  # equal physical timestamps
            self._logical = max(self._logical, rlog) + 1
        return pack(self._last_ms, self._logical)
