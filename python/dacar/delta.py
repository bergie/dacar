"""Transport-agnostic Delta receive boundary (spec §11.2.4).

Every transport — RFed (§11.1), LXMF store-and-forward (§11.2), and optical
Paper Messages (§11.3) — funnels incoming bytes through one identical path:
decode the §5.3 Operation payload, authenticate it via verify-on-ingest
(§5.2 / §11.2.4), and merge it into the CRDT. :class:`DeltaReceiver` is that
shared boundary. Malformed or unauthenticated Deltas are dropped silently
rather than propagated into state or crashing a transport callback.

This keeps the (optional) transport adapters thin: an adapter only has to
hand received bytes to :meth:`DeltaReceiver.apply_payload`, regardless of
whether they arrived over RFed, LXMF, or a scanned QR code.
"""

from __future__ import annotations

from typing import Optional

from dacar.crdt import DEFAULT_MAX_FUTURE_MS, StateVector
from dacar.operation import Operation
from dacar.verifier import KeyResolver


class DeltaReceiver:
    """Decode -> verify -> apply incoming Delta payloads (§11.2.4).

    Bound to one :class:`StateVector` and :data:`~dacar.verifier.KeyResolver`;
    every transport adapter shares a single instance so the receive policy
    (graceful malformed-drop, verify-on-ingest) lives in one place.
    """

    def __init__(self, state: StateVector, key_resolver: KeyResolver) -> None:
        self._state = state
        self._resolver = key_resolver

    def apply_payload(
        self,
        payload: bytes,
        *,
        now_ms: Optional[int] = None,
        max_future_ms: Optional[int] = DEFAULT_MAX_FUTURE_MS,
    ) -> bool:
        """Apply one wire-format Delta.

        Returns ``True`` iff the payload decoded, authenticated, and was applied
        to the CRDT. Malformed payloads are swallowed (return ``False``) — a
        transport callback must never crash on arbitrary bytes. Signature and
        CRDT-level rejection (unknown Issuer, bad sig, stale/future) is
        delegated to :meth:`StateVector.ingest`.
        """
        try:
            operation = Operation.from_payload(payload)
        except (ValueError, TypeError):
            return False  # malformed -> drop silently
        return self._state.ingest(
            operation, self._resolver, now_ms=now_ms, max_future_ms=max_future_ms
        )
