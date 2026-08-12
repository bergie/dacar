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

from typing import List, Optional

from dacar import serialization
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
        log_rejections: bool = False,
    ) -> bool:
        """Apply one wire-format Delta.

        Returns ``True`` iff the payload decoded, authenticated, and was applied
        to the CRDT. Malformed payloads are swallowed (return ``False``) — a
        transport callback must never crash on arbitrary bytes. Signature and
        CRDT-level rejection (unknown Issuer, bad sig, stale/future) is
        delegated to :meth:`StateVector.ingest`.

        If ``log_rejections`` is True, rejections are printed to stderr for
        debugging (useful during sync to identify invalid deltas).
        """
        try:
            operation = Operation.from_payload(payload)
        except (ValueError, TypeError) as e:
            if log_rejections:
                import sys
                print(f"dacar: rejected malformed delta: {e}", file=sys.stderr)
            return False  # malformed -> drop silently
        
        # Check if issuer is known before attempting state ingest
        issuer_hash = operation.issuer
        keyset = self._resolver(issuer_hash)
        if keyset is None:
            if log_rejections:
                import sys
                print(f"dacar: rejected delta: unknown issuer {issuer_hash.hex()[:16]}... (not in keyring or RNS)", file=sys.stderr)
            return False
        
        result = self._state.ingest(
            operation, self._resolver, now_ms=now_ms, max_future_ms=max_future_ms
        )
        if log_rejections and not result:
            import sys
            # Check if it was a timestamp issue
            from dacar.hlc import unpack
            physical, _ = unpack(operation.hlc)
            now = now_ms if now_ms is not None else physical_now_ms()
            horizon = self._state.deletion_horizon_ms
            
            if physical < now - horizon:
                print(f"dacar: rejected delta: timestamp is stale (too old by {(now - physical) / 1000:.0f}s, horizon {horizon / 1000:.0f}s)", file=sys.stderr)
            else:
                # Signature verification failed
                print(f"dacar: rejected delta: signature verification failed for issuer {issuer_hash.hex()[:16]}...", file=sys.stderr)
        return result

    def apply_payloads(
        self,
        payload: bytes,
        *,
        now_ms: Optional[int] = None,
        max_future_ms: Optional[int] = DEFAULT_MAX_FUTURE_MS,
    ) -> int:
        """Authenticate and apply a *batch* of Deltas (§11.1, §11.2.4).

        The secure alternative to ``StateVector.merge()`` for network sync.
        ``payload`` is a MessagePack array of §5.3 Operation payloads
        (``serialization.packb([op_a.to_payload(), op_b.to_payload(), ...])``);
        each element is decoded and run through :meth:`apply_payload`, i.e. it
        is independently Ed25519/threshold-authenticated before it may touch
        state. A single forged, stale (§9), or future-skewed (§12) element is
        dropped without affecting the rest of the batch.

        Returns the number of Deltas authenticated *and* applied. A malformed
        outer payload (not a MessagePack array, undecodable) yields ``0`` and
        is swallowed, so a transport callback can never crash on arbitrary
        bytes — exactly like :meth:`apply_payload`.

        .. warning::
           This is the *only* safe entry point for full-state / bulk
           convergence received over the network. ``StateVector.merge()`` /
           ``StateVector.from_payload()`` are trusted-local snapshot primitives
           that perform **no** signature verification and **must not** be fed
           network bytes.
        """
        try:
            items = serialization.unpackb(payload)
        except (ValueError, TypeError):
            return 0  # malformed outer payload -> drop silently
        if not isinstance(items, list):
            return 0
        applied = 0
        for item in items:
            if not isinstance(item, (bytes, bytearray)):
                continue  # skip non-bin elements defensively
            if self.apply_payload(
                bytes(item), now_ms=now_ms, max_future_ms=max_future_ms
            ):
                applied += 1
        return applied

    @staticmethod
    def pack_payloads(operation_payloads: List[bytes]) -> bytes:
        """Encode a list of §5.3 Operation payloads as a batch (§11.1).

        Inverse of :meth:`apply_payloads`: ``serialization.packb([...])`` of
        already-signed Operation payload byte-strings, suitable for publishing
        as one bulk sync message. Convenience wrapper so callers need not
        import :mod:`dacar.serialization` directly.
        """
        return serialization.packb([bytes(p) for p in operation_payloads])
