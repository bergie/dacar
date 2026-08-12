"""Smoketests for the Dacar compact inner format (§11.1, work doc #10).

The compact format reuses the RTID prelude but carries the raw §5.3 Delta in
place of the LXMF tail, EC-encrypted to the derived channel identity. These
tests cover the pure codec (:func:`wrap_dacar_delta` /
:func:`unwrap_dacar_delta`): round-trip, magic verification, MTU sizing, and
cross-checks against the LXMF envelope it replaces. The transport-level
verify-on-ingest routing is covered by :mod:`tests.test_transport_rfed`.

Requires the ``rns`` package (``dacar[transport]`` extra); no ``lxmf`` needed.
"""

from __future__ import annotations
import unittest

import RNS

from dacar.rfed.blob import (
    MAGIC_RTID,
    PRELUDE_LENGTH,
    unwrap_dacar_delta,
    wrap_dacar_delta,
)
from dacar.rfed.channel import derive_channel
from dacar.rfed.constants import HASH_LENGTH, PUBLIC_KEY_LENGTH
from dacar.naming import RFED_TOPIC

#: Default RNS path MTU (multi-hop, with stamp) the compact format must fit.
RNS_MTU = 500
#: A representative §5.3 Delta size (issuer+grantee+action+hlc+relation+seg+wildcard+sig).
TYPICAL_DELTA_LEN = 170


def _delta(size: int = TYPICAL_DELTA_LEN) -> bytes:
    """A deterministic placeholder Delta of the given byte length."""
    return bytes((i * 7 + 3) & 0xFF for i in range(size))


class WrapDacarDeltaTest(unittest.TestCase):
    def setUp(self):
        self.channel_identity, self.channel_hash = derive_channel(RFED_TOPIC)
        self.sender = RNS.Identity()

    def test_round_trips_a_typical_delta(self):
        delta = _delta()
        wrapped = wrap_dacar_delta(
            channel_identity=self.channel_identity,
            sender_identity=self.sender,
            delta=delta,
        )
        # Framing: channel_hash(16) ‖ inner_blob ‖ (no stamp when cost is None).
        self.assertEqual(wrapped.channel_hash, bytes(self.channel_hash))
        self.assertEqual(
            len(wrapped.rfed_payload), HASH_LENGTH + len(wrapped.inner_blob)
        )
        self.assertIsNone(wrapped.stamp)

        decoded = unwrap_dacar_delta(
            inner_blob=wrapped.inner_blob, channel_identity=self.channel_identity
        )
        self.assertEqual(decoded.delta, delta)
        self.assertEqual(decoded.sender_pub, self.sender.get_public_key())
        # The recovered sender identity has the same hash as the publisher.
        self.assertEqual(decoded.sender_identity.hash, self.sender.hash)

    def test_plaintext_layout_is_magic_then_pub_then_delta(self):
        """The inner plaintext must be RTID ‖ sender_pub(64) ‖ delta (§11.1)."""
        delta = _delta()
        wrapped = wrap_dacar_delta(
            channel_identity=self.channel_identity,
            sender_identity=self.sender,
            delta=delta,
        )
        plaintext = bytes(self.channel_identity.decrypt(wrapped.inner_blob))
        self.assertEqual(plaintext[: len(MAGIC_RTID)], MAGIC_RTID)
        self.assertEqual(
            plaintext[len(MAGIC_RTID) : PRELUDE_LENGTH],
            self.sender.get_public_key(),
        )
        self.assertEqual(plaintext[PRELUDE_LENGTH:], delta)
        self.assertEqual(len(self.sender.get_public_key()), PUBLIC_KEY_LENGTH)

    def test_typical_delta_fits_under_rns_mtu_without_stamp(self):
        wrapped = wrap_dacar_delta(
            channel_identity=self.channel_identity,
            sender_identity=self.sender,
            delta=_delta(),
            stamp_cost=None,
        )
        self.assertLessEqual(
            len(wrapped.rfed_payload), RNS_MTU,
            f"{len(wrapped.rfed_payload)}B > {RNS_MTU}B MTU without stamp",
        )

    def test_typical_delta_fits_under_rns_mtu_with_stamp(self):
        """With a low PoW cost (and thus a stamp) it must still fit MTU."""
        wrapped = wrap_dacar_delta(
            channel_identity=self.channel_identity,
            sender_identity=self.sender,
            delta=_delta(),
            stamp_cost=4,
        )
        self.assertIsNotNone(wrapped.stamp)
        self.assertEqual(len(wrapped.stamp), 32)
        self.assertLessEqual(
            len(wrapped.rfed_payload), RNS_MTU,
            f"{len(wrapped.rfed_payload)}B > {RNS_MTU}B MTU with stamp",
        )

    def test_unwrap_rejects_wrong_channel(self):
        """An inner_blob encrypted to channel A won't decrypt under channel B."""
        delta = _delta()
        other_identity, _ = derive_channel("dacar.policy.other")
        wrapped = wrap_dacar_delta(
            channel_identity=self.channel_identity,
            sender_identity=self.sender,
            delta=delta,
        )
        with self.assertRaises(ValueError):
            unwrap_dacar_delta(inner_blob=wrapped.inner_blob, channel_identity=other_identity)

    def test_unwrap_rejects_bad_magic(self):
        """A plaintext without the RTID magic is refused (EC is fine, format wrong)."""
        # Encrypt a plaintext with a bad magic directly to the channel.
        bad = b"XXXX" + self.sender.get_public_key() + _delta()
        inner_blob = bytes(self.channel_identity.encrypt(bad))
        with self.assertRaises(ValueError):
            unwrap_dacar_delta(
                inner_blob=inner_blob, channel_identity=self.channel_identity
            )

    def test_unwrap_rejects_short_plaintext(self):
        """A plaintext shorter than the prelude is refused."""
        short = self.channel_identity.encrypt(MAGIC_RTID + b"\x00")
        with self.assertRaises(ValueError):
            unwrap_dacar_delta(
                inner_blob=bytes(short), channel_identity=self.channel_identity
            )


if __name__ == "__main__":
    unittest.main()
