"""§11.2 targeted Delta delivery + §11.3 Paper Messages over LXMF.

LXMF gives Dacar forward-secret, store-and-forward, point-to-point delivery of
Deltas to (possibly offline) nodes, alongside the public RFed broadcast. A Delta
(the §5.3 MessagePack payload) is embedded as the *content* of an LXMF message
whose title is the fixed discriminator ``dacar/sync/delta``; on receipt, only
messages with that title are fed to the shared
:class:`~dacar.delta.DeltaReceiver` (verify-on-ingest, §11.2.4).

§11.3 reuses the very same LXMF messages in LXMF's Paper Message encoding
(high-density QR), giving a fully air-gapped, optical channel: export produces
the encrypted paper bytes; import feeds them straight back through the router.

Requires the ``lxmf`` package (``import LXMF``), installed via the optional
``transport`` extra. The pure core never imports this module (see the purity
guard in ``tests/test_transport_lxmf.py``).

Typical use (receiver)::

    router = LXMF.LXMRouter(identity=me, storagepath=...)
    router.register_delivery_callback(
        LxmfDeltaDelivery(receiver=DeltaReceiver(state, key_resolver)).handle_delivery
    )

Typical use (sender, to a known target destination)::

    delivery = LxmfDeltaDelivery(router=router)
    delivery.deliver(delta_payload, target_destination, source=src)
"""

from __future__ import annotations

import LXMF

from dacar.delta import DeltaReceiver
from dacar.naming import LXMF_DELIVERY_TITLE

__all__ = ["LxmfDeltaDelivery", "lxmf_message_title", "lxmf_message_content"]


def lxmf_message_title(message) -> str:
    """Best-effort title of an LXMF message as text."""
    fn = getattr(message, "title_as_string", None)
    if callable(fn):
        try:
            return fn() or ""
        except Exception:
            pass
    t = getattr(message, "title", "")
    if isinstance(t, (bytes, bytearray)):
        return bytes(t).decode("utf-8", "replace")
    return t or ""


def lxmf_message_content(message) -> bytes:
    """Best-effort content of an LXMF message as bytes (the Delta payload)."""
    c = getattr(message, "content", b"")
    if isinstance(c, str):
        return c.encode("utf-8")
    if isinstance(c, (bytes, bytearray)):
        return bytes(c)
    return b""


class LxmfDeltaDelivery:
    """§11.2 targeted Delta delivery over LXMF; §11.3 Paper Message channel.

    Parameters
    ----------
    receiver:
        The shared :class:`DeltaReceiver` (state + key resolver). May be ``None``
        on a send-only node (then :meth:`handle_delivery` raises if called).
    router:
        Optional bound :class:`LXMF.LXMRouter` for :meth:`deliver` / :meth:`ingest_paper`.
    """

    #: Fixed title discriminator (spec §11.2). Aliases :data:`dacar.naming.LXMF_DELIVERY_TITLE`.
    TITLE = LXMF_DELIVERY_TITLE

    def __init__(self, receiver=None, router=None):
        self._receiver = receiver
        self._router = router

    # -- §11.2 send --------------------------------------------------------

    def make_message(self, delta_payload, destination, source=None, desired_method=None):
        """Build an LXMF message wrapping one §5.3 Delta payload (§11.2.2).

        The returned message is *not yet sent*; pass it to ``router.handle_outbound``
        (or call :meth:`deliver`) to queue it for the network.
        """
        return LXMF.LXMessage(
            destination,
            source,
            content=bytes(delta_payload),
            title=self.TITLE,
            desired_method=desired_method,
        )

    def deliver(self, delta_payload, destination, source=None, desired_method=None):
        """Build and queue a Delta for LXMF delivery via the bound router."""
        message = self.make_message(delta_payload, destination, source, desired_method)
        self._router.handle_outbound(message)
        return message

    # -- §11.2 receive -----------------------------------------------------

    def handle_delivery(self, message) -> bool:
        """LXMF delivery callback: filter by title, then apply the Delta (§11.2.4).

        Returns ``True`` if a Dacar Delta was applied, ``False`` otherwise (wrong
        title, or a malformed/forged payload -- which
        :meth:`DeltaReceiver.apply_payload` swallows so a bad message can never
        crash the transport). Non-Dacar messages are passed through untouched.
        """
        if lxmf_message_title(message) != self.TITLE:
            return False
        if self._receiver is None:
            raise RuntimeError("LxmfDeltaDelivery.handle_delivery requires a DeltaReceiver")
        return self._receiver.apply_payload(lxmf_message_content(message))

    # -- §11.3 Paper Messages (air-gapped / optical) ----------------------

    def make_paper_message(self, delta_payload, destination, source=None):
        """Build a §11.3 Paper Message (QR-encodable) wrapping one Delta.

        Same wrapping as :meth:`make_message` but with LXMF's ``PAPER`` delivery
        method, so :attr:`LXMessage.paper_packed` holds the encrypted bytes to
        render as a high-density QR code. Raises if the Delta exceeds
        ``LXMessage.PAPER_MDU``.
        """
        message = self.make_message(
            delta_payload, destination, source, desired_method=LXMF.LXMessage.PAPER
        )
        message.pack()  # sets message.paper_packed (destination_hash + encrypted payload)
        return message

    @staticmethod
    def paper_bytes(message) -> bytes:
        """The encrypted Paper Message bytes ready for QR rendering (§11.3).

        Raises ``ValueError`` if *message* is not a packed Paper Message.
        """
        packed = getattr(message, "paper_packed", None)
        if not packed:
            raise ValueError("message is not a packed Paper Message (paper_packed is empty)")
        return bytes(packed)

    def ingest_paper(self, paper_bytes):
        """Feed a scanned Paper Message back through the bound router (§11.3).

        The router decrypts it (it must own the delivery Identity) and routes the
        recovered LXMF message to the registered delivery callback
        (:meth:`handle_delivery`). Returns the router's propagation result.
        """
        return self._router.lxmf_propagation(bytes(paper_bytes), is_paper_message=True)
