"""Optional RNS-dependent transport adapters for Dacar (spec §8, §11).

Importing this subpackage requires the ``rns`` package (Reticulum Network
Stack). The pure ``dacar`` core has no such dependency: ``import dacar`` does
not import this subpackage.
"""

from dacar.transport.rns_challenge import (  # noqa: F401
    CHALLENGE_REQUEST_PATH,
    DEFAULT_CHALLENGE_TIMEOUT,
    DEFAULT_ESTABLISH_TIMEOUT,
    DEFAULT_TIMEOUT_GRACE,
    RnsChallengeServer,
    RnsLinkTransport,
    challenge_request_handler,
    establish_link,
)
from dacar.transport.rns_identity import RnsIdentityResolver  # noqa: F401

__all__ = [
    "CHALLENGE_REQUEST_PATH",
    "DEFAULT_CHALLENGE_TIMEOUT",
    "DEFAULT_ESTABLISH_TIMEOUT",
    "DEFAULT_TIMEOUT_GRACE",
    "RnsChallengeServer",
    "RnsLinkTransport",
    "challenge_request_handler",
    "establish_link",
    "RnsIdentityResolver",
]

# §11.2/§11.3 LXMF adapters need the ``lxmf`` package. Import gracefully so a
# partial install (only ``rns``) still exposes the §8 symbols above.
try:
    from dacar.transport.lxmf_sync import (  # noqa: F401
        LxmfDeltaDelivery,
        lxmf_message_content,
        lxmf_message_title,
    )
except ImportError:  # pragma: no cover - exercised only without lxmf installed
    pass
else:
    __all__ += ["LxmfDeltaDelivery", "lxmf_message_content", "lxmf_message_title"]
