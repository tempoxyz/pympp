"""Persona KYC for :mod:`mpp.identity` (mppx `extensions/identity/persona`).

Start a Persona inquiry for a person's wallet, then require an approved inquiry on paid
requests, looked up with your Persona API key by the inquiry's reference ID::

    from mpp.extensions.identity import persona

    kyc = persona.server.create(api_key=os.environ["PERSONA_API_KEY"], template_id="itmpl_...")

    # Your onboarding endpoint: prove the wallet, then start an inquiry for its DID.
    reference_id = await persona.server.verify_wallet(
        address=address, chain_id=4217, message=message, signature=signature, nonce=nonce
    )
    started = await kyc.start_inquiry(reference_id)  # started.url: Persona's hosted flow

    check = kyc.payment_check(
        reference_id=lambda input: session_wallet(input.request),  # a DID from verify_wallet
        onboarding="https://api.example/kyc",
        cache=MemoryStore(),
    )
    handler = mpp.charge(amount="1", identity=identity.Route(payment=check))

The server module needs no extra. :func:`server.verify_wallet`'s default EOA signature check
needs ``eth-account``: ``pip install "pympp[evm]"``.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from datetime import datetime
from types import ModuleType
from typing import TYPE_CHECKING, Literal, TypeAlias

InquiryStatus: TypeAlias = Literal[
    "created",
    "pending",
    "completed",
    "approved",
    "declined",
    "failed",
    "expired",
    "needs_review",
]
"""Status of a Persona inquiry."""

TYPE = "kyc"
"""Identity type a payment check lists in the 402's ``Identity-Required`` header."""
ISSUER = "https://api.withpersona.com"
"""Issuer a payment check lists in ``Identity-Required``: Persona's API origin."""
API_URL = "https://api.withpersona.com"
"""Persona API origin."""
INQUIRIES_PATH = "/api/v1/inquiries"
"""Persona API path for inquiries."""
API_VERSION = "2023-01-05"
"""Persona API version sent in ``Persona-Version`` by default."""
STATUSES: tuple[InquiryStatus, ...] = ("approved",)
"""Inquiry statuses accepted by default: approved by your Persona workflow or reviewer."""
REL = "kyc"
"""Link relation of the onboarding URL sent with a rejection."""
TIMEOUT = 5.0
"""Seconds before a Persona API call is abandoned as ``unavailable``."""
CACHE_TTL = 300
"""Seconds an approval stays cached when a ``cache`` is set."""
MAX_PAGES = 3
"""Most inquiry pages read per lookup."""


@dataclass(frozen=True, slots=True)
class VerifiedInquiry:
    """A payer with an accepted Persona inquiry.

    - ``inquiry_id``: Persona inquiry ID, such as ``inq_...``.
    - ``reference_id``: the reference ID the inquiry was created with, which the check matched.
    - ``status``: the inquiry status, such as ``approved``.
    - ``verified_at``: when the inquiry was decisioned, or completed if it never was.
    """

    inquiry_id: str
    reference_id: str
    status: InquiryStatus
    verified_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class StartedInquiry:
    """A started Persona inquiry: its ID and a one-time link to Persona's hosted flow."""

    inquiry_id: str
    url: str


def did(address: str, chain_id: int | str, namespace: str = "eip155") -> str:
    """Return the reference ID for a wallet: its ``did:pkh`` DID, the form a Credential's
    ``source`` takes.

    EVM (``eip155``) addresses are lowercased, since they are case-insensitive; addresses on
    other chains, such as base58 Solana addresses, are kept as they are::

        did("0xAb...", 4217)  # "did:pkh:eip155:4217:0xab..."
    """
    return normalize(f"did:pkh:{namespace}:{chain_id}:{address}")


def normalize(value: str) -> str:
    """Normalize a ``did:pkh`` DID: lowercase the scheme and an EVM address, keep the rest.

    Anything that is not a five-part ``did:pkh`` value is returned unchanged.
    """
    parts = value.split(":")
    if len(parts) != 5 or parts[0].lower() != "did" or parts[1].lower() != "pkh":
        return value
    namespace = parts[2].lower()
    address = parts[4].lower() if namespace == "eip155" else parts[4]
    return ":".join(("did", "pkh", namespace, parts[3], address))


_SUBMODULES = ("server",)

if TYPE_CHECKING:
    from mpp.extensions.identity.persona import server


def __getattr__(name: str) -> ModuleType:
    if name not in _SUBMODULES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f"{__name__}.{name}")
    globals()[name] = module
    return module


__all__ = [
    "API_URL",
    "API_VERSION",
    "CACHE_TTL",
    "INQUIRIES_PATH",
    "ISSUER",
    "MAX_PAGES",
    "REL",
    "STATUSES",
    "TIMEOUT",
    "TYPE",
    "InquiryStatus",
    "StartedInquiry",
    "VerifiedInquiry",
    "did",
    "normalize",
    "server",
]
