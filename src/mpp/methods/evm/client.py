"""EVM payment method (mppx ``evm`` server and client methods)."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any, TypedDict

from eth_utils.address import to_checksum_address

from mpp import Challenge, Credential
from mpp._units import parse_units
from mpp.methods import CanOfferFn, PaymentSuccessHandler
from mpp.methods.evm._eip3009 import (
    authorization_domain,
    challenge_hash,
    sign_authorization,
    to_source,
)
from mpp.methods.evm.assets import EvmAsset
from mpp.methods.evm.intents import CREDENTIAL_TYPE, ChargeIntent, SettleFn
from mpp.x402.facilitator import Facilitator, resolve_facilitator

if TYPE_CHECKING:
    from mpp.server.intent import Intent, VerifiableIntent

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
DEFAULT_VALIDITY_SECONDS = 300


class AuthorizationConfig(TypedDict):
    """EIP-712 domain of a token's EIP-3009 authorizations."""

    name: str
    version: str


@dataclass
class EvmMethod:
    """EVM payment method for HTTP 402 authentication.

    Serves native Payment-auth ``evm/charge`` challenges and, through the same
    intent, x402 ``exact`` clients. Build it with :func:`evm`.
    """

    name: str = "evm"
    currency: str = ""
    chain_id: int = 0
    decimals: int = 6
    domain_name: str = ""
    domain_version: str = ""
    recipient: str | None = None
    account: Any = None
    max_amount: int | None = None
    can_offer: CanOfferFn | None = None
    on_payment_success: PaymentSuccessHandler | None = None
    _intents: dict[str, Intent | VerifiableIntent] = field(default_factory=dict)

    @property
    def intents(self) -> dict[str, Intent | VerifiableIntent]:
        """Intents this method serves (``charge``)."""
        return self._intents

    # -- server ----------------------------------------------------------

    def transform_request(
        self, request: dict[str, Any], credential: Credential | None
    ) -> dict[str, Any]:
        """Normalize a charge request to mppx's ``evm/charge`` wire shape."""
        del credential
        currency = request.get("currency")
        if not isinstance(currency, str) or currency.lower() != self.currency.lower():
            raise ValueError(f"EVM charge currency must be the method's currency {self.currency}")
        recipient = request.get("recipient")
        if not isinstance(recipient, str) or not _ADDRESS_RE.fullmatch(recipient):
            raise ValueError("EVM charge recipient must be an address")
        raw_details = request.get("methodDetails") or {}
        if not isinstance(raw_details, Mapping):
            raise ValueError("methodDetails must be an object")
        details = dict(raw_details)
        if details.get("splits"):
            raise ValueError("EVM charges do not support splits")
        if details.get("feePayer"):
            raise ValueError("EVM charges do not support fee_payer")
        details.pop("feePayer", None)
        details.pop("splits", None)
        chain_id = details.get("chainId", self.chain_id)
        if chain_id != self.chain_id:
            raise ValueError(f"EVM charge chain_id must be the method's chain ID {self.chain_id}")
        details["chainId"] = self.chain_id
        details["credentialTypes"] = [CREDENTIAL_TYPE]
        details["decimals"] = self.decimals
        return {
            **request,
            "currency": to_checksum_address(currency),
            "recipient": to_checksum_address(recipient),
            "methodDetails": details,
        }

    # -- client ----------------------------------------------------------

    def can_handle_challenge(self, challenge: Challenge) -> bool:
        """Return whether this method can sign the challenge's charge."""
        try:
            self._check_challenge(challenge)
        except ValueError:
            return False
        return True

    def _check_challenge(self, challenge: Challenge) -> dict[str, Any]:
        request = challenge.request
        details = request.get("methodDetails")
        if not isinstance(details, Mapping):
            raise ValueError("EVM challenge is missing methodDetails")
        if details.get("chainId") != self.chain_id:
            raise ValueError(f"EVM chain ID is not allowed: {details.get('chainId')}")
        currency = request.get("currency")
        if not isinstance(currency, str) or currency.lower() != self.currency.lower():
            raise ValueError(f"EVM currency is not allowed: {currency}")
        credential_types = details.get("credentialTypes")
        if not isinstance(credential_types, list) or CREDENTIAL_TYPE not in credential_types:
            raise ValueError("EVM authorization is not accepted by this challenge")
        if details.get("splits"):
            raise ValueError("EVM authorization does not support payment splits")
        amount = request.get("amount")
        recipient = request.get("recipient")
        if not isinstance(amount, str) or not amount.isdigit():
            raise ValueError("EVM challenge amount is malformed")
        if int(amount) == 0:
            # A zero-value authorization still signs the challenge realm into its
            # nonce; another host could relay it to the server that realm names.
            raise ValueError("EVM client does not sign zero-amount charges")
        if not isinstance(recipient, str) or not _ADDRESS_RE.fullmatch(recipient):
            raise ValueError("EVM challenge recipient is malformed")
        if self.max_amount is not None and int(amount) > self.max_amount:
            raise ValueError("EVM challenge amount exceeds max_amount")
        return request

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Sign a native ``evm/charge`` credential for a challenge."""
        if self.account is None:
            raise ValueError("No account configured for EVM credentials")
        request = self._check_challenge(challenge)
        if challenge.expires:
            expires = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
            valid_before = int(expires.timestamp())
        else:
            valid_before = int(time.time()) + DEFAULT_VALIDITY_SECONDS
        payer = to_checksum_address(self.account.address)
        payload: dict[str, Any] = {
            "type": CREDENTIAL_TYPE,
            "from": payer,
            "to": to_checksum_address(request["recipient"]),
            "value": request["amount"],
            "validAfter": "0",
            "validBefore": str(valid_before),
            "nonce": challenge_hash(challenge.id, challenge.realm),
        }
        payload["signature"] = sign_authorization(
            self.account,
            domain=authorization_domain(
                name=self.domain_name,
                version=self.domain_version,
                chain_id=self.chain_id,
                currency=request["currency"],
            ),
            payload=payload,
        )
        return Credential(
            challenge=challenge.to_echo(),
            payload=payload,
            source=to_source(address=payer, chain_id=self.chain_id),
        )


def evm(
    *,
    currency: EvmAsset | str,
    recipient: str | None = None,
    chain_id: int | None = None,
    decimals: int | None = None,
    authorization: AuthorizationConfig | None = None,
    facilitator: str | Facilitator | None = None,
    settle: SettleFn | None = None,
    max_timeout_seconds: int = 300,
    account: Any = None,
    max_amount: str | Decimal | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> EvmMethod:
    """Create an EVM payment method that charges with EIP-3009 authorizations.

    On a server, the method's ``charge`` intent serves both native MPP
    clients and x402 ``exact`` clients from the same endpoint, and settles
    through an x402 facilitator or a custom ``settle`` hook. On a client,
    pass ``account`` to sign native ``evm/charge`` credentials.

    Example:
        from mpp.methods.evm import BASE_USDC, evm
        from mpp.server import Mpp

        server = Mpp.create(
            method=evm(
                currency=BASE_USDC,
                recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                facilitator="https://facilitator.example.com",
            ),
        )

    Args:
        currency: A known :class:`EvmAsset`, or a token address together
            with ``chain_id``, ``decimals`` and ``authorization``.
        recipient: Address that receives payments (servers).
        chain_id: EVM chain ID. Inferred from a known asset.
        decimals: Token decimals. Inferred from a known asset.
        authorization: EIP-712 domain (``name``, ``version``) the token signs
            EIP-3009 authorizations with. Inferred from a known asset.
        facilitator: x402 facilitator URL or client that verifies and settles
            payments (servers).
        settle: Custom settlement hook used instead of a facilitator. It
            receives the verified authorization and returns its reference.
        max_timeout_seconds: x402 ``maxTimeoutSeconds`` offered to clients.
        account: eth-account ``LocalAccount`` that signs credentials (clients).
        max_amount: Largest display-unit amount the client pays (clients).
        can_offer: Optional callback deciding whether to offer a request.
        on_payment_success: Optional callback for this method's payments.
    """
    if isinstance(currency, EvmAsset):
        if chain_id is not None and chain_id != currency.chain_id:
            raise ValueError(
                f"currency is on chain ID {currency.chain_id}, not chain_id={chain_id}"
            )
        address = currency.address
        resolved_chain_id = currency.chain_id
        resolved_decimals = currency.decimals if decimals is None else decimals
        domain: AuthorizationConfig = authorization or {
            "name": currency.name,
            "version": currency.version,
        }
    else:
        if not isinstance(currency, str) or not _ADDRESS_RE.fullmatch(currency):
            raise ValueError("currency must be an EvmAsset or a token address")
        if chain_id is None:
            raise ValueError("EVM currency addresses require chain_id")
        if decimals is None:
            raise ValueError("EVM currency addresses require decimals")
        if authorization is None:
            raise ValueError("EVM currency addresses require authorization metadata")
        address = currency
        resolved_chain_id = chain_id
        resolved_decimals = decimals
        domain = authorization
    if isinstance(resolved_chain_id, bool) or not isinstance(resolved_chain_id, int):
        raise ValueError("chain_id must be an integer")
    if (
        isinstance(resolved_decimals, bool)
        or not isinstance(resolved_decimals, int)
        or not 0 <= resolved_decimals <= 36
    ):
        raise ValueError("decimals must be an integer between 0 and 36")
    if not isinstance(domain.get("name"), str) or not domain.get("name"):
        raise ValueError("authorization name is required")
    if not isinstance(domain.get("version"), str) or not domain.get("version"):
        raise ValueError("authorization version is required")
    if recipient is not None and not _ADDRESS_RE.fullmatch(recipient):
        raise ValueError("recipient must be an address")

    intents: dict[str, Intent | VerifiableIntent] = {}
    if recipient is not None or facilitator is not None or settle is not None:
        if recipient is None:
            raise ValueError("EVM servers require recipient")
        intents["charge"] = ChargeIntent(
            name=domain["name"],
            version=domain["version"],
            facilitator=resolve_facilitator(facilitator) if facilitator is not None else None,
            settle=settle,
            max_timeout_seconds=max_timeout_seconds,
        )
    elif account is None:
        raise ValueError(
            "evm() requires recipient and a facilitator or settle hook (servers) "
            "or account (clients)"
        )
    else:
        # Clients match challenges on (method, intent) without verifying them.
        intents["charge"] = _ClientChargeIntent()

    return EvmMethod(
        currency=to_checksum_address(address),
        chain_id=resolved_chain_id,
        decimals=resolved_decimals,
        domain_name=domain["name"],
        domain_version=domain["version"],
        recipient=to_checksum_address(recipient) if recipient is not None else None,
        account=account,
        max_amount=(
            parse_units(str(max_amount), resolved_decimals) if max_amount is not None else None
        ),
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        _intents=intents,
    )


class _ClientChargeIntent:
    """Placeholder intent that lets client runtimes match ``evm/charge``."""

    name = "charge"

    async def verify(self, credential: Credential, request: dict[str, Any]) -> Any:
        raise NotImplementedError("client-side EVM methods cannot verify credentials")
