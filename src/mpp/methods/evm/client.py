"""EVM charge for clients, and the ``evm()`` shorthand for either side."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any, TypedDict, overload

from eth_utils.address import to_checksum_address

from mpp import Challenge, Credential
from mpp._typing import is_list, is_mapping
from mpp._units import parse_units
from mpp.methods import CanOfferFn, PaymentSuccessHandler
from mpp.methods.evm._eip3009 import (
    authorization_domain,
    challenge_hash,
    sign_authorization,
    to_source,
)
from mpp.methods.evm.assets import EvmAsset
from mpp.methods.evm.intents import CREDENTIAL_TYPE, SettleFn
from mpp.methods.evm.intents import charge as definition
from mpp.runtime import ClientMethod, CredentialParams
from mpp.x402._client import is_x402_challenge
from mpp.x402._exact import check_exact, create_payment_signature
from mpp.x402._server import RouteBinding
from mpp.x402.facilitator import Facilitator

if TYPE_CHECKING:
    from mpp.server.method import RequestContext, ServerMethod
    from mpp.store import Store

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
DEFAULT_VALIDITY_SECONDS = 300


class AuthorizationConfig(TypedDict):
    """EIP-712 domain of a token's EIP-3009 authorizations."""

    name: str
    version: str


_OPTION_KEYS = frozenset(
    {"amount", "currency", "recipient", "splits", "fee_payer", "chain_id", "extra", "external_id"}
)


@dataclass(frozen=True)
class _Config:
    """The token, chain and party an EVM method charges or pays with."""

    currency: str
    chain_id: int
    decimals: int
    domain_name: str
    domain_version: str
    recipient: str | None = None
    account: Any = None
    max_amount: int | None = None

    # -- server ----------------------------------------------------------

    def resolve_request(self, context: RequestContext) -> dict[str, Any]:
        """Turn route input (a display-unit ``amount`` and options) into the wire request."""
        options = context.request
        unknown = options.keys() - _OPTION_KEYS
        if unknown:
            raise TypeError(f"unsupported option: {sorted(unknown, key=str)[0]}")
        amount = options.get("amount")
        if not isinstance(amount, str) or not amount.strip():
            raise ValueError("offer requires a non-empty string amount")
        details = {
            key: value
            for key, value in (
                ("chainId", options.get("chain_id")),
                ("splits", options.get("splits")),
            )
            if value is not None
        }
        request: dict[str, Any] = {
            "amount": str(parse_units(amount, self.decimals)),
            "currency": options.get("currency") or self.currency,
            "recipient": options.get("recipient") or self.recipient,
            "methodDetails": details,
        }
        if options.get("extra") is not None:
            request["extra"] = options["extra"]
        if options.get("external_id") is not None:
            request["externalId"] = options["external_id"]
        # fee_payer is a Tempo option: EIP-3009 payers pay no gas, so like mppx an
        # EVM offer composed with sponsored Tempo offers ignores it.
        return self.wire_request(request)

    def wire_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Normalize a charge request to the ``evm/charge`` wire shape."""
        currency = request.get("currency")
        if not isinstance(currency, str) or currency.lower() != self.currency.lower():
            raise ValueError(f"EVM charge currency must be the method's currency {self.currency}")
        recipient = request.get("recipient")
        if not isinstance(recipient, str) or not _ADDRESS_RE.fullmatch(recipient):
            raise ValueError("EVM charge recipient must be an address")
        raw_details: object = request.get("methodDetails") or {}
        if not is_mapping(raw_details):
            raise ValueError("methodDetails must be an object")
        details = dict(raw_details)
        if details.get("splits"):
            raise ValueError("EVM charges do not support splits")
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
            if is_x402_challenge(challenge):
                check_exact(
                    challenge,
                    chain_id=self.chain_id,
                    currency=self.currency,
                    max_amount=self.max_amount,
                )
            else:
                self._check_challenge(challenge)
        except ValueError:
            return False
        return True

    def _check_challenge(self, challenge: Challenge) -> dict[str, Any]:
        request = challenge.request
        details = request.get("methodDetails")
        if not is_mapping(details):
            raise ValueError("EVM challenge is missing methodDetails")
        if details.get("chainId") != self.chain_id:
            raise ValueError(f"EVM chain ID is not allowed: {details.get('chainId')}")
        currency = request.get("currency")
        if not isinstance(currency, str) or currency.lower() != self.currency.lower():
            raise ValueError(f"EVM currency is not allowed: {currency}")
        credential_types = details.get("credentialTypes")
        if not is_list(credential_types) or CREDENTIAL_TYPE not in credential_types:
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


def _config(
    *,
    currency: EvmAsset | str,
    chain_id: int | None,
    decimals: int | None,
    authorization: AuthorizationConfig | None,
    recipient: str | None = None,
    account: Any = None,
    max_amount: str | Decimal | None = None,
) -> _Config:
    """Resolve a currency (known asset or token address) to the method's configuration."""
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
    return _Config(
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
    )


def charge(
    *,
    currency: EvmAsset | str,
    account: Any,
    chain_id: int | None = None,
    decimals: int | None = None,
    authorization: AuthorizationConfig | None = None,
    max_amount: str | Decimal | None = None,
) -> ClientMethod:
    """Create a client ``evm/charge`` method that signs EIP-3009 authorizations.

    It pays native ``evm/charge`` challenges and x402 v2 ``exact`` offers
    (``PAYMENT-REQUIRED``) in its currency and chain, as mppx's client does:
    when a server offers both, the native challenge is paid. x402 offers are
    signed with the token name and version the server advertises in
    ``extra``, and paid responses carry the settlement in
    ``PAYMENT-RESPONSE`` (see :func:`mpp.x402.payment_response`).

    Example:
        from eth_account import Account
        from mpp.client import Mpp
        from mpp.methods.evm import BASE_USDC
        from mpp.methods.evm import client as evm

        method = evm.charge(currency=BASE_USDC, account=Account.from_key("0x..."))
        async with Mpp(methods=[method]) as mpp:
            response = await mpp.fetch("https://api.example.com/paid")

    Args:
        currency: A known :class:`EvmAsset`, or a token address together
            with ``chain_id``, ``decimals`` and ``authorization``.
        account: eth-account ``LocalAccount`` that signs credentials.
        chain_id: EVM chain ID. Inferred from a known asset.
        decimals: Token decimals. Inferred from a known asset.
        authorization: EIP-712 domain (``name``, ``version``) the token signs
            EIP-3009 authorizations with. Inferred from a known asset.
        max_amount: Largest display-unit amount the client pays.
    """
    if account is None:
        raise ValueError("No account configured for EVM credentials")
    config = _config(
        currency=currency,
        chain_id=chain_id,
        decimals=decimals,
        authorization=authorization,
        account=account,
        max_amount=max_amount,
    )

    async def create_credential(params: CredentialParams) -> str:
        if is_x402_challenge(params.challenge):
            return create_payment_signature(
                params.challenge,
                account=config.account,
                chain_id=config.chain_id,
                currency=config.currency,
                max_amount=config.max_amount,
            )
        credential = await config.create_credential(params.challenge)
        return credential.to_authorization()

    return ClientMethod(
        method=definition,
        create_credential=create_credential,
        can_handle_challenge=config.can_handle_challenge,
    )


@overload
def evm(
    *,
    currency: EvmAsset | str,
    recipient: str,
    chain_id: int | None = None,
    decimals: int | None = None,
    authorization: AuthorizationConfig | None = None,
    facilitator: str | Facilitator | None = None,
    settle: SettleFn | None = None,
    max_timeout_seconds: int = 300,
    route_binding: RouteBinding = "required",
    max_validity_seconds: int = 3600,
    store: Store | None = None,
    can_offer: CanOfferFn | None = None,
    on_payment_success: PaymentSuccessHandler | None = None,
) -> ServerMethod: ...


@overload
def evm(
    *,
    currency: EvmAsset | str,
    account: Any,
    chain_id: int | None = None,
    decimals: int | None = None,
    authorization: AuthorizationConfig | None = None,
    max_amount: str | Decimal | None = None,
) -> ClientMethod: ...


def evm(
    *,
    currency: EvmAsset | str,
    recipient: str | None = None,
    account: Any = None,
    max_amount: str | Decimal | None = None,
    **options: Any,
) -> ServerMethod | ClientMethod:
    """Create the server (with ``recipient``) or client (with ``account``) ``evm/charge`` method.

    Shorthand for :func:`mpp.methods.evm.server.charge` and
    :func:`mpp.methods.evm.client.charge`.
    """
    if recipient is not None or "facilitator" in options or "settle" in options:
        from mpp.methods.evm.server import charge as server_charge

        if recipient is None:
            raise ValueError("EVM servers require recipient")
        return server_charge(currency=currency, recipient=recipient, **options)
    if account is None:
        raise ValueError(
            "evm() requires recipient and a facilitator or settle hook (servers) "
            "or account (clients)"
        )
    return charge(currency=currency, account=account, max_amount=max_amount, **options)
