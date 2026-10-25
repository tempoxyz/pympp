"""x402 ``exact`` client: signs EIP-3009 ``PAYMENT-SIGNATURE`` credentials."""

import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from mpp import expires
from mpp.challenge import Challenge
from mpp.x402 import _route_binding
from mpp.x402._evm import get_address, parse_units
from mpp.x402._header import encode_payment_signature
from mpp.x402._signer import has_signer, sign_typed_data
from mpp.x402._types import (
    Eip3009Authorization,
    ExactEip3009Payload,
    Extension,
    PaymentPayload,
    PaymentRequirements,
    ResourceInfo,
    chain_id_of,
    to_payment_requirements,
)
from mpp.x402.assets import Currency, is_raw_address, matches, resolve

AUTHORIZATION_TYPES: Final = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}
"""EIP-712 type definition for EIP-3009 ``transferWithAuthorization``."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """Client payment policy shared by the EVM charge and x402 exact signers.

    Attributes:
        account: Signer used for credentials unless one is supplied in the credential context.
        decimals: Token decimals used to parse ``max_amount`` when currency metadata has none.
        max_amount: Maximum display-unit amount the client is willing to pay.
        max_atomic_amount: Maximum atomic amount the client is willing to pay.
        networks: Allowlist of EVM chain ids.
        currencies: Allowlist of currencies (raw addresses require ``networks``).
    """

    account: Any = None
    decimals: int | None = None
    max_amount: str | None = None
    max_atomic_amount: str | None = None
    networks: Sequence[int] | None = None
    currencies: Sequence[Currency] | None = None


async def create_credential(challenge: Challenge, policy: Policy, *, account: Any = None) -> str:
    """Creates an x402 exact ``PAYMENT-SIGNATURE`` header value for a synthesized challenge.

    ``account`` (the credential context) takes precedence over ``policy.account``.

    Raises:
        ValueError: When the challenge violates the policy or cannot be signed.
    """
    signer = account if account is not None else policy.account
    if not has_signer(signer):
        raise ValueError("x402 exact requires a typed-data signer.")

    request = challenge.request
    accepted = to_payment_requirements(request)
    _assert_policy(policy, accepted)
    if not request.get("resource"):
        raise ValueError("x402 exact EIP-3009 requires resource information.")
    resource = ResourceInfo.model_validate(request["resource"])
    extensions = _extensions(request.get("extensions"))
    if extensions is not None and "mppx" in extensions:
        extensions = _with_nonce_salt(extensions)
    extra = accepted.extra or {}
    transfer_method = extra.get("assetTransferMethod", "eip3009")
    if transfer_method != "eip3009":
        raise ValueError(f"x402 exact {transfer_method} signing is not implemented yet.")
    name, version = extra.get("name"), extra.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError("x402 exact EIP-3009 requires token name and version.")

    now = int(expires.now().timestamp())
    nonce = (
        _route_binding.nonce(accepted=accepted, extensions=extensions, resource=resource)
        if extensions is not None and "mppx" in extensions
        else "0x" + secrets.token_hex(32)
    )
    authorization = Eip3009Authorization.model_validate(
        {
            "from": get_address(signer.address),
            "nonce": nonce,
            "to": get_address(accepted.pay_to),
            "validAfter": str(now - 600),
            "validBefore": str(now + int(accepted.max_timeout_seconds)),
            "value": accepted.amount,
        }
    )
    signature = await sign_typed_data(
        signer,
        {
            "domain": {
                "chainId": chain_id_of(accepted.network),
                "name": name,
                "verifyingContract": get_address(accepted.asset),
                "version": version,
            },
            "message": {
                "from": authorization.from_,
                "nonce": authorization.nonce,
                "to": authorization.to,
                "validAfter": int(authorization.valid_after),
                "validBefore": int(authorization.valid_before),
                "value": int(authorization.value),
            },
            "primaryType": "TransferWithAuthorization",
            "types": AUTHORIZATION_TYPES,
        },
    )
    payment_payload = PaymentPayload(
        accepted=accepted,
        payload=ExactEip3009Payload(authorization=authorization, signature=signature),
        resource=resource,
        x402Version=2,
    )
    if extensions is not None:
        payment_payload = payment_payload.model_copy(update={"extensions": extensions})
    return encode_payment_signature(payment_payload)


def can_handle_challenge(challenge: Challenge, policy: Policy) -> bool:
    """Returns whether this policy can sign the given x402 exact challenge."""
    request = challenge.request
    try:
        accepted = to_payment_requirements(request)
        _assert_policy(policy, accepted)
    except ValueError:
        return False
    if not request.get("resource"):
        return False
    extra = accepted.extra or {}
    if extra.get("assetTransferMethod", "eip3009") != "eip3009":
        return False
    return isinstance(extra.get("name"), str) and isinstance(extra.get("version"), str)


def _assert_policy(policy: Policy, accepted: PaymentRequirements) -> None:
    chain_id = chain_id_of(accepted.network)
    if policy.networks is not None and chain_id not in policy.networks:
        raise ValueError(f"x402 exact chain ID is not allowed: {chain_id}.")
    currencies = policy.currencies
    if currencies is not None:
        if any(is_raw_address(currency) for currency in currencies) and not policy.networks:
            raise ValueError("x402 exact raw currency allowlists require networks.")
        accepted_currency = get_address(accepted.asset)
        if not any(
            matches(currency, accepted_currency, accepted.network) for currency in currencies
        ):
            raise ValueError(f"x402 exact currency is not allowed: {accepted_currency}.")
    if policy.max_atomic_amount is not None and int(accepted.amount) > int(
        policy.max_atomic_amount
    ):
        raise ValueError("x402 exact amount exceeds maxAtomicAmount.")
    if policy.max_amount is not None:
        decimals = accepted_decimals(policy, accepted.asset, accepted.network)
        if decimals is None:
            raise ValueError("x402 exact maxAmount requires currency decimals.")
        if int(accepted.amount) > parse_units(policy.max_amount, decimals):
            raise ValueError("x402 exact amount exceeds maxAmount.")


def accepted_decimals(policy: Policy, asset: str, network: str) -> int | None:
    """Decimals of the policy currency matching ``asset`` (falls back to ``policy.decimals``)."""
    currency = find_currency(policy, asset, network)
    resolved = resolve(currency, network) if currency is not None else None
    if resolved is not None and resolved.decimals is not None:
        return resolved.decimals
    return policy.decimals


def find_currency(policy: Policy, asset: str, network: str) -> Currency | None:
    """Returns the first policy currency matching ``asset`` on ``network``."""
    accepted_currency = get_address(asset)
    return next(
        (
            currency
            for currency in policy.currencies or ()
            if matches(currency, accepted_currency, network)
        ),
        None,
    )


def _extensions(value: Any) -> dict[str, Extension] | None:
    if not isinstance(value, Mapping):
        return None
    return {str(key): Extension.model_validate(item) for key, item in value.items()}


def _with_nonce_salt(extensions: dict[str, Extension]) -> dict[str, Extension]:
    mppx = extensions["mppx"]
    salted = Extension(info={**mppx.info, "nonce": secrets.token_hex(32)}, schema=mppx.schema_)
    return {**extensions, "mppx": salted}
