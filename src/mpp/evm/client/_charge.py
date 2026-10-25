from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict

from mpp import expires
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.evm._types import (
    AuthorizationConfig,
    AuthorizationPayload,
    authorization_typed_data,
    challenge_hash,
    network_of,
    to_source,
)
from mpp.evm._types import (
    charge as charge_method,
)
from mpp.method import ClientMethod, CredentialParams
from mpp.x402 import _exact
from mpp.x402._evm import get_address, parse_units
from mpp.x402._protocol import is_x402_challenge
from mpp.x402._signer import has_signer, sign_typed_data
from mpp.x402.assets import Currency, Eip3009Transfer, is_raw_address, matches, resolve


class ChargeContext(BaseModel):
    """Per-request credential context: an ``account`` overriding the configured one."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    account: Any = None


def charge(
    *,
    account: Any = None,
    authorization: AuthorizationConfig | None = None,
    decimals: int | None = None,
    max_amount: str | None = None,
    max_atomic_amount: str | None = None,
    networks: Sequence[int] | None = None,
    currencies: Sequence[Currency] | None = None,
) -> ClientMethod:
    """Creates an EVM charge client method.

    Signs native Payment-auth ``authorization`` (EIP-3009) credentials, and x402 ``exact``
    ``PAYMENT-SIGNATURE`` payloads for challenges synthesized from x402 offers.

    Args:
        account: Typed-data signer (:class:`mpp.x402.TypedDataSigner` or an ``eth_account``
            account). May instead be supplied per request as ``context={"account": ...}``.
        authorization: EIP-3009 token domain metadata for currencies without known metadata.
        decimals: Token decimals used to parse ``max_amount`` when currency metadata has none.
        max_amount: Maximum display-unit amount the client is willing to pay.
        max_atomic_amount: Maximum atomic amount the client is willing to pay.
        networks: Allowlist of EVM chain ids.
        currencies: Allowlist of currencies (raw addresses require ``networks``).
    """
    policy = _exact.Policy(
        account=account,
        decimals=decimals,
        max_amount=max_amount,
        max_atomic_amount=max_atomic_amount,
        networks=tuple(networks) if networks is not None else None,
        currencies=tuple(currencies) if currencies is not None else None,
    )

    def can_handle_challenge(challenge: Challenge) -> bool:
        if not _is_x402(challenge):
            return True
        return _exact.can_handle_challenge(challenge, policy)

    async def create_credential(params: CredentialParams[Any]) -> str:
        challenge = params.challenge
        context_account = params.context.account if params.context is not None else None
        if _is_x402(challenge):
            return await _exact.create_credential(challenge, policy, account=context_account)

        signer = context_account if context_account is not None else account
        if not has_signer(signer):
            raise ValueError("EVM authorization requires a typed-data signer.")
        request = challenge.request
        method_details = request.get("methodDetails") or {}
        chain_id = method_details["chainId"]
        _assert_policy(policy, request)
        if "authorization" not in (method_details.get("credentialTypes") or ()):
            raise ValueError("EVM authorization is not accepted by this challenge.")
        if method_details.get("splits"):
            raise ValueError("EVM authorization does not support payment splits.")
        if int(request["amount"]) == 0:
            # A zero-value authorization still signs the challenge realm into its nonce; another
            # host could relay it to the server that realm names.
            raise ValueError("EVM client does not sign zero-amount charges.")

        domain = _resolve_authorization(policy, authorization, request)
        expiry = expires.parse(challenge.expires) if challenge.expires else None
        valid_before = str(
            int(expiry.timestamp()) if expiry else int(expires.now().timestamp()) + 300
        )
        payer = get_address(signer.address)
        nonce = challenge_hash(id=challenge.id, realm=challenge.realm)
        signature = await sign_typed_data(
            signer,
            authorization_typed_data(
                authorization=domain,
                chain_id=chain_id,
                currency=request["currency"],
                from_=payer,
                to=request["recipient"],
                value=request["amount"],
                valid_after=0,
                valid_before=valid_before,
                nonce=nonce,
            ),
        )
        payload = {
            "from": payer,
            "nonce": nonce,
            "signature": signature,
            "to": get_address(request["recipient"]),
            "type": "authorization",
            "validAfter": "0",
            "validBefore": valid_before,
            "value": request["amount"],
        }
        return Credential(
            challenge=challenge,
            payload=AuthorizationPayload.model_validate(payload).to_dict(),
            source=to_source(address=payer, chain_id=chain_id),
        ).serialize()

    return ClientMethod(
        method=charge_method,
        create_credential=create_credential,
        can_handle_challenge=can_handle_challenge,
        context=ChargeContext,
    )


def _is_x402(challenge: Challenge) -> bool:
    return (
        is_x402_challenge(challenge)
        and challenge.request.get("scheme") == "exact"
        and isinstance(challenge.request.get("network"), str)
    )


def _assert_policy(policy: _exact.Policy, request: dict[str, Any]) -> None:
    chain_id = request["methodDetails"]["chainId"]
    network = network_of(chain_id)
    if policy.networks is not None and chain_id not in policy.networks:
        raise ValueError(f"EVM chain ID is not allowed: {chain_id}.")
    if policy.currencies is not None:
        if any(is_raw_address(currency) for currency in policy.currencies) and not policy.networks:
            raise ValueError("EVM raw currency allowlists require networks.")
        accepted = get_address(request["currency"])
        if not any(matches(currency, accepted, network) for currency in policy.currencies):
            raise ValueError(f"EVM currency is not allowed: {accepted}.")
    amount = int(request["amount"])
    if policy.max_atomic_amount is not None and amount > int(policy.max_atomic_amount):
        raise ValueError("EVM charge amount exceeds maxAtomicAmount.")
    if policy.max_amount is not None:
        decimals = _exact.accepted_decimals(policy, request["currency"], network)
        if decimals is None:
            raise ValueError("EVM charge maxAmount requires currency decimals.")
        if amount > parse_units(policy.max_amount, decimals):
            raise ValueError("EVM charge amount exceeds maxAmount.")


def _resolve_authorization(
    policy: _exact.Policy, authorization: AuthorizationConfig | None, request: dict[str, Any]
) -> AuthorizationConfig:
    network = network_of(request["methodDetails"]["chainId"])
    currency = _exact.find_currency(policy, request["currency"], network)
    resolved = resolve(currency, network) if currency is not None else None
    if resolved is not None and isinstance(resolved.transfer, Eip3009Transfer):
        return AuthorizationConfig(name=resolved.transfer.name, version=resolved.transfer.version)
    if authorization is not None:
        return authorization
    raise ValueError("EVM authorization requires token name and version.")
