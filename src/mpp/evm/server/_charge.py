import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError

from mpp import expires
from mpp import store as _store
from mpp.challenge import Challenge
from mpp.credential import Credential
from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    InvalidPayloadError,
    PaymentError,
    VerificationFailedError,
)
from mpp.evm._types import (
    CREDENTIAL_TYPES,
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
from mpp.evm.server import _claims
from mpp.method import (
    CanOfferContext,
    CapturedRequest,
    MaybeAwaitable,
    PaymentSuccessHookContext,
    ServerMethod,
    ValidateContext,
    Validation,
    VerifiedChallengeEnvelope,
    VerifyContext,
)
from mpp.receipt import Receipt
from mpp.server import HttpTransport, Request, Response, Transport
from mpp.server._transport import problem_response
from mpp.x402 import _evm_charge
from mpp.x402._evm import get_address
from mpp.x402._evm_charge import SettleAuthorization, SettleParams, SettleResult, X402Options
from mpp.x402.assets import Currency, Eip3009Transfer, KnownAsset, resolve, to_chain_id


@dataclass(frozen=True, slots=True, kw_only=True)
class _Config:
    authorization: AuthorizationConfig
    chain_id: int
    currency: str
    decimals: int
    max_validity_seconds: int
    recipient: str
    settle: SettleAuthorization
    validate: Callable[[SettleParams], Awaitable[None]] | None
    x402: _evm_charge.ResolvedOptions


def charge(
    *,
    currency: Currency,
    recipient: str,
    authorization: AuthorizationConfig | None = None,
    chain_id: int | None = None,
    decimals: int | None = None,
    settle: SettleAuthorization | None = None,
    x402: X402Options | None = None,
    max_validity_seconds: int = 3600,
    store: _store.AtomicStore | None = None,
    can_offer: Callable[[CanOfferContext], MaybeAwaitable[bool]] | None = None,
    on_payment_success: Callable[[PaymentSuccessHookContext], MaybeAwaitable[None]] | None = None,
) -> ServerMethod:
    """Creates an EVM charge server method.

    Speaks the native Payment-auth ``evm/charge`` wire format and, on the same route, x402 v2
    (``PAYMENT-REQUIRED`` / ``PAYMENT-SIGNATURE`` / ``PAYMENT-RESPONSE``). Supports
    non-mutating ``validate_credential`` checks before settlement through
    ``broadcast_credential``. Validation checks the signature and payment terms, and checks the
    facilitator when using facilitator-backed settlement. Every authorization is claimed in
    ``store`` before settlement, so a replay is answered with 403 and no new challenge. A failed
    settlement releases the claim; an unknown or pending outcome keeps it. Custom settlers remain
    responsible for chain-state checks beyond that claim.

    Args:
        currency: Token address, known asset metadata or a token definition.
        recipient: Recipient wallet address.
        authorization: EIP-3009 token domain metadata. Required for raw addresses and token
            definitions; inferred for known assets.
        chain_id: EVM chain id. Required for raw addresses and token definitions; inferred for
            known assets.
        decimals: Token decimals. Required for raw addresses; inferred otherwise.
        settle: Custom settlement. Defaults to the ``x402.facilitator``.
        x402: x402 compatibility options.
        max_validity_seconds: Longest an authorization may stay valid from now (at least
            ``x402.max_timeout_seconds``). Native credentials may also run to their challenge's
            expiry.
        store: Atomic store claiming each authorization before settlement. Defaults to a bounded
            in-process cache whose claims expire with their authorization.
        can_offer: Decides whether this offer is available for a request.
        on_payment_success: Invoked after a successful payment on this method.

    Raises:
        ValueError: When the configuration is incomplete or inconsistent.
    """
    config = _resolve_config(
        currency=currency,
        recipient=recipient,
        authorization=authorization,
        chain_id=chain_id,
        decimals=decimals,
        settle=settle,
        options=x402,
        max_validity_seconds=max_validity_seconds,
    )
    claims: _store.AtomicStore = store if store is not None else _claims.fallback_store()

    def claim_key(payload: AuthorizationPayload, request: dict[str, Any]) -> str:
        return _claims.claim_key(
            chain_id=request["methodDetails"]["chainId"],
            currency=request["currency"],
            payer=payload.from_,
            nonce=payload.nonce,
        )

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        credential = context.credential
        payload = _payload(credential.payload)
        _assert_uint256(payload)
        request = credential.challenge.request
        method_details = request["methodDetails"]
        chain = method_details["chainId"]

        if "authorization" not in (method_details.get("credentialTypes") or ()):
            raise VerificationFailedError(
                reason="EVM authorization credentials are not supported for this challenge"
            )
        if method_details.get("splits"):
            raise VerificationFailedError(
                reason="EVM authorization credentials do not support splits"
            )
        _assert_address_equal(
            payload.to, request["recipient"], "EVM authorization recipient mismatch"
        )
        if payload.value != request["amount"]:
            raise VerificationFailedError(reason="EVM authorization amount mismatch")
        is_x402 = _evm_charge.is_credential(credential)
        if not is_x402 and payload.nonce.lower() != challenge_hash(
            id=credential.challenge.id, realm=credential.challenge.realm
        ):
            raise VerificationFailedError(reason="EVM authorization challenge hash mismatch")
        now = int(expires.now().timestamp())
        if int(payload.valid_after) > now:
            raise VerificationFailedError(reason="EVM authorization is not valid yet")
        if int(payload.valid_before) <= now:
            raise VerificationFailedError(reason="EVM authorization has expired")
        # The payer picks validBefore; cap it so claims (and an authorization a facilitator
        # holds) cannot stay live indefinitely. A native credential may run to its challenge's
        # expiry, which the server set and HMAC-binds.
        limit = now + config.max_validity_seconds
        if not is_x402:
            limit = max(limit, _challenge_expiry(credential.challenge))
        if int(payload.valid_before) > limit:
            raise VerificationFailedError(reason="EVM authorization is valid for too long")

        try:
            signer = _recover(config.authorization, chain, request["currency"], payload)
        except Exception as error:
            raise VerificationFailedError(
                reason="EVM authorization signature is invalid"
            ) from error
        _assert_address_equal(signer, payload.from_, "EVM authorization signature mismatch")

        payer = get_address(payload.from_)
        source = to_source(address=payer, chain_id=chain)
        if credential.source is not None and not _source_matches(credential.source, payer, chain):
            raise VerificationFailedError(reason="EVM authorization source mismatch")
        # A claimed authorization was settled (or is settling) already. Report it as a replay
        # before the facilitator calls it unpayable, so the payer is not invited to pay twice.
        if _claims.is_claimed(await claims.get(claim_key(payload, request))):
            raise CredentialReplayedError(reason="EVM authorization has already been used")
        if config.validate is not None:
            await config.validate(
                SettleParams(credential=credential, payload=payload, request=request, source=source)
            )
        return Validation(
            challenge=credential.challenge,
            credential=credential,
            details={"payer": payer},
            intent=charge_method.intent,
            method=charge_method.name,
            request=request,
            payer=payer,
            source=source,
        )

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        credential = context.credential
        payload = _payload(credential.payload)
        request = credential.challenge.request
        key = claim_key(payload, request)
        try:
            claimed = await _store.try_claim(
                claims, key, _claims.claim_expires(int(payload.valid_before))
            )
        except _claims.ClaimCacheFullError as error:
            # Refuse without a new challenge rather than forget a live claim.
            raise InternalPaymentError(cause=error) from error
        if not claimed:
            raise CredentialReplayedError(reason="EVM authorization has already been used")
        try:
            settled = await config.settle(
                SettleParams(
                    credential=credential,
                    payload=payload,
                    request=request,
                    source=to_source(
                        address=get_address(payload.from_),
                        chain_id=request["methodDetails"]["chainId"],
                    ),
                )
            )
        except (VerificationFailedError, InvalidPayloadError):
            # Nothing settled: let the payer retry with the same authorization. Any other
            # outcome may have moved funds, so the claim stays.
            await claims.delete(key)
            raise
        if (
            not isinstance(settled, SettleResult)
            or not isinstance(settled.reference, str)
            or not settled.reference
        ):
            error = TypeError("settle must return a SettleResult with a non-empty reference")
            raise InternalPaymentError(cause=error) from error
        return Receipt(
            method=charge_method.name,
            reference=settled.reference,
            status="success",
            timestamp=settled.timestamp or expires.to_iso(expires.now()),
        )

    return ServerMethod(
        method=charge_method,
        validate=validate,
        broadcast=broadcast,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        defaults={
            "chainId": config.chain_id,
            "currency": config.currency,
            "credentialTypes": list(CREDENTIAL_TYPES),
            "decimals": config.decimals,
            "recipient": config.recipient,
        },
        transport=EvmHttpTransport(_evm_charge.X402Path(config.x402)),
    )


class EvmHttpTransport(Transport[Request, Response, Response, Response]):
    """HTTP transport serving native Payment auth and x402 on the same route."""

    name = "evm-http"

    def __init__(self, x402_path: _evm_charge.X402Path) -> None:
        self._mpp = HttpTransport()
        self._x402 = x402_path
        self.credential_headers = tuple(
            dict.fromkeys((*self._mpp.credential_headers, *x402_path.credential_headers))
        )

    async def capture_request(self, input: Request) -> CapturedRequest:
        return await self._mpp.capture_request(input)

    def get_credential(self, input: Request) -> Credential[Any] | None:
        return self._mpp.get_credential(input) or self._x402.get_credential(input)

    async def match_credential(self, *, input: Request, request: dict[str, Any]) -> bool:
        return self._x402.match_credential(input=input, request=request)

    async def bind_credential(
        self, *, challenge: Challenge, credential: Credential[Any], input: Request
    ) -> Credential[Any]:
        if _evm_charge.is_pending_credential(credential):
            return await self._x402.bind_credential(
                challenge=challenge, credential=credential, input=input
            )
        return await self._mpp.bind_credential(
            challenge=challenge, credential=credential, input=input
        )

    async def respond_challenge(
        self,
        *,
        challenge: Challenge,
        input: Request,
        error: PaymentError | None = None,
    ) -> Response:
        if error is not None and error.status == 500:
            # The payment may have landed (or its outcome is unknown); a retry challenge would
            # invite a second payment.
            return Response(
                status=500,
                headers={"Cache-Control": "no-store", "Content-Type": "application/problem+json"},
                body=problem_response(error),
            )
        response = await self._mpp.respond_challenge(challenge=challenge, input=input, error=error)
        if response.status == 403:
            return response
        return self._x402.respond_challenge(
            challenge=challenge, input=input, error=error, response=response
        )

    def respond_receipt(
        self,
        *,
        challenge_id: str,
        credential: Credential[Any],
        input: Request,
        receipt: Receipt,
        response: Response,
        envelope: VerifiedChallengeEnvelope[Any] | None = None,
    ) -> Response:
        response = self._mpp.respond_receipt(
            challenge_id=challenge_id,
            credential=credential,
            input=input,
            receipt=receipt,
            response=response,
            envelope=envelope,
        )
        return self._x402.respond_receipt(
            credential=credential, input=input, receipt=receipt, response=response
        )


def _resolve_config(
    *,
    currency: Currency,
    recipient: str,
    authorization: AuthorizationConfig | None,
    chain_id: int | None,
    decimals: int | None,
    settle: SettleAuthorization | None,
    options: X402Options | None,
    max_validity_seconds: int,
) -> _Config:
    if isinstance(currency, KnownAsset) and chain_id is None:
        chain_id = to_chain_id(currency.network)
    if chain_id is not None:
        resolved = resolve(currency, network_of(chain_id))
        if resolved is None:
            raise ValueError(f"EVM currency is not available on chain ID {chain_id}.")
        address = resolved.address
        if decimals is None:
            decimals = resolved.decimals
        if authorization is None and isinstance(resolved.transfer, Eip3009Transfer):
            authorization = AuthorizationConfig(
                name=resolved.transfer.name, version=resolved.transfer.version
            )
    elif isinstance(currency, str):
        address = currency
    else:
        raise ValueError("EVM authorization requires `chainId`.")

    if authorization is None:
        raise ValueError("EVM authorization requires `authorization` metadata.")
    if chain_id is None:
        raise ValueError("EVM authorization requires `chainId`.")
    if decimals is None:
        raise ValueError("EVM authorization requires `decimals`.")

    resolved_options = _evm_charge.resolve_options(authorization=authorization, options=options)
    if (
        isinstance(max_validity_seconds, bool)
        or not isinstance(max_validity_seconds, int)
        or max_validity_seconds < resolved_options.max_timeout_seconds
    ):
        raise ValueError(
            "EVM authorization `max_validity_seconds` must be >= `max_timeout_seconds`."
        )
    if settle is None and resolved_options.facilitator is not None:
        resolved_settle: SettleAuthorization = _evm_charge.settle_with_facilitator(resolved_options)
    elif settle is not None:
        resolved_settle = settle
    else:
        raise ValueError("EVM authorization requires `settle` or `x402.facilitator`.")

    async def validate_with_facilitator(params: SettleParams) -> None:
        await _evm_charge.verify_with_facilitator(resolved_options, params)

    return _Config(
        authorization=authorization,
        chain_id=chain_id,
        currency=get_address(address),
        decimals=decimals,
        max_validity_seconds=max_validity_seconds,
        recipient=get_address(recipient),
        settle=resolved_settle,
        validate=validate_with_facilitator
        if settle is None and resolved_options.facilitator is not None
        else None,
        x402=resolved_options,
    )


def _payload(payload: Any) -> AuthorizationPayload:
    if isinstance(payload, AuthorizationPayload):
        return payload
    try:
        return AuthorizationPayload.model_validate(payload)
    except ValidationError as error:
        raise InvalidPayloadError() from error


_UINT256_MAX: Final = 2**256 - 1


def _assert_uint256(payload: AuthorizationPayload) -> None:
    for name, value in (
        ("value", payload.value),
        ("validAfter", payload.valid_after),
        ("validBefore", payload.valid_before),
    ):
        # uint256 values have at most 78 digits; longer strings cannot be parsed safely.
        if len(value) > 78:
            raise InvalidPayloadError(reason=f"EVM authorization {name} is malformed")
        if int(value) > _UINT256_MAX:
            raise InvalidPayloadError(reason=f"EVM authorization {name} is out of range")


def _challenge_expiry(challenge: Challenge) -> int:
    parsed = expires.parse(challenge.expires) if challenge.expires else None
    return int(parsed.timestamp()) if parsed is not None else 0


_PKH_SOURCE: Final = re.compile(r"did:pkh:eip155:([0-9]{1,16}):(0x[0-9a-fA-F]{40})")


def _source_matches(source: str, payer: str, chain_id: int) -> bool:
    match = _PKH_SOURCE.fullmatch(source)
    return (
        match is not None
        and int(match.group(1)) == chain_id
        and match.group(2).lower() == payer.lower()
    )


def _recover(
    authorization: AuthorizationConfig, chain_id: int, currency: str, payload: AuthorizationPayload
) -> str:
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    typed_data = authorization_typed_data(
        authorization=authorization,
        chain_id=chain_id,
        currency=currency,
        from_=payload.from_,
        to=payload.to,
        value=payload.value,
        valid_after=payload.valid_after,
        valid_before=payload.valid_before,
        nonce=payload.nonce,
    )
    return Account.recover_message(
        encode_typed_data(full_message=typed_data), signature=payload.signature
    )


def _assert_address_equal(actual: str, expected: str, reason: str) -> None:
    if get_address(actual) != get_address(expected):
        raise VerificationFailedError(reason=reason)


__all__ = ["EvmHttpTransport", "SettleParams", "SettleResult", "X402Options", "charge"]
