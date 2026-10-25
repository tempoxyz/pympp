"""Tempo charge intent (one-time TIP-20 transfer) for servers."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

import attrs
import httpx
from pydantic import ValidationError
from pytempo import Call, TempoTransaction

from mpp import expires as _expires
from mpp import store as _store
from mpp.credential import Credential
from mpp.errors import CredentialReplayedError, InternalPaymentError, VerificationFailedError
from mpp.method import (
    CanOfferContext,
    MaybeAwaitable,
    PaymentSuccessHookContext,
    RequestContext,
    ServerMethod,
    ValidateContext,
    Validation,
    VerifyContext,
    resolve,
)
from mpp.receipt import Receipt
from mpp.tempo import methods
from mpp.tempo._internal import actions
from mpp.tempo._internal import fee_payer as sponsorship
from mpp.tempo._internal.account import TempoAccount
from mpp.tempo._internal.account import resolve as resolve_accounts
from mpp.tempo._internal.address import is_equal
from mpp.tempo._internal.charge import (
    ExpectedTransfer,
    MismatchError,
    assert_challenge_bound_call_memo,
    assert_challenge_bound_memo,
    assert_transfer_calls,
    assert_transfer_logs,
    get_expected_transfers,
    splits_from_method_details,
    verify_hash_credential,
)
from mpp.tempo._internal.envelope import (
    deserialize,
    is_tempo_transaction,
    serialize,
)
from mpp.tempo._internal.envelope import fee_token as transaction_fee_token
from mpp.tempo._internal.envelope import sender as transaction_sender
from mpp.tempo._internal.fee_token import resolve_fee_token
from mpp.tempo._internal.hexutil import keccak256, to_bytes, to_hex
from mpp.tempo._internal.proof import (
    PkhSource,
    hash_typed_data,
    parse_pkh_source,
    recover_authorized_proof_signer,
    typed_data,
)
from mpp.tempo._internal.remote_fee_payer import RemoteFeePayer
from mpp.tempo._internal.rpc import (
    RpcClient,
    RpcError,
    RpcTransportError,
    TransactionReceipt,
    TransactionReceiptNotFoundError,
    TransactionReceiptTimeoutError,
)
from mpp.tempo._internal.signature import parse_secp256k1, recover_address
from mpp.tempo.assets import DECIMALS, resolve_currency
from mpp.tempo.chains import TESTNET_CHAIN_ID
from mpp.tempo.server import _relay
from mpp.tempo.server._internal.clients import ClientResolver, GetClient, remote_fee_payer_client
from mpp.tempo.server._internal.fallback_store import fallback_store

logger = logging.getLogger("mpp.tempo")

type ChargeMode = methods.ChargeMode
type FeePayerInput = TempoAccount | RemoteFeePayer | str | Literal[True]

_DEFAULT_MAX_TOTAL_FEE: Final = 50_000_000_000_000_000
_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MIN_REMAINING_VALIDITY_SECONDS: Final = 15
_VALID_BEFORE_GRACE_SECONDS: Final = 2
_RECOVERY_TYPE: Final = "mppx:charge-recovery"
_AMBIGUOUS_MESSAGE: Final = re.compile(r"\balready ?known\b|\bknown transaction\b", re.IGNORECASE)

_REQUEST_FIELDS: Final = {
    (info.alias or name): name for name, info in methods.ChargeRequest.model_fields.items()
}


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidateSenderParams:
    """Arguments for :data:`ValidateSender`."""

    sender: str
    """Actual TIP-20 ``Transfer.from`` address."""
    expected_sender: str
    """Address mpp would normally require as the sender."""
    source: PkhSource | None = None
    """Parsed hash credential source, when the credential includes one."""


type ValidateSender = Callable[[ValidateSenderParams], MaybeAwaitable[bool]]
"""Authorizes a TIP-20 transfer sender that differs from the credential source.

Core verification still checks amount, currency, recipient, memo binding,
transaction success, and replay protection.
"""


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidationDetails:
    """``Validation.details`` for Tempo charge credentials."""

    mode: Literal["proof", "pull", "push"]
    sender: str | None = None
    serialized_transaction: str | None = None
    transfers: tuple[ExpectedTransfer, ...] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class _Context:
    allowed_fee_tokens: list[str] | None
    amount: str
    chain_id: int
    challenge_id: str
    realm: str
    client: RpcClient
    currency: str
    is_zero_amount: bool
    method_details: dict[str, Any]
    payload: methods.HashPayload | methods.TransactionPayload | methods.ProofPayload
    recipient: str
    request_allows_fee_payer: bool
    request_fee_payer: TempoAccount | None
    resolved_request: dict[str, Any]
    supported_modes: list[str] | None


@dataclass(frozen=True, slots=True, kw_only=True)
class _Validated:
    details: ValidationDetails
    payer: str | None
    hash: str | None = None
    receipt: TransactionReceipt | None = None
    funding_currency: str | None = None
    is_fee_payer_tx: bool = False
    serialized_transaction: str | None = None
    transaction: TempoTransaction | None = None
    transfers: tuple[ExpectedTransfer, ...] = ()


def charge(
    *,
    amount: str | None = None,
    currency: str | None = None,
    decimals: int = DECIMALS,
    description: str | None = None,
    external_id: str | None = None,
    recipient: str | None = None,
    account: TempoAccount | str | None = None,
    fee_payer: FeePayerInput | None = None,
    splits: Sequence[methods.Split | Mapping[str, Any]] | None = None,
    supported_modes: Sequence[ChargeMode] | None = None,
    chain_id: int | None = None,
    testnet: bool = False,
    get_client: GetClient | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    fee_token: str | None = None,
    fee_payer_policy: sponsorship.PolicyOverrides | None = None,
    store: _store.AtomicStore | None = None,
    store_key_prefix: str = "",
    validate_sender: ValidateSender | None = None,
    wait_for_confirmation: bool = True,
    confirmation_timeout_ms: int = 30_000,
    relay: _relay.RelayOptions | None = None,
    can_offer: Callable[[CanOfferContext], MaybeAwaitable[bool]] | None = None,
    on_payment_success: Callable[[PaymentSuccessHookContext], MaybeAwaitable[None]] | None = None,
) -> ServerMethod:
    """Creates a Tempo charge method for servers.

    Args:
        amount: Default amount (decimal string, e.g. ``"1.5"``).
        currency: TIP-20 token address (defaults to USDC.e on mainnet, pathUSD otherwise).
        decimals: Token decimals used to convert ``amount`` to base units.
        recipient: Payment recipient (defaults to ``account``'s address).
        account: Account (or address) that receives payments.
        fee_payer: ``True`` (``account`` sponsors fees), a separate sponsoring account,
            or a remote fee-payer service (URL or :class:`RemoteFeePayer`).
        splits: Additional transfers taken out of ``amount``.
        supported_modes: Accepted credential modes (``push`` hash / ``pull`` transaction).
        chain_id: Chain to charge on (mainnet by default, Moderato with ``testnet``).
        get_client: Returns the RPC client for a chain ID (default: public Tempo RPC).
        allowed_fee_tokens: Tokens sponsored transactions may pay fees in. Local sponsorship
            defaults to pathUSD plus the chain currency; hosted sponsorship trusts the
            provider unless set. Must not be empty.
        fee_token: Fee token a local fee payer pays gas with (default: a funded allowed token).
        fee_payer_policy: Overrides of the per-chain sponsor fee policy.
        store: Atomic store for replay protection (in-memory by default; zero-amount proofs
            are only replay-protected when a store is given).
        store_key_prefix: Prefix for replay-protection keys.
        validate_sender: Authorizes third-party transfer senders for hash credentials.
        wait_for_confirmation: Wait for the receipt before responding (``False`` broadcasts
            after simulation and optimistically reports success).
        confirmation_timeout_ms: Receipt wait budget; the synchronous broadcast may use at
            most two thirds, the rest polls for the receipt after an ambiguous failure.
        relay: Delegates validation and broadcast to Tempo API's MPP relay.
    """
    if allowed_fee_tokens is not None and len(allowed_fee_tokens) == 0:
        raise ValueError("`allowedFeeTokens` must contain at least one token.")
    for split in splits or ():
        # Rejects fixed split memos in the MPP attribution format before any issuance.
        methods.Split.model_validate(split)
    raw_store = store if store is not None else fallback_store("tempo.charge")
    replay_store = _store.prefixed(raw_store, store_key_prefix)
    proof_store = _store.prefixed(store, store_key_prefix) if store is not None else None

    accounts = resolve_accounts(account=account, recipient=recipient, fee_payer=fee_payer)
    local_fee_payer = accounts.fee_payer
    remote = accounts.remote_fee_payer
    if fee_token and remote:
        raise ValueError("`feeToken` can only be configured for a local fee payer.")
    remote_client = remote_fee_payer_client(remote) if remote else None
    clients = ClientResolver(get_client=get_client)
    currency = currency or resolve_currency(chain_id=chain_id, testnet=testnet)

    def request_fee_payer(request: Mapping[str, Any]) -> TempoAccount | None:
        value = request.get("fee_payer")
        return value if isinstance(value, TempoAccount) else None

    async def resolve_request(context: RequestContext) -> dict[str, Any]:
        request = _normalize_input(context.request)
        resolved_chain_id: int | None = request.get("chain_id") or None
        if resolved_chain_id is None:
            if chain_id is not None:
                resolved_chain_id = chain_id
            elif testnet:
                resolved_chain_id = TESTNET_CHAIN_ID
            else:
                resolved_chain_id = await clients.default_chain_id()
        try:
            await clients(resolved_chain_id)
        except Exception:
            raise ValueError(f"No client configured with chainId {resolved_chain_id}.") from None
        requested = request.get("fee_payer")
        resolved_fee_payer: TempoAccount | bool | None
        if requested is False:
            resolved_fee_payer = False if context.credential is not None else None
        else:
            sponsor = request_fee_payer(request) or local_fee_payer
            if context.credential is not None:
                resolved_fee_payer = sponsor or (True if remote else None)
            else:
                resolved_fee_payer = True if sponsor or remote else None
        return {
            **request,
            "chain_id": resolved_chain_id,
            "fee_payer": resolved_fee_payer,
        }

    async def credential_context(
        credential: Credential[Any], raw_request: Mapping[str, Any]
    ) -> _Context:
        request = _normalize_input(raw_request)
        challenge = credential.challenge
        payload = credential.payload.root
        resolved = _wire_request(raw_request)
        method_details: dict[str, Any] = dict(resolved.get("methodDetails") or {})
        context_chain_id: int = (
            method_details.get("chainId")
            or request.get("chain_id")
            or await clients.default_chain_id()
        )
        amount = str(resolved["amount"])
        is_zero_amount = int(amount) == 0

        _expires.ensure(challenge.expires, challenge.id)
        if is_zero_amount and payload.type != "proof":
            raise MismatchError("Zero-amount challenges require a proof credential.", {})

        # Request-level local sponsorship takes precedence over the hosted provider.
        sponsor = request_fee_payer(request) or local_fee_payer
        context_allowed_fee_tokens = (
            list(allowed_fee_tokens)
            if allowed_fee_tokens is not None
            else sponsorship.default_allowed_fee_tokens(context_chain_id)
            if sponsor or not remote
            else None
        )
        client = await clients(context_chain_id)
        return _Context(
            allowed_fee_tokens=context_allowed_fee_tokens,
            amount=amount,
            chain_id=context_chain_id,
            challenge_id=challenge.id,
            realm=challenge.realm,
            client=client,
            currency=str(resolved["currency"]),
            is_zero_amount=is_zero_amount,
            method_details=method_details,
            payload=payload,
            recipient=str(resolved.get("recipient") or ""),
            request_allows_fee_payer=request.get("fee_payer") is not False,
            request_fee_payer=request_fee_payer(request),
            resolved_request=resolved,
            supported_modes=method_details.get("supportedModes"),
        )

    def validate_payment_route(
        calls: Sequence[Call],
        context: _Context,
        transfers: Sequence[ExpectedTransfer],
        is_fee_payer_tx: bool = False,
    ) -> str | None:
        """Validates a recognized payment route; returns the funding currency."""
        matched = assert_transfer_calls(
            calls,
            currency=context.currency,
            transfers=transfers,
            exact_count=is_fee_payer_tx,
            challenge_id=context.challenge_id,
            realm=context.realm,
        )
        assert_challenge_bound_call_memo(
            matched,
            challenge_id=context.challenge_id,
            realm=context.realm,
            calls=calls,
            currency=context.currency,
        )
        try:
            funding = sponsorship.validate_calls(
                calls,
                _details(context),
                currency=context.currency,
                expected_transfers=transfers,
            )
        except Exception:
            if is_fee_payer_tx:
                raise
            # Unrecognized routes stay valid for unsponsored payments, without funding metadata.
            return None
        return funding

    async def sender_validator(expected_sender: str, sender: str, source: PkhSource | None) -> bool:
        assert validate_sender is not None
        return bool(
            await resolve(
                validate_sender(
                    ValidateSenderParams(
                        sender=sender, expected_sender=expected_sender, source=source
                    )
                )
            )
        )

    async def validate_hash(
        credential: Credential[Any], payload: methods.HashPayload, context: _Context
    ) -> _Validated:
        if context.supported_modes and "push" not in context.supported_modes:
            raise MismatchError("Hash credentials are not supported for this challenge.", {})
        source = _parse_hash_source(context.chain_id, credential.source)
        verification = await verify_hash_credential(
            context.client,
            transaction_hash=payload.hash,
            challenge_id=context.challenge_id,
            realm=context.realm,
            amount=context.amount,
            currency=context.currency,
            recipient=context.recipient,
            splits=splits_from_method_details(context.method_details),
            source=source,
            validate_sender=sender_validator if validate_sender is not None else None,
        )
        transfers = tuple(verification.transfers)
        return _Validated(
            details=ValidationDetails(mode="push", sender=verification.sender, transfers=transfers),
            payer=verification.payer,
            hash=payload.hash,
            receipt=verification.receipt,
            transfers=transfers,
        )

    async def validate_proof(
        credential: Credential[Any], payload: methods.ProofPayload, context: _Context
    ) -> _Validated:
        if not context.is_zero_amount:
            raise MismatchError("Proof credentials are only valid for zero-amount challenges.", {})
        if not credential.source:
            raise MismatchError("Proof credential must include a source.", {})
        proof_chain_id = (credential.challenge.request.get("methodDetails") or {}).get(
            "chainId"
        ) or context.chain_id
        source = parse_pkh_source(credential.source)
        if source is None or source.chain_id != proof_chain_id:
            raise MismatchError("Proof credential source is invalid.", {})
        data = typed_data(
            account=source.address,
            chain_id=proof_chain_id,
            challenge_id=context.challenge_id,
            realm=context.realm,
        )
        if not _recovers(hash_typed_data(data), payload.signature, source.address):
            signer = recover_authorized_proof_signer(
                chain_id=proof_chain_id,
                challenge_id=context.challenge_id,
                realm=context.realm,
                signature=payload.signature,
                source_address=source.address,
            )
            authorized = signer is not None and await actions.is_active_access_key(
                context.client, account=source.address, access_key=signer
            )
            if not authorized:
                raise MismatchError("Proof signature does not match source.", {})
        return _Validated(
            details=ValidationDetails(mode="proof", sender=source.address), payer=source.address
        )

    async def validate_transaction(
        credential: Credential[Any],
        payload: methods.TransactionPayload,
        context: _Context,
    ) -> _Validated:
        if context.supported_modes and "pull" not in context.supported_modes:
            raise MismatchError("Transaction credentials are not supported for this challenge.", {})
        serialized = payload.signature
        if not is_tempo_transaction(serialized):
            raise MismatchError("Only Tempo (0x76/0x78) transactions are supported.", {})
        transaction = deserialize(serialized)
        sender = transaction_sender(transaction)
        if transaction.sender_signature is None or sender is None:
            raise MismatchError(
                "Transaction must be signed by the sender before fee payer co-signing.", {}
            )
        if credential.source:
            source = parse_pkh_source(credential.source)
            source_chain_id = (credential.challenge.request.get("methodDetails") or {}).get(
                "chainId"
            ) or context.chain_id
            if source is None or source.chain_id != source_chain_id:
                raise MismatchError("Transaction credential source is invalid.", {})
            if not is_equal(source.address, sender):
                raise MismatchError("Transaction credential source does not match the sender.", {})
        is_fee_payer_tx = (
            context.method_details.get("feePayer") is True
            and context.request_allows_fee_payer
            and bool(context.request_fee_payer or local_fee_payer or remote)
        )
        transfers = tuple(
            get_expected_transfers(
                amount=context.amount,
                recipient=context.recipient,
                splits=splits_from_method_details(context.method_details),
            )
        )
        funding_currency = validate_payment_route(
            transaction.calls, context, transfers, is_fee_payer_tx
        )
        if is_fee_payer_tx:
            sponsorship.assert_allowed_fee_token(
                transaction_fee_token(transaction), context.allowed_fee_tokens
            )
        else:
            await context.client.call(sponsorship.simulation_request(transaction, fee_payer=False))
        return _Validated(
            details=ValidationDetails(
                mode="pull",
                sender=sender,
                serialized_transaction=serialized,
                transfers=transfers,
            ),
            payer=sender,
            funding_currency=funding_currency,
            is_fee_payer_tx=is_fee_payer_tx,
            serialized_transaction=serialized,
            transaction=transaction,
            transfers=transfers,
        )

    async def validate_credential(credential: Credential[Any], context: _Context) -> _Validated:
        match context.payload:
            case methods.HashPayload() as payload:
                return await validate_hash(credential, payload, context)
            case methods.ProofPayload() as payload:
                return await validate_proof(credential, payload, context)
            case methods.TransactionPayload() as payload:
                return await validate_transaction(credential, payload, context)

    async def validate(context: ValidateContext[Any]) -> Validation[Any]:
        credential_ctx = await credential_context(context.credential, context.request)
        validated = await validate_credential(context.credential, credential_ctx)
        return Validation(
            challenge=context.credential.challenge,
            credential=context.credential,
            details=validated.details,
            intent="charge",
            method="tempo",
            request=credential_ctx.resolved_request,
            payer=validated.payer,
            source=context.credential.source,
        )

    async def broadcast(context: VerifyContext[Any]) -> Receipt:
        credential = context.credential
        challenge = credential.challenge
        ctx = await credential_context(credential, context.request)
        validated = await validate_credential(credential, ctx)
        sponsor_account = (
            (ctx.request_fee_payer or local_fee_payer)
            if ctx.method_details.get("feePayer") is True and ctx.request_allows_fee_payer
            else None
        )
        expires = _expires.ensure(challenge.expires, challenge.id)
        replay_expires = _epoch_ms(expires)

        match ctx.payload.type:
            case "hash":
                assert validated.hash is not None
                assert validated.receipt is not None
                if not await _store.try_claim(
                    replay_store, _hash_key(validated.hash), replay_expires
                ):
                    raise CredentialReplayedError(reason="Transaction hash has already been used")
                # Only final hash receipts need this lookup; validation stays receipt-only.
                try:
                    transaction = await ctx.client.get_transaction(validated.hash)
                except Exception:
                    transaction = None
                funding_currency: str | None = None
                sender = validated.details.sender
                if (
                    isinstance(transaction, dict)
                    and isinstance(transaction.get("from"), str)
                    and sender is not None
                    and is_equal(transaction["from"], sender)
                ):
                    # Unrecognized calls do not invalidate an already verified payment.
                    with contextlib.suppress(Exception):
                        funding_currency = validate_payment_route(
                            _transaction_calls(transaction), ctx, validated.transfers
                        )
                return _receipt(validated.receipt.transaction_hash, funding_currency)

            case "proof":
                if proof_store is not None and not await _store.try_claim(
                    proof_store, f"mppx:charge:proof:{challenge.id}", replay_expires
                ):
                    raise CredentialReplayedError(reason="Proof credential has already been used")
                _expires.ensure(expires, challenge.id)
                return _receipt(challenge.id)

            case "transaction":
                return await broadcast_transaction(
                    ctx, validated, sponsor_account, expires, replay_expires
                )

    async def broadcast_transaction(
        ctx: _Context,
        validated: _Validated,
        sponsor_account: TempoAccount | None,
        expires: str,
        replay_expires: int,
    ) -> Receipt:
        transaction = validated.transaction
        serialized = validated.serialized_transaction
        assert transaction is not None
        assert serialized is not None
        client = ctx.client
        details = _details(ctx)
        policy = fee_payer_policy

        # Pre-broadcast dedup: catch exact byte-for-byte replays early.
        credential_hash = _keccak(serialized)
        if not await _store.try_claim(replay_store, _hash_key(credential_hash), replay_expires):
            raise CredentialReplayedError(reason="Transaction hash has already been used")

        # Set only after this request claims the final hash, so cleanup never releases a marker
        # that another request holds.
        claimed_final_hash: str | None = None
        # A locally sponsored submission whose outcome is unknown leaves a recovery record (the
        # exact envelope this server signed), so a retry reconciles it instead of signing and
        # paying again. ``keep_record`` is true while a submitted transaction may still land.
        recovery_key = _recovery_key(credential_hash) if sponsor_account is not None else None
        record_owned = False
        keep_record = False

        async def submit(final_serialized: str, final_hash: str) -> Receipt:
            nonlocal keep_record
            keep_record = True
            try:
                if wait_for_confirmation:
                    receipt = await _broadcast_and_confirm(
                        client,
                        final_serialized,
                        final_hash,
                        transaction,
                        confirmation_timeout_ms,
                    )
                    keep_record = False
                    return await settled(receipt, final_hash)
                # Optimistic path: broadcast without waiting (simulation already ran).
                reference = await client.send_raw_transaction(final_serialized)
            except Exception as error:
                if keep_record and not _is_ambiguous_broadcast_error(error):
                    keep_record = False
                raise
            keep_record = False
            if reference.lower() != final_hash.lower():
                raise VerificationFailedError(
                    reason="Broadcast transaction hash does not match the signed transaction"
                )
            return _receipt(reference, validated.funding_currency)

        async def settled(receipt: TransactionReceipt, final_hash: str) -> Receipt:
            matched = await assert_transfer_logs(
                receipt,
                currency=ctx.currency,
                sender=transaction_sender(transaction) or "",
                transfers=validated.transfers,
                challenge_id=ctx.challenge_id,
                realm=ctx.realm,
            )
            assert_challenge_bound_memo(
                matched,
                challenge_id=ctx.challenge_id,
                realm=ctx.realm,
                receipt=receipt,
                currency=ctx.currency,
            )
            if receipt.transaction_hash.lower() != final_hash.lower():
                raise VerificationFailedError(
                    reason="Broadcast transaction hash does not match the signed transaction"
                )
            return _receipt(receipt.transaction_hash, validated.funding_currency)

        async def claim_final_hash(final_hash: str) -> None:
            nonlocal claimed_final_hash
            if final_hash.lower() != credential_hash.lower():
                if not await _store.try_claim(replay_store, _hash_key(final_hash), replay_expires):
                    raise CredentialReplayedError(reason="Transaction hash has already been used")
                claimed_final_hash = final_hash

        async def reconcile(final_serialized: str) -> Receipt:
            """Settles a retry of an earlier submission from its receipt, never a new signing."""
            nonlocal keep_record
            final_hash = _keccak(final_serialized)
            await claim_final_hash(final_hash)
            try:
                receipt = await client.get_transaction_receipt(final_hash)
            except TransactionReceiptNotFoundError:
                pass
            else:
                keep_record = False
                return await settled(receipt, final_hash)
            valid_before = deserialize(final_serialized).valid_before
            now = time.time()
            if valid_before is None:
                raise InternalPaymentError(cause=RuntimeError("Recovery transaction has no expiry"))
            if valid_before >= math.ceil(now) + _MIN_REMAINING_VALIDITY_SECONDS:
                if (_expires.parse(expires) or _expires.now()) <= _expires.now():
                    raise InternalPaymentError(
                        cause=RuntimeError("Earlier submission has an unknown outcome")
                    )
                # Re-send only the exact envelope this server already signed and simulated.
                return await submit(final_serialized, final_hash)
            if valid_before + _VALID_BEFORE_GRACE_SECONDS < now and await _confirm_not_included(
                client, final_hash, valid_before
            ):
                keep_record = False
                raise VerificationFailedError(
                    reason="Sponsored transaction expired before it was included"
                )
            raise InternalPaymentError(
                cause=RuntimeError("Earlier submission has an unknown outcome")
            )

        try:
            if recovery_key is not None:
                recovered = await _read_recovery(replay_store, recovery_key)
                if recovered is not None:
                    record_owned = keep_record = True
                    receipt = await reconcile(recovered)
                    await replay_store.delete(recovery_key)
                    return receipt

            sponsor: str | None = None
            if sponsor_account is not None:
                selectable = ctx.allowed_fee_tokens or sponsorship.default_allowed_fee_tokens(
                    ctx.chain_id
                )

                async def complete_local() -> sponsorship.Sponsorship:
                    assert sponsor_account is not None
                    selected_fee_token = fee_token or await resolve_fee_token(
                        client,
                        account=sponsor_account.address,
                        allowed_tokens=selectable,
                        candidate_tokens=selectable,
                        prioritize_candidates=True,
                    )
                    sponsored = sponsorship.prepare_sponsored_transaction(
                        attrs.evolve(transaction, fee_token=selected_fee_token)
                        if selected_fee_token
                        else transaction,
                        chain_id=ctx.chain_id,
                        details=details,
                        allowed_fee_tokens=selectable,
                        challenge_expires=expires,
                        policy=policy,
                    )
                    return sponsorship.Sponsorship(
                        fee_payer=sponsor_account.address, transaction=sponsored
                    )

                completed = await sponsorship.preflight_sponsorship(
                    transaction, complete=complete_local, simulate=client.call
                )
                sponsorship.assert_transaction_policy(
                    completed.transaction,
                    chain_id=ctx.chain_id,
                    details=details,
                    challenge_expires=expires,
                    policy=policy,
                )
                completed_serialized = sponsorship.sign_as_fee_payer(
                    completed.transaction, sponsor_account
                )
                sponsor = completed.fee_payer
            elif remote_client is not None and validated.is_fee_payer_tx:

                async def complete_hosted() -> sponsorship.Sponsorship:
                    assert remote_client is not None
                    hosted = await sponsorship.fill_hosted_fee_payer_transaction(
                        transaction,
                        client=remote_client,
                        chain_id=ctx.chain_id,
                        details=details,
                        allowed_fee_tokens=ctx.allowed_fee_tokens,
                        challenge_expires=expires,
                        policy=policy,
                    )
                    return sponsorship.Sponsorship(
                        fee_payer=hosted.fee_payer,
                        fee_token=hosted.fee_token,
                        transaction=transaction,
                        serialized_transaction=hosted.serialized_transaction,
                    )

                completed = await sponsorship.preflight_sponsorship(
                    transaction, complete=complete_hosted, simulate=client.call
                )
                assert completed.serialized_transaction is not None
                completed_serialized = completed.serialized_transaction
                sponsor = completed.fee_payer
            else:
                completed_serialized = serialized

            # Nodes normalize accepted signature encodings before deriving transaction hashes;
            # broadcast the canonical envelope so replay keys match the node's hash.
            final_serialized = serialize(deserialize(completed_serialized))
            final_hash = _keccak(final_serialized)
            await claim_final_hash(final_hash)

            if validated.is_fee_payer_tx:
                if not sponsor:
                    raise VerificationFailedError(
                        reason="Sponsored transaction has no configured fee payer"
                    )
                sponsorship.assert_transaction_policy(
                    transaction,
                    chain_id=ctx.chain_id,
                    details=details,
                    challenge_expires=expires,
                    policy=policy,
                )
                _expires.ensure(expires, ctx.challenge_id)

            # Pre-broadcast simulation for non-sponsored transactions.
            if not validated.is_fee_payer_tx:
                await client.call(sponsorship.simulation_request(transaction, fee_payer=False))

            if validated.is_fee_payer_tx:
                sponsorship.assert_transaction_policy(
                    transaction,
                    chain_id=ctx.chain_id,
                    details=details,
                    challenge_expires=expires,
                    policy=policy,
                )

            # Authorize before the irreversible send: a challenge that expired during
            # sponsorship or simulation must not be settled.
            _expires.ensure(expires, ctx.challenge_id)
            if recovery_key is not None:
                # Persist the envelope before sending, failing closed: a submission whose outcome
                # could be lost must not be broadcast at all.
                try:
                    record_owned = await _create_recovery(
                        replay_store,
                        recovery_key,
                        final_serialized,
                        _recovery_expires(replay_expires, transaction.valid_before),
                    )
                except Exception as error:
                    raise InternalPaymentError(cause=error) from error
                if not record_owned:
                    raise InternalPaymentError(
                        cause=RuntimeError("Another submission owns this credential's recovery")
                    )
            receipt = await submit(final_serialized, final_hash)
            if recovery_key is not None:
                await replay_store.delete(recovery_key)
            return receipt
        except BaseException:
            # Only a successful settlement consumes the credential. A signed transaction can be
            # mined at most once, so a retry re-broadcasts it and recovers the receipt.
            if record_owned and not keep_record and recovery_key is not None:
                await replay_store.delete(recovery_key)
            if claimed_final_hash is not None:
                await replay_store.delete(_hash_key(claimed_final_hash))
            await replay_store.delete(_hash_key(credential_hash))
            raise

    defaults = {
        key: value
        for key, value in {
            "amount": amount,
            "currency": currency,
            "decimals": decimals,
            "description": description,
            "external_id": external_id,
            "recipient": accounts.recipient,
            "splits": list(splits) if splits is not None else None,
            "supported_modes": list(supported_modes) if supported_modes is not None else None,
        }.items()
        if value is not None
    }
    method = ServerMethod(
        method=methods.charge,
        validate=validate,
        broadcast=broadcast,
        resolve_request=resolve_request,
        can_offer=can_offer,
        on_payment_success=on_payment_success,
        stable_binding=charge_binding,
        defaults=defaults,
    )
    return _relay.configure(method, relay) if relay is not None else method


def charge_binding(request: dict[str, Any]) -> dict[str, Any]:
    """Wire request fields a Tempo charge credential is bound to (``feePayer`` excluded)."""
    method_details = request.get("methodDetails") or {}
    return {
        "amount": request.get("amount"),
        "chainId": method_details.get("chainId"),
        "currency": request.get("currency"),
        "description": request.get("description"),
        "externalId": request.get("externalId"),
        "recipient": request.get("recipient"),
        "splits": method_details.get("splits"),
        "supportedModes": method_details.get("supportedModes"),
    }


# -- helpers -----------------------------------------------------------------------------------


def _normalize_input(request: Mapping[str, Any]) -> dict[str, Any]:
    """Maps camelCase route-input keys to :class:`~mpp.tempo.methods.ChargeRequest` field names."""
    return {_REQUEST_FIELDS.get(key, key): value for key, value in request.items()}


def _wire_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Transforms route input to the wire request; HMAC-bound wire requests pass through."""
    try:
        return methods.charge.normalize_request(_normalize_input(request))
    except (ValidationError, ValueError, TypeError):
        return dict(request)


def _details(context: _Context) -> dict[str, str]:
    return {"amount": context.amount, "currency": context.currency, "recipient": context.recipient}


def _keccak(serialized: str) -> str:
    return to_hex(keccak256(to_bytes(serialized)))


def _hash_key(transaction_hash: str) -> str:
    return f"mppx:charge:{transaction_hash.lower()}"


def _recovery_key(transaction_hash: str) -> str:
    return f"mppx:charge:recovery:{transaction_hash.lower()}"


def _recovery_expires(challenge_expires_ms: int, valid_before: int | None) -> int:
    """Keeps a recovery record through the challenge and the transaction's inclusion window."""
    if valid_before is None:
        return challenge_expires_ms
    return max(challenge_expires_ms, (valid_before + _VALID_BEFORE_GRACE_SECONDS) * 1000)


async def _read_recovery(store: _store.AtomicStore, key: str) -> str | None:
    """Returns the live recovery envelope for ``key``, raising when the record is unusable."""
    record = await store.get(key)
    if record is None:
        return None
    if (
        not isinstance(record, dict)
        or record.get("type") != _RECOVERY_TYPE
        or not isinstance(record.get("transaction"), str)
        or not is_tempo_transaction(record["transaction"])
        or not isinstance(record.get("expires"), int)
    ):
        raise InternalPaymentError(
            cause=RuntimeError("Recovery record lacks the original signed transaction")
        )
    if record["expires"] <= time.time() * 1000:
        return None
    return record["transaction"]


async def _create_recovery(
    store: _store.AtomicStore, key: str, serialized: str, expires: int
) -> bool:
    """Atomically stores a recovery envelope unless a live record already exists."""
    record = {"expires": expires, "transaction": serialized, "type": _RECOVERY_TYPE}

    def change(current: Any | None) -> _store.Change[bool]:
        live = (
            isinstance(current, dict)
            and isinstance(current.get("expires"), int)
            and current["expires"] > time.time() * 1000
        )
        return _store.Noop(False) if live else _store.Set(record, True)

    return await store.update(key, change)


async def _confirm_not_included(
    client: RpcClient, transaction_hash: str, valid_before: int
) -> bool:
    """Whether chain time shows ``transaction_hash`` can no longer be included.

    The latest block must be at or past ``valid_before``, and a receipt lookup made after
    reading that block must still find nothing.
    """
    try:
        block = await client.get_block("latest")
        timestamp = int(str((block or {}).get("timestamp")), 0)
    except Exception:
        return False
    if timestamp < valid_before:
        return False
    try:
        await client.get_transaction_receipt(transaction_hash)
    except TransactionReceiptNotFoundError:
        return True
    except Exception:
        return False
    return False


def _epoch_ms(value: str) -> int:
    parsed = _expires.parse(value)
    assert parsed is not None
    return math.floor(parsed.timestamp() * 1000)


def _recovers(digest: bytes, signature: str, address: str) -> bool:
    """Whether a secp256k1 ``signature`` over ``digest`` recovers to ``address``."""
    try:
        return is_equal(recover_address(digest, parse_secp256k1(signature)), address)
    except Exception:
        return False


def _receipt(reference: str, funding_currency: str | None = None) -> Receipt:
    return Receipt(
        method="tempo",
        reference=reference,
        timestamp=_expires.to_iso(_expires.now()),
        funding_currency=funding_currency or None,
    )


def _parse_hash_source(chain_id: int | None, source: str | None) -> PkhSource | None:
    if not source:
        return None
    parsed = parse_pkh_source(source)
    if parsed is None or (chain_id is not None and parsed.chain_id != chain_id):
        raise MismatchError("Hash credential source is invalid.", {})
    return parsed


def _transaction_calls(transaction: Mapping[str, Any]) -> list[Call]:
    raw_calls = transaction.get("calls")
    if isinstance(raw_calls, list):
        return [
            Call(
                to=call.get("to") or "",
                data=call.get("data") or call.get("input") or "0x",
                value=_quantity(call.get("value")),
            )
            for call in raw_calls
            if isinstance(call, dict)
        ]
    if transaction.get("to"):
        return [Call(to=transaction["to"], data=transaction.get("input") or "0x")]
    return []


def _quantity(value: Any) -> int:
    if value in (None, "0x", ""):
        return 0
    return int(value, 16) if isinstance(value, str) else int(value)


def _is_ambiguous_broadcast_error(error: BaseException) -> bool:
    """Whether a failed synchronous broadcast may still have reached the mempool.

    Ambiguous outcomes, matched anywhere in the ``__cause__`` chain: timeouts
    (including the local confirmation deadline), lost connections (transport
    failures without a status or with a 5xx status), JSON-RPC code ``4`` (the
    EIP-7966 timeout for a pooled transaction), and "already known" / "known
    transaction" messages. Every other error is a definitive rejection.
    """
    cause: BaseException | None = error
    while cause is not None:
        if isinstance(cause, RpcTransportError):
            return cause.status is None or cause.status >= 500
        if isinstance(cause, httpx.HTTPStatusError):
            return cause.response.status_code >= 500
        if isinstance(cause, TimeoutError | httpx.TimeoutException | httpx.NetworkError):
            return True
        if isinstance(cause, RpcError) and cause.code == 4:
            return True
        if _AMBIGUOUS_MESSAGE.search(str(cause)):
            return True
        cause = cause.__cause__
    return False


async def _broadcast_and_confirm(
    client: RpcClient,
    serialized: str,
    transaction_hash: str,
    transaction: TempoTransaction,
    timeout_ms: int,
) -> TransactionReceipt:
    """Broadcasts synchronously, recovering the receipt after an ambiguous failure."""
    start = time.monotonic()
    # The sync send gets at most 2/3 of the budget, reserving the rest for recovery.
    send_timeout_ms = math.floor(timeout_ms * 2 / 3)
    deadline = start + timeout_ms / 1000
    # An expiring transaction can no longer be included after this point.
    valid_until = (
        math.inf
        if transaction.valid_before is None
        else start + (transaction.valid_before * 1000 + 2000 - time.time() * 1000) / 1000
    )
    try:
        try:
            return await asyncio.wait_for(
                client.send_raw_transaction_sync(serialized, timeout_ms=send_timeout_ms),
                send_timeout_ms / 1000,
            )
        except TimeoutError as error:
            if isinstance(error, TransactionReceiptTimeoutError):
                raise
            raise TransactionReceiptTimeoutError(transaction_hash) from None
    except Exception as broadcast_error:
        if not _is_ambiguous_broadcast_error(broadcast_error):
            raise
        # The node may have accepted the transaction, so poll for its receipt.
        recovered: TransactionReceipt | None = None
        remaining = min(deadline, valid_until) - time.monotonic()
        if remaining > 0:
            try:
                recovered = await client.wait_for_transaction_receipt(
                    transaction_hash, timeout_seconds=remaining
                )
            except Exception:
                recovered = None
        # When the validity cap ends polling, a transaction mined just before `validBefore`
        # may only now be visible, so look it up exactly once more.
        if recovered is None and valid_until < deadline:
            try:
                recovered = await asyncio.wait_for(
                    client.get_transaction_receipt(transaction_hash),
                    max(deadline, time.monotonic() + client.polling_interval) - time.monotonic(),
                )
            except Exception:
                recovered = None
        if recovered is None:
            raise
        return recovered
