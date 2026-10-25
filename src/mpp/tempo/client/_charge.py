"""Tempo charge intent (one-time TIP-20 transfer) for clients."""

from __future__ import annotations

import asyncio
import math
import secrets
import time
from collections.abc import Sequence
from typing import Any

import attrs
from pydantic import BaseModel, ConfigDict, ValidationError
from pytempo import Call, TempoTransaction

from mpp import expires as _expires
from mpp.credential import Credential
from mpp.errors import PaymentExpiredError
from mpp.method import ClientMethod, CredentialParams, resolve
from mpp.tempo import attribution, methods
from mpp.tempo._internal import abi
from mpp.tempo._internal.account import TempoAccount
from mpp.tempo._internal.address import resolve as resolve_address
from mpp.tempo._internal.charge import get_transfers, splits_from_method_details
from mpp.tempo._internal.envelope import (
    EXPIRING_NONCE_KEY,
    SERIALIZED_TYPE,
    InvalidTransactionError,
    deserialize,
    has_fee_payer,
    serialize,
    serialize_for_fee_payer,
)
from mpp.tempo._internal.fee_token import default_fee_tokens, resolve_fee_token
from mpp.tempo._internal.hexutil import keccak256, to_bytes, to_hex
from mpp.tempo._internal.proof import proof_source, typed_data
from mpp.tempo._internal.rpc import RpcClient, RpcError, call_request
from mpp.tempo._internal.units import parse_units
from mpp.tempo.assets import MACH_ADDRESS
from mpp.tempo.client._resolve_account import (
    ExecuteCalls,
    ResolveAccount,
    ResolveAccountInfo,
    ResolveAccountOperation,
    SignPaymentProof,
)
from mpp.tempo.server._internal.clients import ClientResolver, GetClient

type ChargeMode = methods.ChargeMode

# Lifetime of the expiring-nonce ``validBefore`` (capped at the challenge expiry). Sponsoring
# servers need 15 s of remaining validity at cosigning; 60 s (pympp, wider than mppx's 25 s)
# leaves about 45 s for clock skew, signing and the HTTP and RPC round trips.
_VALIDITY_SECONDS = 60
_MIN_SPONSORED_SECONDS = 15
_GAS_BUFFER = 5_000
_BASE_FEE_MULTIPLIER_NUM, _BASE_FEE_MULTIPLIER_DEN = 12, 10


class ChargeContext(BaseModel):
    """Per-request context accepted by the Tempo charge client (``context=`` on fetch)."""

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    account: TempoAccount | None = None
    """Signing account."""
    mode: ChargeMode | None = None


def charge(
    *,
    account: TempoAccount | None = None,
    client_id: str | None = None,
    expected_chain_id: int | None = None,
    allowed_chain_ids: Sequence[int] | None = None,
    expected_recipients: Sequence[str] | None = None,
    currencies: Sequence[str] | None = None,
    decimals: int | None = None,
    max_amount: str | None = None,
    max_atomic_amount: str | None = None,
    mode: ChargeMode | None = None,
    resolve_account: ResolveAccount | None = None,
    get_client: GetClient | None = None,
) -> ClientMethod:
    """Creates a Tempo charge method for clients.

    Args:
        account: Signing account (can be overridden per request via ``context``).
        client_id: Client identifier fingerprinted into attribution memos.
        expected_chain_id: Only pay on this chain (also used when a challenge omits it).
        allowed_chain_ids: Chains permitted for payment (empty rejects all).
        expected_recipients: Allowlist for the primary and every split recipient.
        currencies: Allowlist of TIP-20 currencies (required with ``max_amount`` caps).
        decimals: Decimals of ``currencies``, used to parse ``max_amount``.
        max_amount: Maximum display-unit amount per charge (exact; never rounded).
        max_atomic_amount: Maximum base-unit amount per charge.
        mode: ``"push"`` (client broadcasts, sends the hash) or ``"pull"`` (server
            broadcasts the signed transaction). Defaults to ``"pull"``.
        resolve_account: Selects the signing account once the challenge and chain are known.
        get_client: Returns the RPC client for a chain ID (default: public Tempo RPC).
    """
    # Caps are denominated in the challenge currency, so they require a currency pin.
    if (max_amount is not None or max_atomic_amount is not None) and currencies is None:
        raise ValueError("Tempo charge maxAmount and maxAtomicAmount require currencies.")
    policy = _Policy(
        expected_chain_id=expected_chain_id,
        allowed_chain_ids=allowed_chain_ids,
        expected_recipients=expected_recipients,
        currencies=currencies,
        max_amount=_parse_max_amount(max_amount, decimals),
        max_atomic_amount=int(max_atomic_amount) if max_atomic_amount is not None else None,
    )
    clients = ClientResolver(get_client=get_client)

    def can_handle_challenge(challenge: Any) -> bool:
        # Skip offers that violate client policy so an acceptable offer can be chosen.
        try:
            policy.check(challenge.request)
        except Exception:
            # Malformed offers are skipped too, like mppx (which catches any error).
            return False
        return True

    async def create(params: CredentialParams[ChargeContext]) -> str:
        challenge = params.challenge
        context = params.context or ChargeContext()
        request = challenge.request
        policy.check(request)
        method_details: dict[str, Any] = request.get("methodDetails") or {}
        # Sign on the pinned chain when the challenge omits a chain ID.
        resolved_chain_id: int | None = (
            method_details.get("chainId")
            or expected_chain_id
            or (allowed_chain_ids[0] if allowed_chain_ids and len(allowed_chain_ids) == 1 else None)
        )
        client = await clients(resolved_chain_id)
        # Reject a resolved client whose chain conflicts with the payment chain.
        client_chain_id = await clients.chain_id_of(client)
        if resolved_chain_id is not None and client_chain_id != resolved_chain_id:
            raise ValueError(
                f"Chain ID mismatch: expected {resolved_chain_id}, got {client_chain_id}."
            )
        chain_id = client_chain_id
        _assert_allowed_chain_id(allowed_chain_ids, chain_id)

        amount = str(request["amount"])
        supported_modes: list[str] = method_details.get("supportedModes") or ["pull", "push"]
        default_account = context.account or account
        if default_account is None:
            raise ValueError("No `account` provided. Pass `account` to parameters or context.")

        async def select_account(operation: ResolveAccountOperation) -> TempoAccount:
            if resolve_account is None:
                return default_account
            selected = await resolve(
                resolve_account(
                    ResolveAccountInfo(
                        account=default_account, chain_id=chain_id, operation=operation
                    )
                )
            )
            return selected or default_account

        # Zero amount: sign EIP-712 typed data instead of creating a transaction.
        if int(amount) == 0:
            signer = await select_account(SignPaymentProof())
            proof_data = typed_data(
                account=signer.address,
                chain_id=chain_id,
                challenge_id=challenge.id,
                realm=challenge.realm,
            )
            signature = signer.sign_typed_data(proof_data)
            return Credential(
                challenge=challenge,
                payload={"signature": signature, "type": "proof"},
                source=proof_source(address=signer.address, chain_id=chain_id),
            ).serialize()

        currency = str(request["currency"])
        memo = attribution.encode(
            challenge_id=challenge.id, server_id=challenge.realm, client_id=client_id
        )
        transfers = get_transfers(
            amount=amount,
            recipient=str(request.get("recipient")),
            memo=memo,
            splits=splits_from_method_details(method_details),
        )
        # Every leg without a fixed memo carries this challenge's memo, so no leg of the
        # payment can be shared with another challenge in a batch.
        transfer_calls = [
            Call(
                to=resolve_address(currency),
                data=abi.TRANSFER_WITH_MEMO.encode(
                    transfer.recipient, int(transfer.amount), to_bytes(transfer.memo or memo)
                ),
            )
            for transfer in transfers
        ]
        selected = await select_account(ExecuteCalls(calls=transfer_calls))
        calls = transfer_calls
        fee_token: str | None = None
        # MACH cannot pay transaction fees; pay them in a funded supported stablecoin.
        if currency.lower() == MACH_ADDRESS.lower():
            allowed_fee_tokens = default_fee_tokens(chain_id)
            fee_token = await resolve_fee_token(
                client,
                account=selected.address,
                allowed_tokens=allowed_fee_tokens,
                candidate_tokens=allowed_fee_tokens,
                prioritize_candidates=True,
            )

        explicit_mode = context.mode or mode
        if explicit_mode is not None:
            if explicit_mode not in supported_modes:
                raise ValueError(f"Challenge does not support {explicit_mode} mode.")
            selected_mode = explicit_mode
        else:
            selected_mode = "pull" if "pull" in supported_modes else supported_modes[0]

        if selected_mode == "pull" and method_details.get("feePayer"):
            _assert_sponsorable(challenge.expires)
        source = proof_source(address=selected.address, chain_id=chain_id)
        valid_before = _valid_before(challenge.expires)
        prepared = await _prepare_transaction(
            client,
            account=selected,
            chain_id=chain_id,
            calls=calls,
            fee_token=fee_token,
            valid_before=valid_before,
        )

        if selected_mode == "push":
            receipt = await client.send_raw_transaction_sync(
                serialize(selected.sign_transaction(prepared))
            )
            return Credential(
                challenge=challenge,
                payload={"hash": receipt.transaction_hash, "type": "hash"},
                source=source,
            ).serialize()

        # Estimate before enabling fee-payer mode so Tempo includes sender signature and
        # access-key verification costs in the gas budget.
        prepared = attrs.evolve(prepared, gas_limit=prepared.gas_limit + _GAS_BUFFER)
        if method_details.get("feePayer"):
            signed = selected.sign_transaction(
                attrs.evolve(
                    prepared, awaiting_fee_payer=True, fee_payer_signature=None, fee_token=None
                )
            )
            serialized = serialize_for_fee_payer(signed)
        else:
            serialized = serialize(selected.sign_transaction(prepared))
        return Credential(
            challenge=challenge,
            payload={"signature": serialized, "type": "transaction"},
            source=source,
        ).serialize()

    # Share an in-flight signing so concurrent calls for one challenge cannot yield two
    # independently settleable transactions. Settled signings are not reused.
    signing: dict[str, asyncio.Future[str]] = {}

    async def create_credential(params: CredentialParams[ChargeContext]) -> str:
        # Enforce client policy on every call, including ones joining a signing.
        policy.check(params.challenge.request)
        signer = (params.context.account if params.context else None) or account
        key = f"{signer.address.lower() if signer else ''}:{params.challenge.id}"
        task = signing.get(key)
        if task is None:
            task = asyncio.ensure_future(create(params))
            signing[key] = task
            task.add_done_callback(lambda _: signing.pop(key, None))
        return await asyncio.shield(task)

    return ClientMethod(
        method=methods.charge,
        create_credential=create_credential,
        can_handle_challenge=can_handle_challenge,
        context=ChargeContext,
        transaction_hash=transaction_hash,
    )


def transaction_hash(credential: str) -> str | None:
    """The final transaction hash of a credential, when known before settlement.

    Push credentials carry the broadcast hash; pull credentials hash a canonical,
    sender-signed ``0x76`` transaction. Sponsored transactions (``0x78`` envelopes
    or ``0x76`` awaiting a fee payer) return ``None``: the co-signature changes the hash.
    """
    try:
        payload = methods.ChargePayload.model_validate(
            Credential.deserialize(credential).payload
        ).root
    except (ValidationError, ValueError):
        return None
    if isinstance(payload, methods.HashPayload):
        return payload.hash
    serialized = payload.signature
    if not isinstance(payload, methods.TransactionPayload) or not serialized.startswith(
        SERIALIZED_TYPE
    ):
        return None
    try:
        transaction = deserialize(serialized)
        # Reject trailing or non-canonical bytes, which never identify an on-chain transaction.
        canonical = serialize(transaction)
    except (InvalidTransactionError, ValueError):
        return None
    if transaction.sender_signature is None or (
        has_fee_payer(transaction) and transaction.fee_payer_signature is None
    ):
        return None
    if canonical != serialized:
        return None
    return to_hex(keccak256(to_bytes(serialized)))


# -- policy ------------------------------------------------------------------------------------


class _Policy:
    def __init__(
        self,
        *,
        expected_chain_id: int | None,
        allowed_chain_ids: Sequence[int] | None,
        expected_recipients: Sequence[str] | None,
        currencies: Sequence[str] | None,
        max_amount: int | None,
        max_atomic_amount: int | None,
    ) -> None:
        self.expected_chain_id = expected_chain_id
        self.allowed_chain_ids = allowed_chain_ids
        self.expected_recipients = (
            {r.lower() for r in expected_recipients} if expected_recipients is not None else None
        )
        self.currencies = {c.lower() for c in currencies} if currencies is not None else None
        self.max_amount = max_amount
        self.max_atomic_amount = max_atomic_amount

    def check(self, request: dict[str, Any]) -> None:
        """Rejects a challenge whose chain, currency, recipients, amount or split memos violate
        policy."""
        method_details = request.get("methodDetails") or {}
        chain_id = method_details.get("chainId")
        if (
            self.expected_chain_id is not None
            and chain_id is not None
            and chain_id != self.expected_chain_id
        ):
            raise ValueError(
                f"Chain ID mismatch: expected {self.expected_chain_id}, got {chain_id}."
            )
        if chain_id is not None or (
            self.allowed_chain_ids is not None and len(self.allowed_chain_ids) == 0
        ):
            _assert_allowed_chain_id(self.allowed_chain_ids, chain_id)
        currency = str(request.get("currency", ""))
        if self.currencies is not None and currency.lower() not in self.currencies:
            raise ValueError(f"Tempo charge currency is not allowed: {currency}.")
        for split in method_details.get("splits") or []:
            # A fixed split leg with an MPP attribution memo could also pay another challenge.
            memo = split.get("memo")
            if isinstance(memo, str) and attribution.is_mpp_memo(memo):
                raise ValueError(methods.FIXED_ATTRIBUTION_MEMO_ERROR)
        if self.expected_recipients is not None:
            recipient = request.get("recipient")
            if not recipient or str(recipient).lower() not in self.expected_recipients:
                raise ValueError(f"Unexpected primary recipient: {recipient}")
            for split in method_details.get("splits") or []:
                if str(split.get("recipient", "")).lower() not in self.expected_recipients:
                    raise ValueError(f"Unexpected split recipient: {split.get('recipient')}")
        amount = int(request.get("amount", 0))
        if self.max_atomic_amount is not None and amount > self.max_atomic_amount:
            raise ValueError("Tempo charge amount exceeds maxAtomicAmount.")
        if self.max_amount is not None and amount > self.max_amount:
            raise ValueError("Tempo charge amount exceeds maxAmount.")


def _assert_allowed_chain_id(allowed: Sequence[int] | None, chain_id: int | None) -> None:
    if allowed is not None and (chain_id is None or chain_id not in allowed):
        raise ValueError(
            f"Chain ID not allowed: {chain_id if chain_id is not None else 'unknown'}."
        )


def _parse_max_amount(max_amount: str | None, decimals: int | None) -> int | None:
    """Parses ``max_amount`` to base units, rejecting values that cannot be exact."""
    if max_amount is None:
        return None
    if decimals is None:
        raise ValueError("Tempo charge maxAmount requires currency decimals.")
    fraction = max_amount.partition(".")[2].rstrip("0")
    if len(fraction) > decimals:
        raise ValueError(
            f"Tempo charge maxAmount {max_amount} has more fractional digits than "
            f"{decimals} decimals allow."
        )
    return parse_units(max_amount, decimals)


# -- transactions ------------------------------------------------------------------------------


def _valid_before(expires: str | None, *, now: float | None = None) -> int:
    default_expiry = math.floor(time.time() if now is None else now) + _VALIDITY_SECONDS
    parsed = _expires.parse(expires) if expires else None
    if parsed is None:
        return default_expiry
    # `validBefore` is an exclusive whole-second bound: cap at the second after a (possibly
    # fractional) expiry to stay valid as long as the challenge.
    return min(default_expiry, math.floor(parsed.timestamp()) + 1)


def _assert_sponsorable(expires: str | None, *, now: float | None = None) -> None:
    """Refuses a sponsored challenge too close to expiry for the server to cosign.

    ``validBefore`` is capped at the challenge expiry and a sponsoring server rejects
    transactions with less than 15 s of validity left, so signing could only produce a
    rejected payment.
    """
    parsed = _expires.parse(expires) if expires else None
    if parsed is None:
        return
    if parsed.timestamp() - (time.time() if now is None else now) < _MIN_SPONSORED_SECONDS:
        raise PaymentExpiredError(expires=expires) from ValueError(
            f"Sponsored challenge expires in less than {_MIN_SPONSORED_SECONDS} seconds; "
            "request a new challenge"
        )


def _random_valid_after() -> int:
    """Random past second distinguishing otherwise-identical expiring transactions."""
    latest = math.floor(time.time()) - 60
    return 0 if latest <= 0 else secrets.randbits(64) % latest


def _quantity(value: Any) -> int | None:
    if value is None:
        return None
    return int(value, 16) if isinstance(value, str) else int(value)


async def _prepare_transaction(
    client: RpcClient,
    *,
    account: TempoAccount,
    chain_id: int,
    calls: Sequence[Call],
    fee_token: str | None,
    valid_before: int,
) -> TempoTransaction:
    """Fills gas and fees for an expiring-nonce transaction (``eth_fillTransaction``)."""
    transaction = TempoTransaction(
        chain_id=chain_id,
        gas_limit=0,
        calls=tuple(calls),
        nonce_key=EXPIRING_NONCE_KEY,
        nonce=0,
        valid_before=valid_before,
        valid_after=_random_valid_after(),
        fee_token=fee_token,
        sender_address=account.address,
    )
    request = call_request(transaction=transaction, sender=account.address)
    try:
        result = await client.fill_transaction(request)
        filled = result.get("tx") if isinstance(result, dict) else None
        if not isinstance(filled, dict):
            raise RpcError(-32603, "eth_fillTransaction returned no transaction")
        max_fee = _quantity(filled.get("maxFeePerGas")) or 0
        return attrs.evolve(
            transaction,
            gas_limit=_quantity(filled.get("gas")) or 0,
            max_fee_per_gas=max_fee * _BASE_FEE_MULTIPLIER_NUM // _BASE_FEE_MULTIPLIER_DEN,
            max_priority_fee_per_gas=_quantity(filled.get("maxPriorityFeePerGas")) or 0,
            fee_token=fee_token or filled.get("feeToken") or None,
        )
    except RpcError as error:
        if error.code not in (-32601, -32004) and "not available" not in error.message:
            raise
    # Nodes without `eth_fillTransaction`: estimate gas and EIP-1559 fees individually.
    gas = await client.estimate_gas(request)
    priority = await client.max_priority_fee_per_gas()
    block = await client.get_block("latest") or {}
    base_fee = _quantity(block.get("baseFeePerGas")) or 0
    return attrs.evolve(
        transaction,
        gas_limit=gas,
        max_fee_per_gas=base_fee * _BASE_FEE_MULTIPLIER_NUM // _BASE_FEE_MULTIPLIER_DEN + priority,
        max_priority_fee_per_gas=priority,
    )
