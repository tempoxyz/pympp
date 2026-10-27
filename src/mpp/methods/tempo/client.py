"""Tempo charge for clients.

:func:`charge` returns the :class:`~mpp.runtime.ClientMethod` that pays Tempo
charge challenges; :class:`TempoMethod` implements its credential creation.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, cast

from mpp import Challenge, Credential
from mpp.errors import PaymentExpiredError
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._defaults import (
    CHAIN_ID,
    MACH,
    OUSD,
    RPC_URL,
    default_currencies_for_chain,
    default_currency_for_chain,
    fee_tokens_for_chain,
    rpc_url_for_chain,
)
from mpp.methods.tempo._rpc import _rpc_call, _tip20_balance, estimate_gas
from mpp.methods.tempo.fee_payer_policy import MIN_REMAINING_VALIDITY_SECONDS, get_policy

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mpp.methods.tempo.account import TempoAccount
    from mpp.runtime import ClientMethod


# Tempo AA (type-0x76) transactions have higher intrinsic gas than legacy txs
# (~270k for a single TIP-20 transfer). A safe static limit avoids the need for
# AA-aware eth_estimateGas calls, matching the approach used by mpp-rs.
DEFAULT_GAS_LIMIT = 1_000_000
EXPIRING_NONCE_KEY = (1 << 256) - 1  # U256::MAX
# Lifetime of the expiring-nonce ``valid_before`` the client signs, capped at
# the challenge expiry + 1. Sponsoring servers require at least
# MIN_REMAINING_VALIDITY_SECONDS (15s) of remaining validity at cosigning, so a
# 60s window leaves about 45s for client/server clock skew, signing and the
# HTTP and RPC round trips. Deliberately wider than mppx's 25s, and well under
# Tempo's expiring-nonce cap (300s since T11; it was 30s before).
EXPIRING_NONCE_VALID_BEFORE_SECS = 60
FEE_PAYER_VALID_BEFORE_SECS = EXPIRING_NONCE_VALID_BEFORE_SECS  # Deprecated alias.
# Tempo gas prices use attodollars (10^-18 USD) while TIP-20 fee tokens use
# microdollars (10^-6 USD).
ATTODOLLARS_PER_MICRODOLLAR = 10**12
_CHAIN_ID_UNSET = object()
_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_ATOMIC_AMOUNT_RE = re.compile(r"[0-9]+")
_CAPS_REQUIRE_CURRENCY_PIN = (
    "Tempo charge max_amount and max_atomic_amount require a currency pin "
    "(currency= or currencies=)."
)


class TransactionError(Exception):
    """Transaction building or submission failed.

    Error messages are sanitized to avoid leaking sensitive transaction data.
    """


# ──────────────────────────────────────────────────────────────────
# Charge client method
# ──────────────────────────────────────────────────────────────────


@dataclass
class TempoMethod:
    """Tempo payment method implementation.

    Handles client-side credential creation for Tempo payments. Create it with
    :func:`charge`, which wraps it in a client method.
    """

    name: str = "tempo"
    account: TempoAccount | None = None
    fee_payer: TempoAccount | None = None
    root_account: str | None = None
    rpc_url: str = RPC_URL
    chain_id: int | None = None
    currency: str | None = None
    recipient: str | None = None
    decimals: int = 6
    client_id: str | None = None
    # Accepted currencies in offer order. With more than one, servers issue one
    # charge offer per currency unless a request overrides ``currency``.
    currencies: tuple[str, ...] = field(default=(), kw_only=True)
    # Server-side local fee sponsorship: the token the fee payer pays gas in,
    # and the tokens it may select. ``None`` selects defaults at broadcast.
    fee_token: str | None = field(default=None, kw_only=True)
    allowed_fee_tokens: tuple[str, ...] | None = field(default=None, kw_only=True)
    # Client-side charge policy. ``max_atomic_amount`` is in base units;
    # ``max_amount`` is in token units and requires ``max_amount_decimals``.
    # Caps are validated at construction and read on every check. ``None``
    # disables a check.
    max_atomic_amount: int | str | None = field(default=None, kw_only=True)
    max_amount: str | Decimal | None = field(default=None, kw_only=True)
    max_amount_decimals: int | None = field(default=None, kw_only=True)
    expected_recipients: tuple[str, ...] | None = field(default=None, kw_only=True)
    # Chains a client may pay on. ``None`` allows any chain; empty rejects all.
    allowed_chain_ids: Sequence[int] | None = field(default=None, kw_only=True)
    _cached_chain_ids: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _chain_id_explicit: bool = field(default=False, init=False, repr=False)
    _currency_explicit: bool = field(default=True, init=False, repr=False)
    _chain_id_lock: asyncio.Lock | None = field(default=None, init=False, repr=False)
    _rpc_url_explicit: bool = field(default=False, init=False, repr=False)
    _signing: dict[tuple[str, str], asyncio.Task[Credential]] = field(
        default_factory=dict, init=False, repr=False
    )

    def __post_init__(self) -> None:
        """Validate charge policy at construction."""
        self._amount_caps()
        if self.allowed_chain_ids is not None:
            if isinstance(self.allowed_chain_ids, (str, bytes)):
                raise ValueError("allowed_chain_ids must be a sequence of chain IDs")
            self.allowed_chain_ids = tuple(self.allowed_chain_ids)
            for chain_id in self.allowed_chain_ids:
                if not isinstance(chain_id, int) or isinstance(chain_id, bool):
                    raise ValueError(f"Invalid Tempo chain ID: {chain_id!r}")

    def _amount_caps(self) -> tuple[int | None, int | None]:
        """Return ``(max_atomic_amount, max_amount)`` in base units from the current fields."""
        max_atomic = (
            None
            if self.max_atomic_amount is None
            else _parse_max_atomic_amount(self.max_atomic_amount)
        )
        max_token = None
        if self.max_amount is not None:
            if self.max_amount_decimals is None:
                raise ValueError("Tempo charge max_amount requires max_amount_decimals.")
            max_token = _parse_max_amount(self.max_amount, self.max_amount_decimals)
        if (max_atomic is not None or max_token is not None) and not self._pinned_currencies():
            raise ValueError(_CAPS_REQUIRE_CURRENCY_PIN)
        return max_atomic, max_token

    def _pinned_currencies(self) -> tuple[str, ...]:
        """Return the currencies the client explicitly pinned, or ``()``."""
        if not self._currency_explicit:
            return ()
        if self.currencies:
            return self.currencies
        return () if self.currency is None else (self.currency,)

    async def _get_chain_id(self, rpc_url: str) -> int:
        """Fetch the chain ID once per RPC URL and reuse it for later requests."""
        cached = self._cached_chain_ids.get(rpc_url)
        if cached is not None:
            return cached

        if self._chain_id_lock is None:
            self._chain_id_lock = asyncio.Lock()

        async with self._chain_id_lock:
            cached = self._cached_chain_ids.get(rpc_url)
            if cached is not None:
                return cached

            chain_id_hex = await _rpc_call(rpc_url, "eth_chainId", [])
            chain_id = int(chain_id_hex, 16)
            self._cached_chain_ids[rpc_url] = chain_id
            return chain_id

    async def _resolve_expected_chain_id(self) -> int | None:
        """Return the chain ID pinned by local client configuration.

        A client may pin the chain explicitly via ``chain_id`` or implicitly by
        supplying a custom ``rpc_url``. In the latter case, trust the chain
        reported by that RPC instead of the server challenge.
        """
        if self._rpc_url_explicit and not self._chain_id_explicit:
            return await self._get_chain_id(self.rpc_url)
        if self.chain_id is not None:
            return self.chain_id
        if self.rpc_url:
            return await self._get_chain_id(self.rpc_url)
        return None

    def _known_expected_chain_id(self) -> int | None:
        """Return the chain ID pin when it is known without an RPC call.

        Mirrors :meth:`_resolve_expected_chain_id`, reading an RPC-reported
        chain ID only once it has been cached.
        """
        if self._rpc_url_explicit and not self._chain_id_explicit:
            return self._cached_chain_ids.get(self.rpc_url)
        if self.chain_id is not None:
            return self.chain_id
        return self._cached_chain_ids.get(self.rpc_url)

    async def _resolve_supported_fee_token(
        self,
        *,
        account: str,
        chain_id: int,
        rpc_url: str,
        required_balance: int,
    ) -> str:
        """Return a stablecoin that can cover the transaction fee."""
        for token in fee_tokens_for_chain(chain_id):
            try:
                if await _tip20_balance(rpc_url, token, account) >= required_balance:
                    return token
            except Exception:
                continue
        raise TransactionError("Charges require a funded supported stablecoin for transaction fees")

    def _check_charge_policy(self, request: dict, expected_chain_id: int | None) -> None:
        """Reject a challenge whose chain, recipients, amount or split memos violate the policy.

        Runs during challenge selection and again before signing.
        """
        challenge_chain_id = _challenge_chain_id(request)
        if (
            expected_chain_id is not None
            and challenge_chain_id is not None
            and challenge_chain_id != expected_chain_id
        ):
            raise ValueError(
                f"Challenge requests chain ID {challenge_chain_id}, "
                f"but client is restricted to {expected_chain_id}"
            )
        self._check_allowed_chain_id(
            challenge_chain_id if challenge_chain_id is not None else expected_chain_id
        )
        _check_recipient_addresses(request)
        self._check_expected_recipients(request)
        self._check_amount_caps(request)
        from mpp.methods.tempo.schemas import reject_fixed_attribution_memos

        reject_fixed_attribution_memos(request)

    def _check_allowed_chain_id(self, chain_id: int | None) -> None:
        """Reject a payment chain outside ``allowed_chain_ids``.

        An unknown chain is only rejected by an empty allowlist; signing
        always resolves the chain first, so it is checked again then.
        """
        allowed = self.allowed_chain_ids
        if allowed is None:
            return
        if not allowed or (chain_id is not None and chain_id not in allowed):
            raise ValueError(
                f"Chain ID not allowed: {chain_id if chain_id is not None else 'unknown'}"
            )

    def _check_amount_caps(self, request: dict) -> None:
        """Reject a challenge above either cap or outside the pinned currencies.

        The caps bound ``amount`` (base units, splits included) and only apply to
        currencies the client pinned, so their value is fixed by the client.
        """
        max_atomic, max_token = self._amount_caps()
        if max_atomic is None and max_token is None:
            return
        currency = request.get("currency")
        pinned = {pinned.lower() for pinned in self._pinned_currencies()}
        if not isinstance(currency, str) or currency.lower() not in pinned:
            raise ValueError(
                f"Challenge requests currency {currency!r}, "
                "which is not a currency the client pinned for its amount caps"
            )
        try:
            amount = int(request["amount"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Challenge amount must be an integer in base units") from error
        if max_atomic is not None and amount > max_atomic:
            raise ValueError("Tempo charge amount exceeds max_atomic_amount.")
        if max_token is not None and amount > max_token:
            raise ValueError("Tempo charge amount exceeds max_amount.")

    def _check_expected_recipients(self, request: dict) -> None:
        """Reject a primary or split recipient outside ``expected_recipients``."""
        if self.expected_recipients is not None:
            allowed = {recipient.lower() for recipient in self.expected_recipients}
            recipient = request.get("recipient")
            if not isinstance(recipient, str) or recipient.lower() not in allowed:
                raise ValueError(
                    f"Challenge requests recipient {recipient!r}, "
                    "which is not in the client's expected recipients"
                )
            method_details = request.get("methodDetails")
            splits = method_details.get("splits") if isinstance(method_details, dict) else None
            for split in splits or ():
                split_recipient = split.get("recipient") if isinstance(split, dict) else None
                if not isinstance(split_recipient, str) or split_recipient.lower() not in allowed:
                    raise ValueError(
                        f"Challenge requests split recipient {split_recipient!r}, "
                        "which is not in the client's expected recipients"
                    )

    def can_handle_challenge(self, challenge: Challenge) -> bool:
        """Return whether a challenge passes the client's chain, recipient and amount policy.

        Used during challenge selection so an offer this client would reject is
        skipped in favour of one it will pay. A chain pinned only by a custom
        ``rpc_url`` is checked here once its chain ID is cached;
        ``create_credential`` always re-checks before signing.
        """
        try:
            self._check_charge_policy(challenge.request, self._known_expected_chain_id())
        except ValueError:
            return False
        return True

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        For the charge intent, this builds and signs a TempoTransaction (type 0x76)
        using an expiring nonce. Sponsored charges carry a fee payer placeholder
        for the server or fee payer service to co-sign before broadcast.

        Concurrent calls for the same challenge and signer share one in-flight
        signing. Once it settles, a later call signs afresh.

        Args:
            challenge: The payment challenge from the server.

        Returns:
            A credential with the signed transaction.

        Raises:
            ValueError: If no account is configured, the intent is unsupported,
                or the challenge violates the client's chain, amount cap or
                ``expected_recipients`` policy.
            TransactionError: If transaction building fails.
        """
        if self.account is None:
            raise ValueError("No account configured for signing")

        if challenge.intent != "charge":
            raise ValueError(f"Unsupported intent: {challenge.intent}")
        # Enforce client policy on every call, including ones joining a signing.
        self._check_charge_policy(challenge.request, await self._resolve_expected_chain_id())

        # Share an in-flight signing so concurrent calls for one challenge cannot
        # yield two independently settleable transactions.
        key = ((self.root_account or self.account.address).lower(), challenge.id)
        task = self._signing.get(key)
        if task is None:
            task = asyncio.ensure_future(self._create_credential(challenge))
            self._signing[key] = task
            task.add_done_callback(lambda _: self._signing.pop(key, None))
        return await asyncio.shield(task)

    async def _create_credential(self, challenge: Challenge) -> Credential:
        if self.account is None:
            raise ValueError("No account configured for signing")

        request = challenge.request
        expected_chain_id = await self._resolve_expected_chain_id()
        self._check_charge_policy(request, expected_chain_id)
        if expected_chain_id is None:
            expected_chain_id = _challenge_chain_id(request)
        method_details = request.get("methodDetails", {})
        use_fee_payer = (
            method_details.get("feePayer", False) if isinstance(method_details, dict) else False
        )
        if use_fee_payer:
            _assert_sponsored_challenge_time_left(challenge.expires)

        memo = encode_attribution(
            challenge_id=challenge.id,
            server_id=challenge.realm,
            client_id=self.client_id,
        )

        splits = method_details.get("splits") if isinstance(method_details, dict) else None

        rpc_url = self.rpc_url
        raw_tx, chain_id = await self._build_tempo_transfer(
            amount=request["amount"],
            currency=request["currency"],
            recipient=request["recipient"],
            memo=memo,
            rpc_url=rpc_url,
            expected_chain_id=expected_chain_id,
            awaiting_fee_payer=use_fee_payer,
            splits=splits,
            expires=challenge.expires,
        )

        # When signing with an access key, the credential source is the
        # root account (the smart wallet), not the access key.
        source_address = self.root_account if self.root_account else self.account.address

        return Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": raw_tx},
            source=f"did:pkh:eip155:{chain_id}:{source_address}",
        )

    def transaction_hash(self, credential: Credential) -> str | None:
        """Return the on-chain hash of a credential's signed 0x76 transaction.

        Returns ``None`` unless the payload decodes as a sender-signed 0x76
        transaction. Sponsored (0x78 fee payer envelope) transactions return
        ``None`` because their final hash depends on the fee payer's co-signature.
        """
        import rlp
        from eth_hash.auto import keccak

        payload = credential.payload
        raw_tx = payload.get("signature")
        if payload.get("type") != "transaction" or not isinstance(raw_tx, str):
            return None
        try:
            tx_bytes = bytes.fromhex(raw_tx.removeprefix("0x"))
            fields = rlp.decode(tx_bytes[1:]) if tx_bytes[:1] == b"\x76" else None
        except (ValueError, rlp.DecodingError):
            return None
        # 0x76 || rlp([13 body fields, key_authorization?, sender_signature])
        if (
            not isinstance(fields, list)
            or len(fields) not in (14, 15)
            or not isinstance(fields[4], list)
            or not fields[4]
            or not isinstance(fields[-1], bytes)
            or not fields[-1]
        ):
            return None
        return "0x" + keccak(tx_bytes).hex()

    async def _build_tempo_transfer(
        self,
        amount: str,
        currency: str,
        recipient: str,
        memo: str | None = None,
        rpc_url: str | None = None,
        expected_chain_id: int | None = None,
        awaiting_fee_payer: bool = False,
        splits: list[dict] | None = None,
        expires: str | None = None,
    ) -> tuple[str, int]:
        """Build a client-signed Tempo transaction.

        Creates a TempoTransaction (type 0x76) with a supported fee token.
        Ordinary charges use the transfer currency; MACH charges select a
        funded supported stablecoin because MACH cannot pay transaction fees.

        Always uses an expiring nonce (nonce_key=U256::MAX, nonce=0) with a
        short ``valid_before`` window for replay protection, so concurrent
        charges from one key never contend for a sequential nonce.

        When ``awaiting_fee_payer`` is True, the transaction is built with
        a fee payer placeholder so a sponsoring service can co-sign it
        before broadcast.

        Args:
            amount: Transfer amount as string.
            currency: TIP-20 token contract address.
            recipient: Recipient address.
            memo: Optional 32-byte memo (hex string) for transferWithMemo.
            rpc_url: RPC URL to use. Defaults to ``self.rpc_url``.
            expected_chain_id: If set, verify the RPC reports this chain ID.
            awaiting_fee_payer: If True, build for fee payer sponsorship.
            expires: Challenge expiry (ISO 8601). Caps ``valid_before``.

        Returns:
            Tuple of (raw signed transaction hex, chain ID).

        Raises:
            TransactionError: If the RPC's chain ID doesn't match expected.
        """
        from pytempo import Call, TempoTransaction

        if self.account is None:
            raise ValueError("No account configured")

        resolved_rpc = rpc_url or self.rpc_url

        gas_estimate_data: str | None = None

        if splits:
            from mpp.methods.tempo.intents import get_transfers
            from mpp.methods.tempo.schemas import Split as SplitModel

            parsed_splits = [SplitModel(**s) for s in splits]
            transfer_list = get_transfers(int(amount), recipient, memo, parsed_splits)
            call_list = []
            for t in transfer_list:
                transfer_memo = "0x" + t.memo.hex() if t.memo is not None else memo
                if transfer_memo is not None:
                    td = self._encode_transfer_with_memo(t.recipient, t.amount, transfer_memo)
                else:
                    td = self._encode_transfer(t.recipient, t.amount)
                call_list.append(Call.create(to=currency, value=0, data=td))
            calls_tuple = tuple(call_list)
        else:
            if memo:
                transfer_data = self._encode_transfer_with_memo(recipient, int(amount), memo)
            else:
                transfer_data = self._encode_transfer(recipient, int(amount))
            calls_tuple = (Call.create(to=currency, value=0, data=transfer_data),)
            gas_estimate_data = transfer_data

        # When using an access key, the root account (smart wallet) is the
        # sender, not the access key address.
        sender = self.root_account if self.root_account else self.account.address

        chain_id = await self._get_chain_id(resolved_rpc)
        gas_price = int(await _rpc_call(resolved_rpc, "eth_gasPrice", []), 16)
        max_priority_fee_per_gas = gas_price

        if expected_chain_id is not None and chain_id != expected_chain_id:
            raise TransactionError(
                f"Chain ID mismatch: RPC returned {chain_id}, "
                f"expected {expected_chain_id} from client policy"
            )

        if awaiting_fee_payer:
            # Keep sponsored envelopes inside the server's default policy.
            max_priority_fee_per_gas = min(gas_price, get_policy(chain_id).max_priority_fee_per_gas)

        gas_limit = DEFAULT_GAS_LIMIT
        try:
            if splits:
                total_estimated = 0
                for c in calls_tuple:
                    total_estimated += await estimate_gas(
                        resolved_rpc, sender, currency, c.data.hex()
                    )
                gas_limit = max(gas_limit, total_estimated + 5_000 * len(calls_tuple))
            elif gas_estimate_data is not None:
                estimated = await estimate_gas(resolved_rpc, sender, currency, gas_estimate_data)
                gas_limit = max(gas_limit, estimated + 5_000)
        except Exception:
            pass

        fee_token: str | None = None
        if not awaiting_fee_payer:
            fee_token = currency
            if currency.lower() in (MACH.lower(), OUSD.lower()):
                required_balance = max(
                    1,
                    (gas_limit * gas_price + ATTODOLLARS_PER_MICRODOLLAR - 1)
                    // ATTODOLLARS_PER_MICRODOLLAR,
                )
                fee_token = await self._resolve_supported_fee_token(
                    account=sender,
                    chain_id=chain_id,
                    rpc_url=resolved_rpc,
                    required_balance=required_balance,
                )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=gas_limit,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            nonce=0,
            nonce_key=EXPIRING_NONCE_KEY,
            fee_token=fee_token,
            awaiting_fee_payer=awaiting_fee_payer,
            # Set after the RPC round trips above, just before signing.
            valid_before=_expiring_valid_before(expires),
            calls=calls_tuple,
        )

        if self.root_account:
            from pytempo import sign_tx_access_key

            signed_tx = sign_tx_access_key(tx, self.account.private_key, self.root_account)
        else:
            signed_tx = tx.sign(self.account.private_key)

        if awaiting_fee_payer:
            from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

            return "0x" + encode_fee_payer_envelope(signed_tx).hex(), chain_id

        return "0x" + signed_tx.encode().hex(), chain_id

    def _encode_transfer(self, to: str, amount: int) -> str:
        """Encode a TIP-20 transfer call.

        Selector: 0xa9059cbb = keccak256("transfer(address,uint256)")[:4]
        """
        selector = "a9059cbb"
        return f"0x{selector}{_abi_address(to)}{_abi_uint256(amount)}"

    def _encode_transfer_with_memo(self, to: str, amount: int, memo: str) -> str:
        """Encode a TIP-20 transferWithMemo call.

        Selector: 0x95777d59 = keccak256(
            "transferWithMemo(address,uint256,bytes32)"
        )[:4]
        """
        selector = "95777d59"
        to_padded = _abi_address(to)
        amount_padded = _abi_uint256(amount)
        memo_clean = memo[2:] if memo.startswith("0x") else memo
        if len(memo_clean) != 64:
            raise ValueError(f"memo must be exactly 32 bytes (64 hex chars), got {len(memo_clean)}")
        if not all(c in "0123456789abcdefABCDEF" for c in memo_clean):
            raise ValueError("memo must be hex-encoded")
        return f"0x{selector}{to_padded}{amount_padded}{memo_clean.lower()}"


def _check_recipient_addresses(request: dict) -> None:
    """Reject a primary or split recipient that is not a 20-byte hex address.

    The transfer calldata embeds each recipient as one ABI word, so a longer
    value would spill into the amount word and sign a transfer the amount caps
    never saw (VERIA-1145).
    """
    recipient = request.get("recipient")
    if not isinstance(recipient, str) or _ADDRESS_RE.fullmatch(recipient) is None:
        raise ValueError(f"Challenge recipient is not a valid address: {recipient!r}")
    method_details = request.get("methodDetails")
    splits = method_details.get("splits") if isinstance(method_details, dict) else None
    for split in splits or ():
        split_recipient = split.get("recipient") if isinstance(split, dict) else None
        if not isinstance(split_recipient, str) or _ADDRESS_RE.fullmatch(split_recipient) is None:
            raise ValueError(
                f"Challenge split recipient is not a valid address: {split_recipient!r}"
            )


def _abi_address(address: str) -> str:
    """ABI-encode a 20-byte hex address as one 32-byte word (64 hex chars)."""
    if not isinstance(address, str) or _ADDRESS_RE.fullmatch(address) is None:
        raise ValueError(f"Invalid recipient address: {address!r}")
    return address[2:].lower().zfill(64)


def _abi_uint256(value: int) -> str:
    """ABI-encode a uint256 as one 32-byte word (64 hex chars)."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 256:
        raise ValueError("Transfer amount must be a uint256")
    return f"{value:064x}"


def _assert_sponsored_challenge_time_left(expires: str | None) -> None:
    """Refuse a sponsored challenge too close to expiry for the server to cosign.

    The client caps ``valid_before`` at the challenge expiry, and a sponsoring
    server rejects transactions with less than
    ``MIN_REMAINING_VALIDITY_SECONDS`` of validity left, so signing such a
    challenge could only produce a rejected payment. Raises
    ``PaymentExpiredError`` before signing, so the HTTP transport returns the
    402 for the caller to retry, as it does for an already-expired challenge.
    """
    if not expires:
        return
    try:
        challenge_expiry = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return
    if challenge_expiry - time.time() < MIN_REMAINING_VALIDITY_SECONDS:
        raise PaymentExpiredError(expires) from ValueError(
            "Sponsored challenge expires in less than "
            f"{MIN_REMAINING_VALIDITY_SECONDS} seconds; request a new challenge"
        )


def _expiring_valid_before(expires: str | None) -> int:
    """Return an expiring-nonce ``valid_before`` capped at the challenge expiry.

    ``valid_before`` is an exclusive whole-second bound, so the cap is the
    second after the (possibly fractional) expiry. The transaction then stays
    valid for as long as the challenge does.
    """
    valid_before = int(time.time()) + EXPIRING_NONCE_VALID_BEFORE_SECS
    if not expires:
        return valid_before
    try:
        challenge_expiry = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return valid_before
    return min(valid_before, int(challenge_expiry) + 1)


# ──────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────


def _tempo_method(
    account: TempoAccount | None = None,
    fee_payer: TempoAccount | None = None,
    chain_id: int | None | object = _CHAIN_ID_UNSET,
    rpc_url: str | None = None,
    root_account: str | None = None,
    currency: str | None = None,
    recipient: str | None = None,
    decimals: int = 6,
    client_id: str | None = None,
    currencies: Sequence[str] | None = None,
    fee_token: str | None = None,
    allowed_fee_tokens: Sequence[str] | None = None,
    max_atomic_amount: int | str | None = None,
    max_amount: str | Decimal | None = None,
    max_amount_decimals: int | None = None,
    expected_recipients: Sequence[str] | None = None,
    allowed_chain_ids: Sequence[int] | None = None,
) -> TempoMethod:
    """Resolve and validate Tempo charge configuration shared by clients and servers.

    Args:
        account: Account for signing transactions (client-side).
        fee_payer: Account for co-signing sponsored transactions
            (server-side). When set, the server signs with domain
            ``0x78`` and broadcasts directly — no external fee payer
            service needed.
        chain_id: Tempo chain ID (default: 4217 for mainnet, use 42431
            for testnet). Resolves the RPC URL automatically from known chains.
        rpc_url: Tempo RPC endpoint URL. Overrides the URL resolved
            from ``chain_id``. When provided without ``chain_id``, the client
            pins itself to whatever chain that RPC reports. Defaults to mainnet
            if neither is set.
        root_account: Root account address for access key signing.
        currency: Deprecated for servers; use ``currencies=[currency]``.
            Restricts charges to this one currency. Mutually exclusive with
            ``currencies``.
        recipient: Default recipient address for server-issued charges. Not
            enforced when paying; use ``expected_recipients`` for that.
        decimals: Token decimal places for amount conversion (default: 6).
        client_id: Optional client identity for attribution memos.
        currencies: Ordered currency addresses a server accepts. Servers issue
            one charge offer per currency, in order. Replaces the defaults:
            OUSD then USDC.e on mainnet, OUSD then pathUSD on Moderato, and
            the single :func:`default_currency_for_chain` currency elsewhere.
            Duplicates are removed case-insensitively.
        fee_token: Token a local ``fee_payer`` pays gas in. Must also be in
            the allowed fee tokens. If omitted, the first allowed token the
            fee payer holds a balance of is used, else the first allowed.
            Independent of the charge currency. Requires ``fee_payer``.
        allowed_fee_tokens: Tokens a sponsored charge may pay gas in. A local
            ``fee_payer`` defaults to :func:`fee_tokens_for_chain` (pathUSD,
            then USDC.e on mainnet). An external ``feePayerUrl`` sponsor picks
            its own token unless this is set, in which case its token must be
            explicitly set and in the list. Must contain at least one token.
        max_atomic_amount: Client-side cap on a charge's ``amount``, in base
            units of the challenge currency, as an int or a string of digits
            (e.g. ``1_000_000`` is 1.00 of a 6-decimal token). Includes splits,
            excludes network fees. Over-cap challenges are skipped during
            challenge selection and rejected before signing. Requires an
            explicit ``currency=`` or ``currencies=`` pin; challenges in any
            other currency are skipped and rejected, so the cap is always
            denominated in a currency the client chose.
        max_amount: Client-side cap in token units, as a decimal string or
            ``Decimal`` (e.g. ``"1.5"``), checked like ``max_atomic_amount``.
            Requires ``max_amount_decimals`` and a currency pin, like
            ``max_atomic_amount``. May be combined with ``max_atomic_amount``.
        max_amount_decimals: Token decimals used to convert ``max_amount`` to
            base units (TIP-20 tokens use 6). Challenges do not carry
            decimals, so this is required with ``max_amount``. A
            ``max_amount`` with more significant fractional digits is
            rejected rather than rounded; trailing zeros are accepted.
        expected_recipients: Client-side allowlist of recipient addresses. The
            primary recipient and every split recipient must be listed
            (case-insensitive). Other challenges are skipped during challenge
            selection and rejected before signing. An empty sequence rejects
            every charge.
        allowed_chain_ids: Client-side allowlist of chain IDs a charge may be
            paid on. The challenge's chain, or the client's pinned chain when
            the challenge omits one, must be listed. Combined with the
            ``chain_id``/``rpc_url`` pin, a charge must satisfy both. Other
            challenges are skipped during challenge selection and rejected
            before signing. An empty sequence rejects every charge.

    Returns:
        A configured TempoMethod instance.
    """
    chain_id_explicit = chain_id is not _CHAIN_ID_UNSET
    resolved_chain_id: int | None
    if chain_id is _CHAIN_ID_UNSET:
        resolved_chain_id = CHAIN_ID
    else:
        resolved_chain_id = cast("int | None", chain_id)

    rpc_url_explicit = rpc_url is not None
    if rpc_url is None:
        if resolved_chain_id is None:
            raise ValueError("chain_id or rpc_url is required")
        rpc_url = rpc_url_for_chain(resolved_chain_id)

    if currency is not None and currencies is not None:
        raise ValueError("pass currency= or currencies=, not both")
    currency_explicit = currency is not None or currencies is not None
    if currencies is not None:
        accepted = _resolve_currencies(currencies)
        currency = accepted[0]
    elif currency is not None:
        accepted = (currency,)
    else:
        currency = default_currency_for_chain(resolved_chain_id)
        accepted = default_currencies_for_chain(resolved_chain_id)

    if fee_token is not None and fee_payer is None:
        raise ValueError("fee_token can only be configured for a local fee_payer")
    if fee_token is not None and _ADDRESS_RE.fullmatch(fee_token) is None:
        raise ValueError(f"Invalid Tempo fee token address: {fee_token!r}")
    resolved_allowed_fee_tokens: tuple[str, ...] | None = None
    if allowed_fee_tokens is not None:
        if isinstance(allowed_fee_tokens, str):
            raise ValueError("allowed_fee_tokens must be a sequence of addresses")
        resolved_allowed_fee_tokens = tuple(allowed_fee_tokens)
        if not resolved_allowed_fee_tokens:
            raise ValueError("allowed_fee_tokens must contain at least one token")
        for token in resolved_allowed_fee_tokens:
            if not isinstance(token, str) or _ADDRESS_RE.fullmatch(token) is None:
                raise ValueError(f"Invalid Tempo fee token address: {token!r}")

    resolved_expected_recipients: tuple[str, ...] | None = None
    if expected_recipients is not None:
        if isinstance(expected_recipients, str):
            raise ValueError("expected_recipients must be a sequence of addresses")
        resolved_expected_recipients = tuple(expected_recipients)
        for address in resolved_expected_recipients:
            if not isinstance(address, str) or _ADDRESS_RE.fullmatch(address) is None:
                raise ValueError(f"Invalid Tempo recipient address: {address!r}")

    method = TempoMethod(
        account=account,
        fee_payer=fee_payer,
        rpc_url=rpc_url,
        chain_id=resolved_chain_id,
        root_account=root_account,
        currency=currency,
        recipient=recipient,
        decimals=decimals,
        client_id=client_id,
        currencies=accepted,
        fee_token=fee_token,
        allowed_fee_tokens=resolved_allowed_fee_tokens,
        max_atomic_amount=max_atomic_amount,
        max_amount=max_amount,
        max_amount_decimals=max_amount_decimals,
        expected_recipients=resolved_expected_recipients,
        allowed_chain_ids=allowed_chain_ids,
    )
    if (max_atomic_amount is not None or max_amount is not None) and not currency_explicit:
        raise ValueError(_CAPS_REQUIRE_CURRENCY_PIN)
    method._chain_id_explicit = chain_id_explicit
    method._currency_explicit = currency_explicit
    method._rpc_url_explicit = rpc_url_explicit
    return method


def charge(
    *,
    account: TempoAccount,
    chain_id: int | None | object = _CHAIN_ID_UNSET,
    rpc_url: str | None = None,
    root_account: str | None = None,
    currency: str | None = None,
    currencies: Sequence[str] | None = None,
    client_id: str | None = None,
    max_atomic_amount: int | str | None = None,
    max_amount: str | Decimal | None = None,
    max_amount_decimals: int | None = None,
    expected_recipients: Sequence[str] | None = None,
    allowed_chain_ids: Sequence[int] | None = None,
) -> ClientMethod:
    """Create the client method that pays Tempo charge challenges.

    It signs a TIP-20 transfer (type ``0x76`` transaction with an expiring nonce)
    for each challenge it accepts. Options are described on :func:`_tempo_method`:
    ``currency``/``currencies`` pin the currencies it pays, and the charge policy
    (``max_atomic_amount``, ``max_amount``, ``expected_recipients``,
    ``allowed_chain_ids`` and the ``chain_id``/``rpc_url`` pin) skips other
    challenges during selection and rejects them before signing.

    Example:
        from mpp.client import Mpp
        from mpp.methods.tempo import TempoAccount
        from mpp.methods.tempo import client as tempo

        account = TempoAccount.from_key("0x...")
        async with Mpp(methods=[tempo.charge(account=account)]) as client:
            response = await client.get("https://api.example.com/resource")
    """
    return _client_method(
        _tempo_method(
            account=account,
            chain_id=chain_id,
            rpc_url=rpc_url,
            root_account=root_account,
            currency=currency,
            currencies=currencies,
            client_id=client_id,
            max_atomic_amount=max_atomic_amount,
            max_amount=max_amount,
            max_amount_decimals=max_amount_decimals,
            expected_recipients=expected_recipients,
            allowed_chain_ids=allowed_chain_ids,
        )
    )


def _client_method(method: TempoMethod) -> ClientMethod:
    """Wrap a configured :class:`TempoMethod` as the Tempo charge client method.

    Challenges in currencies other than the pinned ones are not selected.
    """
    from mpp.methods.tempo.schemas import charge as definition
    from mpp.runtime import ClientMethod, CredentialParams

    pinned = {pin.lower() for pin in method._pinned_currencies()}

    async def create_credential(params: CredentialParams) -> str:
        return (await method.create_credential(params.challenge)).to_authorization()

    def can_handle_challenge(challenge: Challenge) -> bool:
        currency = challenge.request.get("currency")
        if pinned and not (isinstance(currency, str) and currency.lower() in pinned):
            return False
        return method.can_handle_challenge(challenge)

    return ClientMethod(
        method=definition,
        create_credential=create_credential,
        can_handle_challenge=can_handle_challenge,
        transaction_hash=method.transaction_hash,
    )


def _resolve_currencies(currencies: Sequence[str]) -> tuple[str, ...]:
    """Validate and deduplicate an ordered currency list, preserving order."""
    if isinstance(currencies, str):
        raise ValueError("currencies must be a sequence of addresses, not a string")
    seen: set[str] = set()
    resolved: list[str] = []
    for currency in currencies:
        if not isinstance(currency, str) or _ADDRESS_RE.fullmatch(currency) is None:
            raise ValueError(f"Invalid Tempo currency address: {currency!r}")
        key = currency.lower()
        if key not in seen:
            seen.add(key)
            resolved.append(currency)
    if not resolved:
        raise ValueError("currencies must contain at least one currency")
    return tuple(resolved)


def _challenge_chain_id(request: dict) -> int | None:
    """Return the challenge's numeric ``methodDetails.chainId``, ignoring other values."""
    method_details = request.get("methodDetails")
    chain_id = method_details.get("chainId") if isinstance(method_details, dict) else None
    if chain_id is None:
        return None
    try:
        return int(chain_id)
    except (TypeError, ValueError):
        return None


def _parse_max_atomic_amount(value: int | str) -> int:
    """Validate a base-unit cap given as a non-negative int or a string of digits."""
    if isinstance(value, str) and _ATOMIC_AMOUNT_RE.fullmatch(value):
        return int(value)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ValueError("max_atomic_amount must be a non-negative integer or digit string")


def _parse_max_amount(value: str | Decimal, decimals: int) -> int:
    """Convert a token-unit cap to base units exactly.

    Rejects significant fractional digits beyond ``decimals`` instead of
    rounding, so the conversion can never raise the cap. Trailing zeros are
    accepted.
    """
    if isinstance(decimals, bool) or not isinstance(decimals, int) or decimals < 0:
        raise ValueError("max_amount_decimals must be a non-negative integer")
    if not isinstance(value, str | Decimal):
        raise ValueError(
            "max_amount must be a decimal string or Decimal in token units; "
            "use max_atomic_amount for base units"
        )
    try:
        parsed = Decimal(value.strip() if isinstance(value, str) else value)
    except InvalidOperation:
        raise ValueError(f"Invalid max_amount: {value!r}") from None
    sign, digits, exponent = parsed.as_tuple()
    if sign or not isinstance(exponent, int):
        raise ValueError("max_amount must be a finite, non-negative amount")
    coefficient = int("".join(map(str, digits)))
    shift = exponent + decimals
    if shift >= 0:
        return coefficient * 10**shift
    atomic, remainder = divmod(coefficient, 10**-shift)
    if remainder:
        raise ValueError(
            f"Tempo charge max_amount {value} has more fractional digits "
            f"than {decimals} decimals allow."
        )
    return atomic
