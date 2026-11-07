"""Tempo charge for clients.

:func:`charge` returns the :class:`~mpp.runtime.ClientMethod` that pays Tempo
charge challenges; :class:`TempoMethod` implements its credential creation.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, cast

from mpp import Challenge, Credential
from mpp._typing import is_dict, is_list
from mpp.errors import (
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
    ZoneSettlementPendingError,
    ZoneWithdrawalBouncedError,
)
from mpp.methods.tempo import _machine_token
from mpp.methods.tempo import _zone as _zones
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._defaults import (
    CHAIN_ID,
    MACH,
    OUSD,
    PATH_USD,
    RPC_URL,
    USDC,
    default_currencies_for_chain,
    default_currency_for_chain,
    fee_tokens_for_chain,
    rpc_url_for_chain,
)
from mpp.methods.tempo._rpc import _rpc_call, _tip20_balance, estimate_gas
from mpp.methods.tempo.fee_payer_policy import (
    MIN_REMAINING_VALIDITY_SECONDS,
    _get_payer_policy,
    get_policy,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    import httpx

    from mpp.methods.tempo.account import TempoAccount
    from mpp.methods.tempo.schemas import ChargeMode
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


class InsufficientFundsError(TransactionError):
    """The payer lacks the charge currency and no auto-swap route can acquire it."""

    def __init__(self, currency: str) -> None:
        super().__init__(
            f"Insufficient funds: no balance in {currency} and no viable swap route from "
            "fallback currencies."
        )
        self.currency = currency


# Fallback currencies an auto-swap pays from, in priority order. OUSD can fund a
# swap but cannot pay transaction fees, so fees still come from a fee token.
AUTO_SWAP_CURRENCIES: tuple[str, ...] = (PATH_USD, USDC, OUSD)
# keccak256("quoteSwapExactAmountOut(address,address,uint128)")[:4]
_QUOTE_SWAP_EXACT_AMOUNT_OUT_SELECTOR = "1576fa0e"


@dataclass(frozen=True)
class AutoSwap:
    """Auto-swap options for :func:`charge`.

    Attributes:
        token_in: Currencies to swap from, in priority order. The default
            fallback currencies (pathUSD, then USDC.e, then OUSD) are tried
            after them unless ``fallback`` is ``False``.
        slippage: Maximum slippage over the DEX quote, in percent (``1`` = 1%).
        fallback: Whether to also try the default currencies after
            ``token_in``. ``False`` swaps only from ``token_in``, as an
            allowlist. Ignored without ``token_in``.
    """

    token_in: Sequence[str] | None = None
    slippage: float = 1
    fallback: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.token_in, str):
            raise ValueError("AutoSwap token_in must be a sequence of addresses")
        if not math.isfinite(self.slippage) or self.slippage < 0:
            raise ValueError("AutoSwap slippage must be a non-negative percentage")

    def currencies(self) -> tuple[str, ...]:
        """Return the currencies to swap from, explicit ones first."""
        explicit = tuple(self.token_in or ())
        if self.token_in is not None and not self.fallback:
            return explicit
        chosen = {token.lower() for token in explicit}
        return explicit + tuple(t for t in AUTO_SWAP_CURRENCIES if t.lower() not in chosen)


async def _find_auto_swap_calls(
    auto_swap: AutoSwap,
    *,
    account: str,
    amount_out: int,
    token_out: str,
    rpc_url: str,
    fee_headroom: int = 0,
    token_in: str | None = None,
    trusted_currencies: Sequence[str] | None = None,
    client: Any | None = None,
) -> tuple[list[tuple[str, str]], dict[str, int]]:
    """Return ``(to, data)`` approve and swap calls that top ``token_out`` up to ``amount_out``.

    Also returns the balance each token's calls spend, keyed by lowercase
    address. ``fee_headroom`` buys that much more ``token_out`` so the
    payer's existing balance can pay the transaction fee. ``token_in``
    limits the swap to that one fallback currency. ``trusted_currencies``, when
    given, are the only currencies a swap may buy. Returns no calls when
    ``account`` already holds enough ``token_out``. Charge and session
    clients share it.

    Raises:
        InsufficientFundsError: When no fallback currency can fund the swap.
    """
    from mpp.methods.tempo.intents import (
        APPROVE_SELECTOR,
        STABLECOIN_DEX,
        SWAP_EXACT_AMOUNT_OUT_SELECTOR,
    )

    rpc: dict[str, Any] = {} if client is None else {"client": client}
    candidates = [
        t
        for t in auto_swap.currencies()
        if t.lower() != token_out.lower() and (token_in is None or t.lower() == token_in.lower())
    ]
    target, *balances = await asyncio.gather(
        _tip20_balance(rpc_url, token_out, account, **rpc),
        *(_tip20_balance(rpc_url, token, account, **rpc) for token in candidates),
        return_exceptions=True,
    )
    held = 0 if isinstance(target, BaseException) else target
    if held >= amount_out + fee_headroom:
        return [], {}
    if trusted_currencies is not None and token_out.lower() not in {
        t.lower() for t in trusted_currencies
    }:
        # A recipient allowlist does not protect funds swapped into a token
        # the challenge names: only buy currencies the client chose.
        raise TransactionError(
            f"Auto-swap with expected_recipients only buys a pinned or fallback "
            f"currency, not {token_out}"
        )
    # Buy only the shortfall; the payer's existing balance covers the rest.
    deficit = amount_out + fee_headroom - held
    slippage_bps = math.floor(auto_swap.slippage * 100 + 0.5)
    for candidate, balance in zip(candidates, balances, strict=True):
        if isinstance(balance, BaseException) or balance <= 0:
            continue
        quote = {
            "to": STABLECOIN_DEX,
            "data": "0x"
            + _QUOTE_SWAP_EXACT_AMOUNT_OUT_SELECTOR
            + _abi_words(candidate, token_out, deficit),
        }
        try:
            quoted = int(await _rpc_call(rpc_url, "eth_call", [quote, "latest"], **rpc), 16)
        except Exception:
            continue
        max_amount_in = quoted + quoted * slippage_bps // 10_000
        # The swap may spend up to the slippage-adjusted maximum.
        if balance < max_amount_in:
            continue
        calls = [
            (candidate, f"0x{APPROVE_SELECTOR}" + _abi_words(STABLECOIN_DEX, max_amount_in)),
            (
                STABLECOIN_DEX,
                f"0x{SWAP_EXACT_AMOUNT_OUT_SELECTOR}"
                + _abi_words(candidate, token_out, deficit, max_amount_in),
            ),
        ]
        spent = {
            candidate.lower(): max_amount_in,
            token_out.lower(): max(0, amount_out - deficit),
        }
        return calls, spent
    raise InsufficientFundsError(token_out)


# ──────────────────────────────────────────────────────────────────
# Charge client method
# ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, kw_only=True)
class Zone:
    """Pays charges from a Zone balance when a challenge accepts that Zone.

    The client withdraws the charge amount from the Zone to the recipient with
    a challenge-bound memo, waits for the withdrawal to settle on Tempo, and
    sends a ``zone`` credential naming the settlement transaction. Challenges
    that do not accept the Zone, and split payments, are paid on Tempo as usual.

    Attributes:
        rpc_url: RPC endpoint of the Zone chain.
        account: Account that holds the Zone balance and signs the withdrawal.
            Defaults to the charge account (and its ``root_account``).
        chain_id: Zone chain ID. Read from ``rpc_url`` when omitted.
        zone_id: Zone ID. Derived from the Zone chain ID when omitted.
        parent_chain_id: Tempo chain the Zone settles on. Derived from the
            Zone chain ID when omitted; a Zone ID is only unique per parent
            chain, so the client pays from the Zone only on this chain.
        settlement_timeout: Seconds to wait for the withdrawal to settle on
            Tempo (default: 60). The wait also ends at the challenge expiry.
            Tempo is always checked once, so 0 checks without waiting.
        http_client: httpx client every Zone RPC call goes through, owned by
            the caller. Set the Zone's ``X-Authorization-Token`` header on it.
    """

    rpc_url: str
    account: TempoAccount | None = None
    chain_id: int | None = None
    zone_id: int | None = None
    parent_chain_id: int | None = None
    settlement_timeout: float | None = None
    http_client: httpx.AsyncClient | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject options that would fail only after an irreversible withdrawal."""
        timeout = self.settlement_timeout
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))  # pyright: ignore[reportUnnecessaryIsInstance]
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("zone.settlement_timeout must be a finite, non-negative number.")
        if self.zone_id is not None and not _zones.is_id(self.zone_id):
            raise ValueError(f"Invalid Zone ID: {self.zone_id!r}")
        if self.chain_id is not None:
            _assert_zone_chain(self.zone_id, self.chain_id)
            _assert_zone_parent_chain(self.parent_chain_id, self.chain_id)


def _assert_rpc_chain_id(chain_id: int, expected_chain_id: int | None) -> None:
    """Reject a Tempo RPC that serves another chain than the client's policy pins."""
    if expected_chain_id is not None and chain_id != expected_chain_id:
        raise TransactionError(
            f"Chain ID mismatch: RPC returned {chain_id}, "
            f"expected {expected_chain_id} from client policy"
        )


def _assert_zone_chain(zone_id: int | None, chain_id: int) -> None:
    """Reject a ``zone_id`` that names another Zone than the one its chain ID derives."""
    # Only chain IDs that follow a known Zone scheme name their Zone.
    if zone_id is None or _zones.parent_chain_id_from_chain_id(chain_id) is None:
        return
    derived = _zones.id_from_chain_id(chain_id)
    if derived != zone_id:
        raise ValueError(
            f"zone.zone_id {zone_id} does not match Zone {derived} of the Zone chain {chain_id}."
        )


def _assert_zone_parent_chain(parent_chain_id: int | None, chain_id: int) -> None:
    """Reject a ``parent_chain_id`` other than the parent its Zone chain ID derives.

    Selection trusts an explicit parent chain over the derived one, so a
    contradicting one would withdraw for a Zone on another chain.
    """
    derived = _zones.parent_chain_id_from_chain_id(chain_id)
    if parent_chain_id is not None and derived is not None and derived != parent_chain_id:
        raise ValueError(
            f"zone.parent_chain_id {parent_chain_id} does not match parent chain {derived} "
            f"of the Zone chain {chain_id}."
        )


# Seconds the client allows for sending a Zone withdrawal before it waits for settlement.
_ZONE_SUBMISSION_MARGIN = 15.0
# Seconds to look for a withdrawal's receipt on the Zone after its send response fails.
_ZONE_RECEIPT_RECOVERY_TIMEOUT = 15.0
# Gas added to the Zone's estimate for the signature, as the Tempo transfer path does.
_ZONE_GAS_MARGIN = 5_000


@dataclass
class _ZoneSend:
    """Whether a Zone withdrawal may have reached the Zone, so retrying could pay twice.

    ``wanted`` and ``on_submission`` are the push path's cancellation tracking:
    the withdrawal is not sent once every caller is gone, and its signed
    transaction is reported before it is sent.
    """

    sent: bool = False
    raw_tx: str | None = None
    wanted: Callable[[], bool] = lambda: True
    on_submission: Callable[[str], None] | None = None


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
    # Client-side: the token the payer pays an unsponsored transaction's fee in.
    # ``None`` selects it from the charge currency and balances.
    payer_fee_token: str | None = field(default=None, kw_only=True)
    # Independent payer-owned limits; RPC quotes never override these budgets.
    payer_fee_policy: Mapping[str, int] | None = field(default=None, kw_only=True)
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
    # Buy the charge currency through the stablecoin DEX when the payer lacks
    # it. ``None`` disables auto-swap.
    auto_swap: AutoSwap | None = field(default=None, kw_only=True)
    # Settlement mode to use. ``None`` pulls when the challenge allows it, else
    # uses its first supported mode; an explicit mode it does not support fails.
    mode: ChargeMode | None = field(default=None, kw_only=True)
    # Client-side: the httpx client every RPC call goes through, owned by the
    # caller. Set default headers on it, such as a Tempo API key in
    # ``tempo-api-key``. None opens a client per call.
    http_client: httpx.AsyncClient | None = field(default=None, kw_only=True, repr=False)
    # Pays from this Zone's balance when a challenge accepts it (``methodDetails.zones``).
    zone: Zone | None = field(default=None, kw_only=True)
    # Zone withdrawals by challenge, kept after a failed wait so a retry resumes
    # waiting instead of withdrawing again.
    _zone_withdrawals: dict[str, tuple[asyncio.Task[str], _ZoneSend]] = field(
        default_factory=dict[str, tuple[asyncio.Task[str], _ZoneSend]], init=False, repr=False
    )
    _zone_chain_id: int | None = field(default=None, init=False, repr=False)
    _cached_chain_ids: dict[str, int] = field(
        default_factory=dict[str, int], init=False, repr=False
    )
    _chain_id_explicit: bool = field(default=False, init=False, repr=False)
    _currency_explicit: bool = field(default=True, init=False, repr=False)
    _chain_id_lock: asyncio.Lock | None = field(default=None, init=False, repr=False)
    _rpc_url_explicit: bool = field(default=False, init=False, repr=False)
    # Set only by :func:`charge` built with neither ``chain_id`` nor ``rpc_url``: the
    # client then pays on the chain each challenge names, as mppx does. A
    # directly constructed method stays pinned to its own chain.
    _follow_challenge_chain: bool = field(default=False, init=False, repr=False)
    _signing: dict[tuple[str, str], tuple[asyncio.Task[Credential], list[str]]] = field(
        default_factory=dict[tuple[str, str], tuple[asyncio.Task[Credential], list[str]]],
        init=False,
        repr=False,
    )
    # Callers still awaiting each in-flight signing: a push payment is not
    # broadcast once every caller has been cancelled.
    _signing_waiters: dict[tuple[str, str], int] = field(
        default_factory=dict[tuple[str, str], int], init=False, repr=False
    )

    @property
    def _rpc(self) -> dict[str, Any]:
        """Keyword arguments routing an RPC helper call through ``http_client``."""
        return {} if self.http_client is None else {"client": self.http_client}

    def __post_init__(self) -> None:
        """Validate charge policy at construction."""
        self._amount_caps()
        if self.payer_fee_policy is not None:
            self.payer_fee_policy = dict(self.payer_fee_policy)
            for key, value in self.payer_fee_policy.items():
                if key not in {"max_fee_per_gas", "max_priority_fee_per_gas", "max_total_fee"}:
                    raise ValueError(f"Unknown payer fee policy field: {key}")
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f"Payer fee policy {key} must be a non-negative integer")
        if self.mode not in (None, "push", "pull"):
            raise ValueError(f"Invalid Tempo charge mode: {self.mode!r}")
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

            chain_id_hex = await _rpc_call(rpc_url, "eth_chainId", [], **self._rpc)
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
        if self._follow_challenge_chain:
            # As mppx: an unpinned client pays on the chain the challenge names.
            return None
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
        if self._follow_challenge_chain:
            return None
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
        reserved: dict[str, int] | None = None,
    ) -> str:
        """Return a stablecoin that can cover the transaction fee.

        ``reserved`` maps lowercase token addresses to balance the transaction's
        calls already spend, which is not available for fees.
        """
        for token in fee_tokens_for_chain(chain_id):
            spent = (reserved or {}).get(token.lower(), 0)
            try:
                balance = await _tip20_balance(rpc_url, token, account, **self._rpc)
                if balance - spent >= required_balance:
                    return token
            except Exception:
                continue
        raise TransactionError("Charges require a funded supported stablecoin for transaction fees")

    async def _find_machine_token_route(
        self,
        *,
        account: str,
        amount: int,
        currency: str,
        recipient: str,
        memo: str | None,
        rpc_url: str,
    ) -> _machine_token.Route | None:
        """Return the machine-token route when ``account`` holds enough MACH and it simulates.

        As mppx's ``findRoute``, the route is optional: any failure falls back to the
        direct payment.
        """
        try:
            route = _machine_token.get_route(
                chain_id=await self._get_chain_id(rpc_url),
                currency=currency,
                amount=amount,
                recipient=recipient,
                memo=memo,
            )
            if route is None:
                return None
            token = route.calls[0][0]
            if await _tip20_balance(rpc_url, token, account, **self._rpc) < amount:
                return None
            batch = [{"to": to, "value": "0x0", "data": data} for to, data in route.calls]
            await _rpc_call(
                rpc_url,
                "eth_estimateGas",
                [{"from": account, "calls": batch}, "latest"],
                **self._rpc,
            )
        except Exception:
            return None
        return route

    async def _find_swap_calls(
        self,
        *,
        account: str,
        amount_out: int,
        token_out: str,
        rpc_url: str,
        fee_headroom: int = 0,
        token_in: str | None = None,
    ) -> tuple[list[tuple[str, str]], dict[str, int]]:
        """Return ``(to, data)`` approve and swap calls that top ``token_out`` up to ``amount_out``.

        See :func:`_find_auto_swap_calls`. With ``expected_recipients``, only buys
        a currency the client pinned or listed as a fallback.
        """
        assert self.auto_swap is not None
        trusted = (
            None
            if self.expected_recipients is None
            else (*self._pinned_currencies(), *self.auto_swap.currencies())
        )
        return await _find_auto_swap_calls(
            self.auto_swap,
            account=account,
            amount_out=amount_out,
            token_out=token_out,
            rpc_url=rpc_url,
            fee_headroom=fee_headroom,
            token_in=token_in,
            trusted_currencies=trusted,
            client=self.http_client,
        )

    def _check_charge_policy(self, request: dict[str, Any], expected_chain_id: int | None) -> None:
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
        # A challenge without a chain is paid on the pinned chain or, unpinned,
        # the configured default (mainnet), which the allowlist must also admit.
        # A chain pinned only by a custom rpc_url is unknown until its RPC is asked;
        # signing resolves it first and checks again.
        rpc_pinned = self._rpc_url_explicit and not self._chain_id_explicit
        self._check_allowed_chain_id(
            challenge_chain_id
            if challenge_chain_id is not None
            else expected_chain_id
            if expected_chain_id is not None
            else None
            if rpc_pinned
            else self.chain_id
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

    def _check_amount_caps(self, request: dict[str, Any]) -> None:
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

    def _check_expected_recipients(self, request: dict[str, Any]) -> None:
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
            splits = method_details.get("splits") if is_dict(method_details) else None
            for split in splits or ():
                split_recipient = split.get("recipient") if is_dict(split) else None
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
            self._rpc_url_for(challenge.request)
            # A zero amount pays with a proof, whatever the modes; otherwise an
            # offer whose supportedModes exclude this client's mode is skipped.
            if str(challenge.request.get("amount")) != "0":
                self._resolve_mode(challenge.request.get("methodDetails"))
        except ValueError:
            return False
        return True

    def _pinned(self) -> bool:
        return not self._follow_challenge_chain

    def _rpc_url_for(self, request: dict[str, Any]) -> str:
        """The RPC to sign against: the configured one, or for an unpinned client the
        default RPC of the challenge's chain (an unknown chain needs an explicit rpc_url)."""
        chain_id = _challenge_chain_id(request)
        if self._pinned() or chain_id is None or chain_id == self.chain_id:
            return self.rpc_url
        return rpc_url_for_chain(chain_id)

    async def create_credential(self, challenge: Challenge) -> Credential:
        """Create a credential to satisfy the given challenge.

        For the charge intent, this builds and signs a TempoTransaction (type 0x76)
        using an expiring nonce. Sponsored charges carry a fee payer placeholder
        for the server or fee payer service to co-sign before broadcast. In push
        mode the client broadcasts the transaction itself and sends its hash. A
        zero-amount charge is paid with a signed EIP-712 proof instead.

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
        attempt = self._signing.get(key)
        if attempt is None:
            submitted: list[str] = []
            task = asyncio.ensure_future(
                self._create_credential(
                    challenge,
                    wanted=lambda: self._signing_waiters.get(key, 0) > 0,
                    on_submission=submitted.append,
                )
            )
            self._signing[key] = (task, submitted)

            def finished(task: asyncio.Task[Credential]) -> None:
                self._signing.pop(key, None)
                if not task.cancelled():
                    task.exception()

            task.add_done_callback(finished)
        else:
            task, submitted = attempt
        self._signing_waiters[key] = self._signing_waiters.get(key, 0) + 1
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError as error:
            if submitted:
                from eth_hash.auto import keccak

                tx_hash = "0x" + keccak(bytes.fromhex(submitted[0].removeprefix("0x"))).hex()
                raise PaymentOutcomeUnknownError(
                    challenge, error, transaction_hash=tx_hash
                ) from error
            raise
        finally:
            remaining = self._signing_waiters[key] - 1
            if remaining:
                self._signing_waiters[key] = remaining
            else:
                del self._signing_waiters[key]

    async def _create_credential(
        self,
        challenge: Challenge,
        wanted: Callable[[], bool] = lambda: True,
        on_submission: Callable[[str], None] | None = None,
    ) -> Credential:
        if self.account is None:
            raise ValueError("No account configured for signing")

        request = challenge.request
        expected_chain_id = await self._resolve_expected_chain_id()
        self._check_charge_policy(request, expected_chain_id)
        if expected_chain_id is None:
            expected_chain_id = _challenge_chain_id(request)
        if expected_chain_id is None:
            expected_chain_id = self.chain_id
        method_details = request.get("methodDetails", {})
        # When signing with an access key, the credential source is the
        # root account (the smart wallet), not the access key.
        source_address = self.root_account if self.root_account else self.account.address

        # Zero-amount: sign an EIP-712 proof instead of a transaction (mppx
        # tempo/client/Charge.ts), bound to the payer named in the source.
        if int(request["amount"]) == 0:
            from mpp.methods.tempo._proof import proof_source, sign_proof

            if expected_chain_id is None:
                expected_chain_id = await self._get_chain_id(self._rpc_url_for(request))
            signature = sign_proof(
                self.account,
                account=source_address,
                chain_id=expected_chain_id,
                challenge_id=challenge.id,
                realm=challenge.realm,
            )
            return Credential(
                challenge=challenge.to_echo(),
                payload={"type": "proof", "signature": signature},
                source=proof_source(source_address, expected_chain_id),
            )

        if self.zone is not None:
            zone_id = await self._zone_payment(challenge, expected_chain_id)
            if zone_id is not None:
                # The settlement is read from this Tempo RPC, so confirm it serves the
                # pinned chain before withdrawing, as the Tempo path does before signing.
                _assert_rpc_chain_id(
                    await self._get_chain_id(self._rpc_url_for(request)), expected_chain_id
                )
                return await self._create_zone_credential(
                    challenge, zone_id, wanted=wanted, on_submission=on_submission
                )

        mode = self._resolve_mode(method_details)
        use_fee_payer = (
            mode == "pull" and method_details.get("feePayer", False)
            if is_dict(method_details)
            else False
        )
        if use_fee_payer:
            _assert_sponsored_challenge_time_left(challenge.expires)

        memo = encode_attribution(
            challenge_id=challenge.id,
            server_id=challenge.realm,
            client_id=self.client_id,
        )

        splits = method_details.get("splits") if is_dict(method_details) else None

        rpc_url = self._rpc_url_for(request)
        raw_tx, chain_id = await self._build_tempo_transfer(
            amount=request["amount"],
            currency=request["currency"],
            recipient=request["recipient"],
            memo=memo,
            rpc_url=rpc_url,
            expected_chain_id=expected_chain_id,
            awaiting_fee_payer=use_fee_payer,
            splits=splits,
            expires=(
                _push_transaction_expiry(challenge.expires) if mode == "push" else challenge.expires
            ),
            machine_token_enabled=is_dict(method_details)
            and method_details.get("machineTokenEnabled") is True,
        )

        if mode == "push":
            # Every caller was cancelled while the transfer was built: a
            # broadcast now would pay with no one left to receive the hash.
            if not wanted():
                raise asyncio.CancelledError("Push payment cancelled before broadcast")
            if on_submission is not None:
                on_submission(raw_tx)
            tx_hash = await _send_raw_transaction_sync(rpc_url, raw_tx, challenge, **self._rpc)
            return Credential(
                challenge=challenge.to_echo(),
                payload={"type": "hash", "hash": tx_hash},
                source=f"did:pkh:eip155:{chain_id}:{source_address}",
            )

        return Credential(
            challenge=challenge.to_echo(),
            payload={"type": "transaction", "signature": raw_tx},
            source=f"did:pkh:eip155:{chain_id}:{source_address}",
        )

    def _resolve_mode(self, method_details: Any) -> ChargeMode:
        """Pick push or pull from the challenge's ``supportedModes`` (both when absent).

        As mppx, an explicit ``mode`` the challenge does not support fails, and a
        local account prefers pull.
        """
        advertised = method_details.get("supportedModes") if is_dict(method_details) else None
        supported: list[ChargeMode] = (
            [mode for mode in advertised if mode in ("push", "pull")]
            if is_list(advertised)
            else ["pull", "push"]
        )
        if not supported:
            raise ValueError("Challenge supportedModes names no known mode.")
        if self.mode is not None:
            if self.mode not in supported:
                raise ValueError(f"Challenge does not support {self.mode} mode.")
            return self.mode
        return "pull" if "pull" in supported else supported[0]

    def transaction_hash(self, credential: Credential) -> str | None:
        """Return the on-chain hash of a credential's signed 0x76 transaction.

        Returns ``None`` unless the payload decodes as a sender-signed 0x76
        transaction. Sponsored (0x78 fee payer envelope) transactions return
        ``None`` because their final hash depends on the fee payer's co-signature.
        """
        from eth_hash.auto import keccak

        from mpp.methods.tempo import _rlp as rlp

        payload = credential.payload
        if payload.get("type") in ("hash", "zone"):
            tx_hash = payload.get("hash")
            return tx_hash if isinstance(tx_hash, str) else None
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
            not is_list(fields)
            or len(fields) not in (14, 15)
            or not is_list(fields[4])
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
        splits: list[dict[str, Any]] | None = None,
        expires: str | None = None,
        machine_token_enabled: bool = False,
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
            machine_token_enabled: The challenge enables machine-token payments: a payer
                holding enough MACH pays through the first-party swapper instead.

        Returns:
            Tuple of (raw signed transaction hex, chain ID).

        Raises:
            TransactionError: If the RPC's chain ID doesn't match expected.
        """
        # pytempo ships no type information.
        from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

        if self.account is None:
            raise ValueError("No account configured")

        resolved_rpc = rpc_url or self.rpc_url

        gas_estimate_data: str | None = None

        if splits:
            from mpp.methods.tempo.intents import get_transfers
            from mpp.methods.tempo.schemas import Split as SplitModel

            parsed_splits = [SplitModel(**s) for s in splits]
            transfer_list = get_transfers(int(amount), recipient, memo, parsed_splits)
            call_list: list[Call] = []
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

        transfer_calls = calls_tuple
        swapping = False
        swap_calls: list[tuple[str, str]] = []
        swap_spent: dict[str, int] = {}
        # As mppx, try the machine-token route before any other funding.
        machine_route = (
            await self._find_machine_token_route(
                account=sender,
                amount=int(amount),
                currency=currency,
                recipient=recipient,
                memo=memo,
                rpc_url=resolved_rpc,
            )
            if machine_token_enabled and not splits
            else None
        )
        if machine_route is not None:
            calls_tuple = tuple(
                Call.create(to=to, value=0, data=data) for to, data in machine_route.calls
            )
        elif self.auto_swap is not None:
            swap_calls, swap_spent = await self._find_swap_calls(
                account=sender, amount_out=int(amount), token_out=currency, rpc_url=resolved_rpc
            )
            swapping = bool(swap_calls)
            calls_tuple = (
                *(Call.create(to=to, value=0, data=data) for to, data in swap_calls),
                *transfer_calls,
            )

        chain_id = await self._get_chain_id(resolved_rpc)
        gas_price = int(await _rpc_call(resolved_rpc, "eth_gasPrice", [], **self._rpc), 16)
        max_priority_fee_per_gas = gas_price
        payer_policy = _get_payer_policy(chain_id, self.payer_fee_policy)
        if not awaiting_fee_payer:
            if gas_price < 0 or gas_price > payer_policy.max_fee_per_gas:
                raise TransactionError("RPC gas-price quote exceeds payer fee policy")
            max_priority_fee_per_gas = min(gas_price, payer_policy.max_priority_fee_per_gas)

        _assert_rpc_chain_id(chain_id, expected_chain_id)

        if awaiting_fee_payer:
            # Keep sponsored envelopes inside the server's default policy.
            max_priority_fee_per_gas = min(gas_price, get_policy(chain_id).max_priority_fee_per_gas)

        async def estimate_gas_limit(calls: tuple[Call, ...], swapping: bool) -> int:
            gas_limit = DEFAULT_GAS_LIMIT
            try:
                if swapping:
                    # Estimate the whole batch: the transfers alone run before the swap funds them.
                    batch = [
                        {
                            "to": "0x" + bytes(c.to).hex(),
                            "value": hex(c.value),
                            "data": "0x" + c.data.hex(),
                        }
                        for c in calls
                    ]
                    estimated = int(
                        await _rpc_call(
                            resolved_rpc,
                            "eth_estimateGas",
                            [{"from": sender, "calls": batch}, "latest"],
                            **self._rpc,
                        ),
                        16,
                    )
                    gas_limit = max(gas_limit, estimated + 5_000)
                elif splits:
                    total_estimated = 0
                    for c in calls:
                        total_estimated += await estimate_gas(
                            resolved_rpc, sender, currency, c.data.hex(), **self._rpc
                        )
                    gas_limit = max(gas_limit, total_estimated + 5_000 * len(calls))
                elif gas_estimate_data is not None:
                    estimated = await estimate_gas(
                        resolved_rpc, sender, currency, gas_estimate_data, **self._rpc
                    )
                    gas_limit = max(gas_limit, estimated + 5_000)
            except Exception:
                pass
            return gas_limit

        def fee_requirement(gas_limit: int) -> int:
            return max(
                1,
                (gas_limit * gas_price + ATTODOLLARS_PER_MICRODOLLAR - 1)
                // ATTODOLLARS_PER_MICRODOLLAR,
            )

        gas_limit = await estimate_gas_limit(calls_tuple, swapping or machine_route is not None)

        fee_token: str | None = None
        if not awaiting_fee_payer and self.payer_fee_token is not None:
            # An explicit fee token, such as one an access key's spending limits
            # cover (mppx#1149). Sponsored transactions leave it to the fee payer.
            fee_token = self.payer_fee_token
            explicit = fee_token.lower()
            if swapping and (explicit == currency.lower() or swap_spent.get(explicit, 0) > 0):
                # The batch spends the fee token: keep the fee out of what it spends.
                required_balance = fee_requirement(gas_limit)
                fee_balance = await _tip20_balance(resolved_rpc, fee_token, sender, **self._rpc)
                if fee_balance - swap_spent.get(explicit, 0) < required_balance:
                    rebuilt: tuple[list[tuple[str, str]], dict[str, int]] | None = None
                    if explicit == currency.lower():
                        # The payment spends all the fee token the payer holds: buy the fee too.
                        rebuilt = await self._find_swap_calls(
                            account=sender,
                            amount_out=int(amount),
                            token_out=currency,
                            rpc_url=resolved_rpc,
                            fee_headroom=required_balance,
                        )
                    else:
                        # The fee token funds the swap: swap from another currency instead.
                        assert self.auto_swap is not None
                        for token_in in self.auto_swap.currencies():
                            if token_in.lower() in (explicit, currency.lower()):
                                continue
                            try:
                                rebuilt = await self._find_swap_calls(
                                    account=sender,
                                    amount_out=int(amount),
                                    token_out=currency,
                                    rpc_url=resolved_rpc,
                                    token_in=token_in,
                                )
                            except InsufficientFundsError:
                                continue
                            break
                    if rebuilt is None:
                        raise TransactionError(
                            "Charges require a funded fee token for transaction fees"
                        )
                    swap_calls, swap_spent = rebuilt
                    if not swap_calls:
                        # The currency balance rose since the first read: no swap is needed.
                        swap_spent = {currency.lower(): int(amount)}
                    calls_tuple = (
                        *(Call.create(to=to, value=0, data=data) for to, data in swap_calls),
                        *transfer_calls,
                    )
                    # The calls changed: size gas and the fee for the batch that is signed.
                    gas_limit = await estimate_gas_limit(calls_tuple, bool(swap_calls))
                    required_balance = fee_requirement(gas_limit)
                    fee_balance = await _tip20_balance(resolved_rpc, fee_token, sender, **self._rpc)
                    if fee_balance - swap_spent.get(explicit, 0) < required_balance:
                        raise TransactionError(
                            "Charges require a funded fee token for transaction fees"
                        )
        elif not awaiting_fee_payer:
            fee_token = currency
            # A swapping payer may not hold the currency before the swap, so
            # it pays fees in a funded supported stablecoin.
            if (
                swapping
                or machine_route is not None
                or currency.lower() in (MACH.lower(), OUSD.lower())
            ):
                required_balance = fee_requirement(gas_limit)
                try:
                    fee_token = await self._resolve_supported_fee_token(
                        account=sender,
                        chain_id=chain_id,
                        rpc_url=resolved_rpc,
                        required_balance=required_balance,
                        reserved=swap_spent,
                    )
                except TransactionError:
                    if not swapping or currency.lower() not in (
                        t.lower() for t in fee_tokens_for_chain(chain_id)
                    ):
                        raise
                    # The payment spends all the currency the payer holds: buy the fee too.
                    swap_calls, swap_spent = await self._find_swap_calls(
                        account=sender,
                        amount_out=int(amount),
                        token_out=currency,
                        rpc_url=resolved_rpc,
                        fee_headroom=required_balance,
                    )
                    calls_tuple = (
                        *(Call.create(to=to, value=0, data=data) for to, data in swap_calls),
                        *transfer_calls,
                    )
                    if not swap_calls:
                        # The currency balance rose since the first read: no swap is needed.
                        swap_spent = {currency.lower(): int(amount)}
                    else:
                        fee_token = await self._resolve_supported_fee_token(
                            account=sender,
                            chain_id=chain_id,
                            rpc_url=resolved_rpc,
                            required_balance=required_balance,
                            reserved=swap_spent,
                        )
                        if fee_token.lower() != currency.lower():
                            # The rebuild freed another fee token: buy only the payment from
                            # the same token_in, since the swap may not exceed the charge.
                            swap_calls, swap_spent = await self._find_swap_calls(
                                account=sender,
                                amount_out=int(amount),
                                token_out=currency,
                                rpc_url=resolved_rpc,
                                token_in=swap_calls[0][0],
                            )
                            if not swap_calls:
                                swap_spent = {currency.lower(): int(amount)}
                            calls_tuple = (
                                *(
                                    Call.create(to=to, value=0, data=data)
                                    for to, data in swap_calls
                                ),
                                *transfer_calls,
                            )
                    # The calls changed: size gas and the fee for the batch that is signed.
                    gas_limit = await estimate_gas_limit(calls_tuple, bool(swap_calls))
                    required_balance = fee_requirement(gas_limit)
                    fee_token = await self._resolve_supported_fee_token(
                        account=sender,
                        chain_id=chain_id,
                        rpc_url=resolved_rpc,
                        required_balance=required_balance,
                        reserved=swap_spent,
                    )

        # The swap's amountOut is its third word. The server rejects an output above
        # the charge, so a fee the held currency cannot pay fails before signing.
        if swap_calls and int(swap_calls[-1][1][138:202], 16) > int(amount):
            raise TransactionError(
                "Charges require a funded supported stablecoin for transaction fees"
            )

        if awaiting_fee_payer:
            # The RPC round trips above take time: check again immediately before
            # signing (mppx#1131). valid_before is set from the current time below,
            # capped at the challenge expiry, so it keeps at least as much validity
            # as the challenge and needs no separate check (mppx#1137).
            _assert_sponsored_challenge_time_left(expires)

        if not awaiting_fee_payer and gas_limit * gas_price > payer_policy.max_total_fee:
            raise TransactionError("Transaction exceeds payer total-fee budget")

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
            # pytempo ships no type information.
            from pytempo import sign_tx_access_key  # pyright: ignore[reportMissingTypeStubs]

            signed_tx = sign_tx_access_key(tx, self.account.private_key, self.root_account)
        else:
            signed_tx = tx.sign(self.account.private_key)

        if awaiting_fee_payer:
            from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

            return "0x" + encode_fee_payer_envelope(signed_tx).hex(), chain_id

        return "0x" + signed_tx.encode().hex(), chain_id

    async def _get_zone_chain_id(self, zone: Zone) -> int:
        """Return the Zone's chain ID: configured, or read once from its RPC."""
        if zone.chain_id is not None:
            return zone.chain_id
        if self._zone_chain_id is None:
            kwargs = {} if zone.http_client is None else {"client": zone.http_client}
            chain_id = int(await _rpc_call(zone.rpc_url, "eth_chainId", [], **kwargs), 16)
            _assert_zone_chain(zone.zone_id, chain_id)
            self._zone_chain_id = chain_id
        return self._zone_chain_id

    async def _zone_payment(self, challenge: Challenge, chain_id: int | None) -> int | None:
        """Return the Zone ID to pay a challenge from, or ``None`` to pay on Tempo.

        As mppx, a Zone pays a positive push charge without splits on the Zone's
        parent chain when the challenge accepts it and the withdrawal can settle
        before the challenge expires (or is already under way).
        """
        zone = self.zone
        details = challenge.request.get("methodDetails")
        if zone is None or not is_dict(details) or details.get("zones") is None:
            return None
        # Parsed with the server's schema: a malformed field (such as an unknown
        # mode) fails the whole request there, so it is refused here rather than
        # read leniently and withdrawn for.
        parsed = _zones.parse_request(challenge.request).methodDetails
        accepted = parsed.zones
        supported = parsed.supportedModes or ["pull", "push"]
        if "push" not in supported or self.mode not in (None, "push") or parsed.splits:
            return None
        # Nothing is withdrawn yet, so a Zone that can't be resolved (its RPC is
        # down, or its chain names no Zone) leaves the challenge to Tempo.
        try:
            zone_chain_id = await self._get_zone_chain_id(zone)
            zone_id = (
                zone.zone_id if zone.zone_id is not None else _zones.id_from_chain_id(zone_chain_id)
            )
        except Exception:
            return None
        # An explicit parent chain that contradicts the Zone chain's own is a
        # misconfiguration, refused before anything is withdrawn.
        _assert_zone_parent_chain(zone.parent_chain_id, zone_chain_id)
        parent_chain_id = (
            zone.parent_chain_id
            if zone.parent_chain_id is not None
            else _zones.parent_chain_id_from_chain_id(zone_chain_id)
        )
        if chain_id is None or parent_chain_id != chain_id:
            return None
        if not _zones.is_accepted(accepted, zone_id):
            return None
        # Servers reject charge credentials for a challenge without an expiry, and a
        # withdrawal can't be undone, so refuse one before anything is withdrawn.
        if not challenge.expires:
            raise ValueError("Challenge has no expiry, so it can't be paid from a Zone.")
        # A withdrawal can't be undone, so start one only when it can settle before
        # the challenge expires; an expired challenge would invite another payment.
        if _zone_withdrawal_key(challenge) not in self._zone_withdrawals and not (
            _zone_settles_before_expiry(challenge.expires, zone.settlement_timeout)
        ):
            return None
        return zone_id

    async def _create_zone_credential(
        self,
        challenge: Challenge,
        zone_id: int,
        *,
        wanted: Callable[[], bool] = lambda: True,
        on_submission: Callable[[str], None] | None = None,
    ) -> Credential:
        """Pay a challenge from the Zone and return a ``zone`` credential.

        Requests a withdrawal to the recipient with the challenge-bound memo,
        then waits for the portal to settle it on Tempo. Concurrent and later
        calls for one challenge share the withdrawal, so a retry after a failed
        wait resumes it instead of paying again.

        Raises:
            ZoneSettlementPendingError: If the withdrawal did not settle in time.
            ZoneWithdrawalBouncedError: If the withdrawal settled but bounced back
                to the payer's Zone balance.
        """
        assert self.zone is not None
        zone = self.zone
        request = challenge.request
        key = _zone_withdrawal_key(challenge)
        existing = self._zone_withdrawals.get(key)
        if existing is None:
            state = _ZoneSend(wanted=wanted, on_submission=on_submission)
            new_task = asyncio.ensure_future(self._request_zone_withdrawal(challenge, state))
            self._zone_withdrawals[key] = (new_task, state)

            def finished(done: asyncio.Task[str]) -> None:
                # Only a failure before the transaction was sent is safe to retry.
                # After that, the withdrawal may have gone through, so retries of
                # this challenge keep failing.
                if done.cancelled() or (done.exception() is not None and not state.sent):
                    entry = self._zone_withdrawals.get(key)
                    if entry is not None and entry[0] is done:
                        del self._zone_withdrawals[key]

            new_task.add_done_callback(finished)
            task = new_task
        else:
            task, state = existing
            # A retry resuming a sent withdrawal reports it, so cancelling the
            # retry's wait still names the transaction that paid.
            if state.raw_tx is not None and on_submission is not None:
                on_submission(state.raw_tx)
        sender_tag = await asyncio.shield(task)

        try:
            settlement = await _zones.wait_for_settlement(
                self._rpc_url_for(request),
                portal=_zones.portal_address(zone_id),
                sender_tag=sender_tag,
                to=request["recipient"],
                timeout=_zone_settlement_timeout(challenge.expires, zone.settlement_timeout),
                first_scan_limit=_zone_time_left(challenge.expires),
                **self._rpc,
            )
        except Exception as cause:
            raise ZoneSettlementPendingError(
                challenge_id=challenge.id,
                sender_tag=sender_tag,
                zone_id=zone_id,
                challenge=challenge,
            ) from cause
        entry = self._zone_withdrawals.get(key)
        if not settlement.callback_success:
            # The withdrawal bounced back to the payer's Zone balance and paid
            # nothing, so forget it: paying again withdraws again (mpp-rs
            # ``ZoneWithdrawalBounced``). The server would reject its credential.
            if entry is not None and entry[0] is task:
                del self._zone_withdrawals[key]
            raise ZoneWithdrawalBouncedError(
                challenge_id=challenge.id,
                sender_tag=sender_tag,
                zone_id=zone_id,
                challenge=challenge,
            )
        # Forget the withdrawal only when a caller takes the credential: with every
        # caller gone, a retry must find it settled rather than withdraw again.
        if entry is not None and entry[0] is task and wanted():
            del self._zone_withdrawals[key]
        return Credential(
            challenge=challenge.to_echo(),
            payload={
                "hash": settlement.transaction_hash,
                "senderTag": sender_tag,
                "type": "zone",
                "zoneId": zone_id,
            },
        )

    async def _request_zone_withdrawal(self, challenge: Challenge, state: _ZoneSend) -> str:
        """Withdraw the challenge amount from the Zone to its recipient and return the sender tag.

        The withdrawal carries the challenge-bound memo. Its bounce refunds the
        payer, not the payee's Zone address.
        """
        # pytempo ships no type information.
        from eth_abi.abi import decode, encode
        from eth_hash.auto import keccak
        from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

        from mpp.methods.tempo.intents import APPROVE_SELECTOR

        assert self.zone is not None
        zone = self.zone
        account = zone.account or self.account
        if account is None:
            raise ValueError("Zone payments require an account.")
        root_account = self.root_account if zone.account is None else None
        sender = root_account or account.address
        request = challenge.request
        amount = int(request["amount"])
        currency = request["currency"]
        recipient = request["recipient"]
        memo = encode_attribution(
            challenge_id=challenge.id, server_id=challenge.realm, client_id=self.client_id
        )
        rpc_url = zone.rpc_url
        rpc: dict[str, Any] = {} if zone.http_client is None else {"client": zone.http_client}
        chain_id = await self._get_zone_chain_id(zone)

        # The outbox pulls the amount plus its withdrawal fee.
        fee_data = "0x" + _zones.CALCULATE_WITHDRAWAL_FEE_SELECTOR + _abi_words(0)
        fee = int(
            await _rpc_call(
                rpc_url, "eth_call", [{"to": _zones.ZONE_OUTBOX, "data": fee_data}, "latest"], **rpc
            ),
            16,
        )
        # The fee is spent in the charge currency too, so the client's amount caps
        # bound the whole withdrawal, not just the amount the challenge names.
        max_atomic, max_token = self._amount_caps()
        if max_atomic is not None and amount + fee > max_atomic:
            raise ValueError("Zone withdrawal amount plus its fee exceeds max_atomic_amount.")
        if max_token is not None and amount + fee > max_token:
            raise ValueError("Zone withdrawal amount plus its fee exceeds max_amount.")
        approve = "0x" + APPROVE_SELECTOR + _abi_words(_zones.ZONE_OUTBOX, amount + fee)
        withdrawal = (
            "0x"
            + _zones.REQUEST_WITHDRAWAL_SELECTOR
            + encode(
                ["address", "address", "uint128", "bytes32", "uint64", "address", "bytes", "bytes"],
                [currency, recipient, amount, bytes.fromhex(memo[2:]), 0, sender, b"", b""],
            ).hex()
        )
        calls = ((currency, approve), (_zones.ZONE_OUTBOX, withdrawal))
        gas_limit = (
            int(
                await _rpc_call(
                    rpc_url,
                    "eth_estimateGas",
                    [
                        {
                            "from": sender,
                            "calls": [
                                {"to": to, "value": "0x0", "data": data} for to, data in calls
                            ],
                        },
                        "latest",
                    ],
                    **rpc,
                ),
                16,
            )
            + _ZONE_GAS_MARGIN
        )
        gas_price = int(await _rpc_call(rpc_url, "eth_gasPrice", [], **rpc), 16)
        policy = _get_payer_policy(chain_id, self.payer_fee_policy)
        if gas_price < 0 or gas_price > policy.max_fee_per_gas:
            raise TransactionError("RPC gas-price quote exceeds payer fee policy")
        if gas_limit * gas_price > policy.max_total_fee:
            raise TransactionError("Transaction exceeds payer total-fee budget")
        valid_before = _zone_valid_before(challenge.expires, zone.settlement_timeout)
        if valid_before <= time.time():
            raise TransactionError(
                "Challenge expires too soon for a Zone withdrawal to settle; "
                "request a new challenge"
            )
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=gas_limit,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=min(gas_price, policy.max_priority_fee_per_gas),
            nonce=0,
            nonce_key=EXPIRING_NONCE_KEY,
            valid_before=valid_before,
            calls=tuple(Call.create(to=to, value=0, data=data) for to, data in calls),
        )
        # Sign first: a failure until here sent nothing, so the challenge may be retried.
        if root_account:
            from pytempo import sign_tx_access_key  # pyright: ignore[reportMissingTypeStubs]

            signed_tx = sign_tx_access_key(tx, account.private_key, root_account)
        else:
            signed_tx = tx.sign(account.private_key)
        raw_tx = "0x" + signed_tx.encode().hex()
        # The signed transaction fixes its hash, so a lost send response can still be
        # recovered from the Zone.
        tx_hash = "0x" + keccak(bytes.fromhex(raw_tx[2:])).hex()
        # Every caller was cancelled while the withdrawal was prepared: sending
        # it now would pay with no one left to receive the credential.
        if not state.wanted():
            raise asyncio.CancelledError("Zone withdrawal cancelled before submission")
        state.sent = True
        state.raw_tx = raw_tx
        if state.on_submission is not None:
            state.on_submission(raw_tx)
        try:
            receipt = await _rpc_call(rpc_url, "eth_sendRawTransactionSync", [raw_tx], **rpc)
        except Exception as cause:
            # A failure that cannot have reached the Zone moved nothing, so the
            # challenge may be retried.
            if _zone_submission_failed(cause):
                state.sent = False
                state.raw_tx = None
                raise TransactionError(f"Zone withdrawal submission failed: {cause}") from cause
            receipt = await _recover_zone_receipt(rpc_url, tx_hash, rpc)
            if receipt is None:
                raise TransactionError(
                    f"Zone withdrawal outcome is unknown: transaction {tx_hash} may have been "
                    "sent. Retrying this challenge does not withdraw again."
                ) from cause
        if not is_dict(receipt):
            raise TransactionError(f"Zone withdrawal transaction {tx_hash} returned no receipt.")
        receipt_hash = receipt.get("transactionHash")
        receipt_hash = receipt_hash if isinstance(receipt_hash, str) else tx_hash
        # A reverted withdrawal moved nothing, so the challenge may be retried.
        if receipt.get("status") == "0x0":
            state.sent = False
            raise TransactionError(f"Zone withdrawal transaction {receipt_hash} reverted.")
        logs = receipt.get("logs")
        for log in logs if is_list(logs) else []:
            topics = log.get("topics") if is_dict(log) else None
            data = log.get("data") if is_dict(log) else None
            if (
                not is_list(topics)
                or len(topics) != 3
                or not isinstance(topics[0], str)
                or topics[0].lower() != _zones.WITHDRAWAL_REQUESTED_TOPIC
                or not isinstance(topics[2], str)
                or not isinstance(data, str)
                or str(log.get("address", "")).lower() != _zones.ZONE_OUTBOX
            ):
                continue
            try:
                fields = decode(list(_zones.REQUESTED_DATA_TYPES), bytes.fromhex(data[2:]))
            except Exception:
                continue
            return _zones.sender_tag(
                sender="0x" + topics[2][-40:],
                transaction_hash=receipt_hash,
                fallback_nonce=int(fields[6]),
            )
        raise TransactionError("Zone withdrawal request did not emit WithdrawalRequested.")

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


def _zone_withdrawal_key(challenge: Challenge) -> str:
    """Key a Zone withdrawal by its whole Challenge, so another realm's or request's
    challenge with the same ID never matches."""
    return json.dumps(
        [
            challenge.id,
            challenge.realm,
            challenge.method,
            challenge.intent,
            challenge.request,
            challenge.expires,
            challenge.digest,
            challenge.description,
            challenge.opaque,
        ],
        sort_keys=True,
        default=str,
    )


def _zone_settles_before_expiry(expires: str | None, settlement_timeout: float | None) -> bool:
    """Whether a Zone withdrawal can be sent and waited on before ``expires``.

    A challenge without an expiry never qualifies: servers reject its credentials.
    """
    if not expires:
        return False
    timeout = (
        _zones.DEFAULT_SETTLEMENT_TIMEOUT if settlement_timeout is None else settlement_timeout
    )
    remaining = (_parse_expires(expires) - datetime.now(UTC)).total_seconds()
    return remaining > timeout + _ZONE_SUBMISSION_MARGIN


def _zone_settlement_timeout(expires: str | None, settlement_timeout: float | None) -> float:
    """Seconds to wait for settlement: ``settlement_timeout``, cut short at ``expires``."""
    timeout = (
        _zones.DEFAULT_SETTLEMENT_TIMEOUT if settlement_timeout is None else settlement_timeout
    )
    if not expires:
        return timeout
    remaining = (_parse_expires(expires) - datetime.now(UTC)).total_seconds()
    return max(0.0, min(timeout, remaining))


def _zone_time_left(expires: str | None) -> float | None:
    """Seconds left before ``expires`` (0 once it passed), or ``None`` without one."""
    if not expires:
        return None
    return max(0.0, (_parse_expires(expires) - datetime.now(UTC)).total_seconds())


def _zone_valid_before(expires: str | None, settlement_timeout: float | None) -> int:
    """Return a Zone withdrawal's ``valid_before``: late enough to settle and pay.

    A withdrawal included after ``expires`` minus the settlement timeout and
    submission margin could settle too late for its credential, so the
    transaction stops being valid then.
    """
    if not expires:
        return _expiring_valid_before(None)
    timeout = (
        _zones.DEFAULT_SETTLEMENT_TIMEOUT if settlement_timeout is None else settlement_timeout
    )
    cutoff = _parse_expires(expires) - timedelta(seconds=timeout + _ZONE_SUBMISSION_MARGIN)
    # _expiring_valid_before adds one second to the supplied expiry.
    return _expiring_valid_before((cutoff - timedelta(seconds=1)).isoformat())


def _parse_expires(expires: str) -> datetime:
    parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _zone_submission_failed(error: Exception) -> bool:
    """Whether a Zone withdrawal's send failed definitively, before it could pay.

    Classified as the push broadcast does: a definitive JSON-RPC error, or a
    transport failure before the request was sent (connect, pool). Anything
    else may have reached the Zone.
    """
    import httpx

    from mpp.methods.tempo._rpc import RpcError
    from mpp.methods.tempo.intents import _is_ambiguous_broadcast_error

    if isinstance(error, RpcError):
        return not _is_ambiguous_broadcast_error(error.response, resubmitted=True)
    if isinstance(error, httpx.HTTPError):
        return not _is_ambiguous_broadcast_error(error)
    return False


async def _recover_zone_receipt(
    rpc_url: str, tx_hash: str, rpc: dict[str, Any]
) -> dict[str, Any] | None:
    """Look for a Zone withdrawal's receipt after its send response failed."""
    deadline = time.monotonic() + _ZONE_RECEIPT_RECOVERY_TIMEOUT
    while True:
        try:
            receipt = await _rpc_call(rpc_url, "eth_getTransactionReceipt", [tx_hash], **rpc)
        except Exception:
            receipt = None
        if is_dict(receipt):
            return receipt
        if time.monotonic() + _zones.POLLING_INTERVAL > deadline:
            return None
        await asyncio.sleep(_zones.POLLING_INTERVAL)


def _check_recipient_addresses(request: dict[str, Any]) -> None:
    """Reject a primary or split recipient that is not a 20-byte hex address.

    The transfer calldata embeds each recipient as one ABI word, so a longer
    value would spill into the amount word and sign a transfer the amount caps
    never saw.
    """
    recipient = request.get("recipient")
    if not isinstance(recipient, str) or _ADDRESS_RE.fullmatch(recipient) is None:
        raise ValueError(f"Challenge recipient is not a valid address: {recipient!r}")
    method_details = request.get("methodDetails")
    splits = method_details.get("splits") if is_dict(method_details) else None
    if splits is not None and not is_list(splits):
        raise ValueError("Challenge splits must be a list")
    for split in splits or ():
        split_recipient = split.get("recipient") if is_dict(split) else None
        if not isinstance(split_recipient, str) or _ADDRESS_RE.fullmatch(split_recipient) is None:
            raise ValueError(
                f"Challenge split recipient is not a valid address: {split_recipient!r}"
            )


async def _send_raw_transaction_sync(
    rpc_url: str,
    raw_tx: str,
    challenge: Challenge | None = None,
    *,
    client: Any | None = None,
) -> str:
    """Broadcast a signed transaction, wait for its receipt and return its hash.

    A node that answers with a definitive JSON-RPC error refused the
    transaction. Any other failure (a timeout, a lost response, EIP-7966's
    code 4 for a pooled but unconfirmed transaction, or "already known") may
    come after the node accepted it, so it raises ``PaymentOutcomeUnknownError``
    with the transaction's hash rather than an error the caller could take as
    "nothing was paid". This classifies errors as the server's broadcast does.
    """
    import httpx
    from eth_hash.auto import keccak

    from mpp.methods.tempo._rpc import RpcError
    from mpp.methods.tempo.intents import _is_ambiguous_broadcast_error

    def unknown(error: BaseException) -> PaymentOutcomeUnknownError:
        tx_hash = "0x" + keccak(bytes.fromhex(raw_tx.removeprefix("0x"))).hex()
        return PaymentOutcomeUnknownError(challenge, error, transaction_hash=tx_hash)

    if challenge is not None:
        _push_transaction_expiry(challenge.expires)
    try:
        receipt = await _rpc_call(rpc_url, "eth_sendRawTransactionSync", [raw_tx], client=client)
    except RpcError as error:
        # A replay of the payer's own transaction means it may already be
        # paid, never that nothing was, so it is an unknown outcome here.
        if _is_ambiguous_broadcast_error(error.response, resubmitted=True):
            raise unknown(error) from error
        raise TransactionError(f"Transaction submission failed: {error}") from error
    except RuntimeError as error:
        raise TransactionError(f"Transaction submission failed: {error}") from error
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
        raise unknown(error) from error
    tx_hash = receipt.get("transactionHash") if is_dict(receipt) else None
    if (
        not isinstance(tx_hash, str)
        or re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash) is None
        or receipt.get("status") not in ("0x0", "0x1")
    ):
        raise unknown(TransactionError("Incomplete transaction receipt returned"))
    if receipt.get("status") == "0x0":
        raise TransactionError(f"Transaction {tx_hash} reverted")
    return tx_hash


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


def _push_transaction_expiry(expires: str | None) -> str | None:
    """Leave time after inclusion to deliver a hash credential to the merchant."""
    if expires is None:
        return None
    try:
        deadline = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if deadline.tzinfo is None:
            raise ValueError("missing timezone")
    except ValueError as error:
        raise PaymentExpiredError(expires) from error
    if deadline.timestamp() - time.time() <= MIN_REMAINING_VALIDITY_SECONDS:
        raise PaymentExpiredError(expires)
    # _expiring_valid_before adds one second to the supplied expiry.
    return (deadline - timedelta(seconds=MIN_REMAINING_VALIDITY_SECONDS + 1)).isoformat()


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
    auto_swap: bool | AutoSwap = False,
    mode: ChargeMode | None = None,
    payer_fee_token: str | None = None,
    payer_fee_policy: Mapping[str, int] | None = None,
    http_client: httpx.AsyncClient | None = None,
    zone: Zone | None = None,
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
            then USDC.e on mainnet). A hosted fee payer picks its own token
            unless this is set, in which case its token must be in the list.
            Must contain at least one token.
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
        auto_swap: When the payer lacks the challenge currency, buy it through
            the Tempo stablecoin DEX from a fallback currency (pathUSD, then
            USDC.e, then OUSD) in the same transaction. ``True`` uses 1%
            slippage; pass :class:`AutoSwap` to prepend currencies, restrict
            them to ``token_in`` (``fallback=False``) or change the slippage.
            Fees are never paid in OUSD, which is not a fee token.
            Raises :class:`InsufficientFundsError` when no currency can fund it.
            With ``expected_recipients``, it only buys a currency the client
            pinned or swaps from.
        mode: Settlement mode when paying (``"push"`` or ``"pull"``). ``None``
            pulls when the challenge's ``supportedModes`` allow it, else uses
            its first supported mode.
        http_client: httpx client for the payer's RPC calls, owned by the
            caller. Configure headers on it, such as a Tempo API key in
            ``tempo-api-key`` for the hosted RPC (https://api.tempo.xyz/rpc), and a
            timeout of at least 30 seconds for push-mode broadcasts.

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
    if payer_fee_token is not None and (
        not isinstance(payer_fee_token, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        or _ADDRESS_RE.fullmatch(payer_fee_token) is None
    ):
        raise ValueError(f"Invalid Tempo fee token address: {payer_fee_token!r}")
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
        auto_swap=AutoSwap() if auto_swap is True else auto_swap or None,
        mode=mode,
        payer_fee_token=payer_fee_token,
        payer_fee_policy=payer_fee_policy,
        http_client=http_client,
        zone=zone,
    )
    if (max_atomic_amount is not None or max_amount is not None) and not currency_explicit:
        raise ValueError(_CAPS_REQUIRE_CURRENCY_PIN)
    method._chain_id_explicit = chain_id_explicit
    method._currency_explicit = currency_explicit
    method._rpc_url_explicit = rpc_url_explicit
    method._follow_challenge_chain = not chain_id_explicit and not rpc_url_explicit
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
    auto_swap: bool | AutoSwap = False,
    mode: ChargeMode | None = None,
    fee_token: str | None = None,
    fee_policy: Mapping[str, int] | None = None,
    http_client: httpx.AsyncClient | None = None,
    zone: Zone | None = None,
) -> ClientMethod:
    """Create the client method that pays Tempo charge challenges.

    It signs a TIP-20 transfer (type ``0x76`` transaction with an expiring nonce)
    for each challenge it accepts. Options are described on :func:`_tempo_method`:
    ``currency``/``currencies`` pin the currencies it pays, and the charge policy
    (``max_atomic_amount``, ``max_amount``, ``expected_recipients``,
    ``allowed_chain_ids`` and the ``chain_id``/``rpc_url`` pin) skips other
    challenges during selection and rejects them before signing. ``auto_swap``
    buys a missing charge currency through the stablecoin DEX.

    ``mode`` chooses how a charge settles: ``"pull"`` sends the signed
    transaction for the server to broadcast, ``"push"`` broadcasts it and sends
    its hash. By default the client pulls when the challenge's
    ``supportedModes`` allow it and otherwise pushes; an explicit mode the
    challenge does not support fails. Zero-amount charges are paid with a
    signed EIP-712 proof, without a transaction.

    ``fee_token`` is the token the payer pays the transaction fee in when the
    challenge is not fee-sponsored. Set it for an access key whose spending
    limits do not cover the default fee token, such as a key limited to OUSD
    paying a USDC.e charge. By default the fee is paid in the charge currency,
    or in a funded supported stablecoin when that currency cannot pay fees.

    ``fee_policy`` overrides payer-owned ``max_fee_per_gas``,
    ``max_priority_fee_per_gas`` and ``max_total_fee`` ceilings for unsponsored
    payments. Values use attodollars per gas and attodollars, respectively.
    Defaults use the chain's per-gas sponsorship ceilings and a 0.1 USD total
    budget covering the static gas floor. Excessive RPC quotes and worst-case
    total fees are rejected before signing; priority
    fees are capped. These budgets are separate from the transferred amount.

    ``http_client`` carries every RPC call the payer makes, as mppx's
    ``getClient`` does. The caller owns it. Set a Tempo API key on it for
    the hosted RPC: ``httpx.AsyncClient(headers={"tempo-api-key": key}, timeout=30)``
    with ``rpc_url="https://api.tempo.xyz/rpc"``. Give it a timeout of at least
    30 seconds: push mode waits on ``eth_sendRawTransactionSync`` for the receipt,
    and httpx's 5 second default can end a payment in ``PaymentOutcomeUnknownError``.

    ``zone`` pays from a Zone balance instead of the account's Tempo balance when
    a challenge accepts that Zone (``methodDetails.zones``); see :class:`Zone`.
    If the withdrawal does not settle in time, it raises
    :class:`~mpp.errors.ZoneSettlementPendingError`; passing its ``challenge`` to
    the same method's ``create_credential`` resumes the withdrawal instead of
    paying again, while a new request's fresh challenge would withdraw again.

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
            auto_swap=auto_swap,
            mode=mode,
            payer_fee_token=fee_token,
            payer_fee_policy=fee_policy,
            http_client=http_client,
            zone=zone,
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


def _abi_words(*args: str | int) -> str:
    """ABI-encode static address and uint arguments as hex words."""
    return "".join(
        (arg.removeprefix("0x").lower() if isinstance(arg, str) else f"{arg:x}").zfill(64)
        for arg in args
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


def _challenge_chain_id(request: dict[str, Any]) -> int | None:
    """Return the challenge's numeric ``methodDetails.chainId``, ignoring other values."""
    method_details = request.get("methodDetails")
    chain_id = method_details.get("chainId") if is_dict(method_details) else None
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


def _parse_max_amount(value: str | Decimal, decimals: int, *, intent: str = "charge") -> int:
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
            f"Tempo {intent} max_amount {value} has more fractional digits "
            f"than {decimals} decimals allow."
        )
    return atomic


_SESSION_EXPORTS = ("session", "session_manager")


def __getattr__(name: str) -> Any:
    """Lazily load the session client (``session``, ``session_manager``)."""
    if name in _SESSION_EXPORTS:
        from mpp.methods.tempo.session import client as session_client

        value = getattr(session_client, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
