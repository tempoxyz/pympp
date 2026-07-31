"""Client-side Tempo TIP-1034 session payments."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import threading
import time
from collections.abc import Awaitable, Callable, Sequence
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

import httpx

from mpp import Challenge, Credential, MemoryStore, ParseError, Receipt, Store
from mpp.client.transport import _auth_challenges
from mpp.methods.tempo._defaults import CHAIN_ID, RPC_URL, rpc_url_for_chain
from mpp.methods.tempo._rpc import _rpc_call, get_tx_params
from mpp.methods.tempo._session_sse import (
    wrap_async_sse_response,
    wrap_sync_sse_response,
)
from mpp.methods.tempo.client import (
    EXPIRING_NONCE_KEY,
    FEE_PAYER_VALID_BEFORE_SECS,
    TransactionError,
)
from mpp.methods.tempo.fee_payer_policy import get_policy

if TYPE_CHECKING:
    from mpp.methods.tempo.account import TempoAccount

    class AsyncHttpResponseContext(Protocol):
        challenge: Challenge
        credential: Credential
        request: httpx.Request
        response: httpx.Response
        refetch: Callable[[], Awaitable[httpx.Response]] | None
        send: Callable[[httpx.Request], Awaitable[httpx.Response]]
        create_credential: Callable[..., Awaitable[Credential]]

    class SyncHttpResponseContext(Protocol):
        challenge: Challenge
        credential: Credential
        request: httpx.Request
        response: httpx.Response
        refetch: Callable[[], httpx.Response] | None
        send: Callable[[httpx.Request], httpx.Response]
        create_credential: Callable[..., Credential]
        run_sync: Callable[[Awaitable[Any]], Any]


TIP20_CHANNEL_ESCROW = "0x4d50500000000000000000000000000000000000"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
MAX_UINT96 = (1 << 96) - 1
SESSION_GAS_LIMIT = 2_000_000

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_AMOUNT_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_HELD: ContextVar[frozenset[tuple[int, str]]] = ContextVar(
    "mpp_tempo_session_locks", default=frozenset()
)


@dataclass(frozen=True, slots=True)
class _Descriptor:
    payer: str
    payee: str
    operator: str
    token: str
    salt: str
    authorized_signer: str
    expiring_nonce_hash: str

    @classmethod
    def parse(cls, value: object) -> _Descriptor:
        if not isinstance(value, dict):
            raise ValueError("session descriptor must be an object")
        return cls(
            payer=_address(value.get("payer"), "descriptor.payer"),
            payee=_address(value.get("payee"), "descriptor.payee"),
            operator=_address(value.get("operator"), "descriptor.operator"),
            token=_address(value.get("token"), "descriptor.token"),
            salt=_bytes32(value.get("salt"), "descriptor.salt"),
            authorized_signer=_address(
                value.get("authorizedSigner"), "descriptor.authorizedSigner"
            ),
            expiring_nonce_hash=_bytes32(
                value.get("expiringNonceHash"), "descriptor.expiringNonceHash"
            ),
        )

    def wire(self) -> dict[str, str]:
        return {
            "payer": self.payer,
            "payee": self.payee,
            "operator": self.operator,
            "token": self.token,
            "salt": self.salt,
            "authorizedSigner": self.authorized_signer,
            "expiringNonceHash": self.expiring_nonce_hash,
        }


@dataclass(slots=True)
class _Channel:
    channel_id: str
    descriptor: _Descriptor
    escrow: str
    chain_id: int
    deposit: int
    cumulative: int
    accepted: int = 0
    status: Literal["pending", "open"] = "pending"
    pending_transaction: str | None = None
    pending_top_up: int | None = None

    def dump(self) -> str:
        value = asdict(self)
        value["descriptor"] = self.descriptor.wire()
        for name in ("deposit", "cumulative", "accepted", "pending_top_up"):
            if value[name] is None:
                continue
            value[name] = str(value[name])
        return json.dumps(value, separators=(",", ":"), sort_keys=True)

    @classmethod
    def load(cls, raw: object) -> _Channel:
        if isinstance(raw, bytes):
            raw = raw.decode()
        try:
            value = json.loads(cast("str", raw))
        except (TypeError, ValueError) as error:
            raise ValueError("invalid stored Tempo session channel") from error
        if not isinstance(value, dict) or value.get("status") not in {"pending", "open"}:
            raise ValueError("invalid stored Tempo session channel")
        return cls(
            channel_id=_bytes32(value.get("channel_id"), "channel_id"),
            descriptor=_Descriptor.parse(value.get("descriptor")),
            escrow=_address(value.get("escrow"), "escrow"),
            chain_id=_chain_id(value.get("chain_id"), "chain_id"),
            deposit=_amount(value.get("deposit"), "deposit"),
            cumulative=_amount(value.get("cumulative"), "cumulative"),
            accepted=_amount(value.get("accepted"), "accepted"),
            status=cast("Literal['pending', 'open']", value["status"]),
            pending_transaction=_transaction_hex(value.get("pending_transaction")),
            pending_top_up=(
                _amount(value["pending_top_up"], "pending_top_up")
                if value.get("pending_top_up") is not None
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class _Request:
    amount: int
    payee: str
    token: str
    operator: str
    escrow: str
    chain_id: int
    fee_payer: bool
    suggested_deposit: int | None
    min_voucher_delta: int
    snapshot: dict[str, Any] | None
    scope: str


@dataclass
class TempoSessionMethod:
    """Client-only TIP-1034 v2 method for HTTP and SSE payments."""

    account: TempoAccount
    max_deposit: int
    rpc_url: str = RPC_URL
    chain_id: int = CHAIN_ID
    escrow: str = TIP20_CHANNEL_ESCROW
    channel_store: Store = field(default_factory=MemoryStore)
    name: str = field(default="tempo", init=False)
    _intents: dict[str, object] = field(
        default_factory=lambda: {"session": object()}, init=False, repr=False
    )
    _locks: dict[str, threading.Lock] = field(default_factory=dict, init=False, repr=False)
    _locks_guard: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def intents(self) -> dict[str, object]:
        return self._intents

    def can_handle_challenge(self, challenge: Challenge) -> bool:
        details = challenge.request.get("methodDetails")
        return (
            challenge.method == self.name
            and challenge.intent == "session"
            and isinstance(details, dict)
            and details.get("sessionProtocol") == "v2"
        )

    async def create_credential(
        self, challenge: Challenge, *, context: object | None = None
    ) -> Credential:
        request = self._resolve(challenge)
        async with self._locked(request.scope):
            return await self._create(challenge, request, context)

    async def handle_async_http_response(
        self, exchange: AsyncHttpResponseContext
    ) -> httpx.Response:
        request = self._resolve(exchange.challenge)
        action = exchange.credential.payload.get("action")
        if not exchange.response.is_success:
            return exchange.response
        async with self._locked(request.scope):
            await self._accept_response(
                request,
                exchange.response,
                exchange.challenge,
                exchange.credential.payload,
            )
        if action == "topUp" and exchange.refetch:
            return await exchange.refetch()
        if not _is_sse(exchange.response):
            wants_sse = "text/event-stream" in exchange.request.headers.get("accept", "").lower()
            if action == "open" and wants_sse and exchange.refetch:
                return await exchange.refetch()
            return exchange.response

        async def need_voucher(event: dict[str, Any]) -> None:
            async with self._locked(request.scope):
                await self._need_voucher_async(exchange, request, event)

        async def receipt(event: dict[str, Any]) -> None:
            async with self._locked(request.scope):
                await self._record_receipt(request, event, exchange.challenge)

        return wrap_async_sse_response(
            exchange.response, on_need_voucher=need_voucher, on_receipt=receipt
        )

    def handle_http_response(self, exchange: SyncHttpResponseContext) -> httpx.Response:
        request = self._resolve(exchange.challenge)
        action = exchange.credential.payload.get("action")
        if not exchange.response.is_success:
            return exchange.response
        with self._locked_sync(request.scope):
            exchange.run_sync(
                self._accept_response(
                    request,
                    exchange.response,
                    exchange.challenge,
                    exchange.credential.payload,
                )
            )
        if action == "topUp" and exchange.refetch:
            return exchange.refetch()
        if not _is_sse(exchange.response):
            wants_sse = "text/event-stream" in exchange.request.headers.get("accept", "").lower()
            if action == "open" and wants_sse and exchange.refetch:
                return exchange.refetch()
            return exchange.response

        def need_voucher(event: dict[str, Any]) -> None:
            with self._locked_sync(request.scope):
                self._need_voucher_sync(exchange, request, event)

        def receipt(event: dict[str, Any]) -> None:
            with self._locked_sync(request.scope):
                exchange.run_sync(self._record_receipt(request, event, exchange.challenge))

        return wrap_sync_sse_response(
            exchange.response, on_need_voucher=need_voucher, on_receipt=receipt
        )

    async def _create(
        self, challenge: Challenge, request: _Request, context: object | None
    ) -> Credential:
        payload = (
            await self._management(request, context)
            if context is not None
            else await self._payment(request)
        )
        return Credential(
            challenge=challenge.to_echo(),
            payload=payload,
            source=f"did:pkh:eip155:{request.chain_id}:{self.account.address.lower()}",
        )

    async def _payment(self, request: _Request) -> dict[str, Any]:
        channel = await self._load(request)
        if channel is None and request.snapshot is not None:
            channel = await self._recover(request)
        if channel is None:
            target = request.amount
            _limit(target, self.max_deposit, "initial voucher")
            deposit = min(max(target, request.suggested_deposit or target), self.max_deposit)
            return await self._open(request, deposit, target)

        replacement = await self._replace_expired_pending(request, channel)
        if replacement is not None:
            return replacement

        accepted = channel.accepted
        if request.snapshot is not None:
            snapshot = self._snapshot(request, channel)
            required = _amount(snapshot["requiredCumulative"], "requiredCumulative")
            accepted = _amount(snapshot["acceptedCumulative"], "acceptedCumulative")
            if accepted > channel.cumulative:
                raise ValueError("server accepted cumulative exceeds local signed watermark")
            await self._reconcile_deposit(channel, _amount(snapshot["deposit"], "deposit"))
            if channel.status == "pending":
                channel.status = "open"
                channel.pending_transaction = None
            channel.cumulative = max(channel.cumulative, accepted)
            channel.accepted = max(channel.accepted, accepted)
            accepted = channel.accepted
            self._validate(channel, request)
            await self._save(request, channel)
        else:
            if channel.status == "pending":
                return self._open_payload(channel)
            if channel.pending_top_up is not None:
                return self._top_up_payload(channel)
            required = channel.accepted + request.amount

        if channel.pending_top_up is not None:
            return self._top_up_payload(channel)

        target = max(required, channel.cumulative, accepted + request.min_voucher_delta)
        _limit(target, self.max_deposit, "voucher")
        if target > channel.deposit:
            return await self._top_up(request, channel, target - channel.deposit)
        return await self._voucher(request, channel, target)

    async def _management(self, request: _Request, context: object) -> dict[str, Any]:
        if not isinstance(context, dict):
            raise ValueError("Tempo session context must be an object")
        channel = await self._require(request)
        if context.get("channelId") != channel.channel_id:
            raise ValueError("session context references the wrong channel")
        if channel.status != "open":
            raise ValueError("Tempo session channel is not open")
        action = context.get("action")
        if action == "topUp":
            additional = _amount(context.get("additionalDeposit"), "additionalDeposit")
            if additional == 0:
                raise ValueError("additionalDeposit must be greater than zero")
            _limit(channel.deposit + additional, self.max_deposit, "channel deposit")
            return await self._top_up(request, channel, additional)
        if action == "voucher":
            if channel.pending_top_up is not None:
                raise ValueError("Tempo session top-up has not been confirmed")
            target = max(channel.cumulative, _amount(context.get("cumulativeAmount"), "cumulative"))
            _limit(target, min(self.max_deposit, channel.deposit), "voucher")
            return await self._voucher(request, channel, target)
        raise ValueError(f"Unsupported Tempo session action: {action!r}")

    async def _open(self, request: _Request, deposit: int, cumulative: int) -> dict[str, Any]:
        if deposit == 0:
            raise ValueError("Tempo session deposit must be greater than zero")
        salt = "0x" + os.urandom(32).hex()
        payer = self.account.address.lower()
        call = _call(
            "open(address,address,address,uint96,bytes32,address)",
            ["address", "address", "address", "uint96", "bytes32", "address"],
            [
                request.payee,
                request.operator,
                request.token,
                deposit,
                bytes.fromhex(salt[2:]),
                payer,
            ],
        )
        transaction, unsigned = await self._transaction(request, call)
        try:
            preimage = unsigned.encode_for_signing()
        except AttributeError as error:
            raise RuntimeError(
                "Tempo sessions require a pytempo release with encode_for_signing()"
            ) from error
        descriptor = _Descriptor(
            payer=payer,
            payee=request.payee,
            operator=request.operator,
            token=request.token,
            salt=salt,
            authorized_signer=payer,
            expiring_nonce_hash="0x" + _keccak(preimage + bytes.fromhex(payer[2:])).hex(),
        )
        channel_id = _channel_id(descriptor, request.escrow, request.chain_id)
        channel = _Channel(
            channel_id=channel_id,
            descriptor=descriptor,
            escrow=request.escrow,
            chain_id=request.chain_id,
            deposit=deposit,
            cumulative=cumulative,
            pending_transaction=transaction,
        )
        await self._save(request, channel)
        return self._open_payload(channel)

    async def _top_up(
        self, request: _Request, channel: _Channel, additional: int
    ) -> dict[str, Any]:
        if channel.pending_top_up is not None:
            return self._top_up_payload(channel)
        transaction, _ = await self._transaction(
            request,
            _call(
                "topUp((address,address,address,address,bytes32,address,bytes32),uint96)",
                ["(address,address,address,address,bytes32,address,bytes32)", "uint96"],
                [_descriptor_tuple(channel.descriptor), additional],
            ),
            distinguish=True,
        )
        channel.pending_transaction = transaction
        channel.pending_top_up = additional
        await self._save(request, channel)
        return self._top_up_payload(channel)

    def _open_payload(self, channel: _Channel) -> dict[str, Any]:
        transaction = channel.pending_transaction
        if transaction is None:
            raise ValueError("pending Tempo session open has no transaction")
        return {
            "action": "open",
            "type": "transaction",
            "channelId": channel.channel_id,
            "transaction": transaction,
            "descriptor": channel.descriptor.wire(),
            "cumulativeAmount": str(channel.cumulative),
            "signature": _voucher_signature(
                self.account,
                channel.channel_id,
                channel.cumulative,
                channel.escrow,
                channel.chain_id,
            ),
            "authorizedSigner": channel.descriptor.authorized_signer,
        }

    def _top_up_payload(self, channel: _Channel) -> dict[str, Any]:
        transaction = channel.pending_transaction
        additional = channel.pending_top_up
        if transaction is None or additional is None:
            raise ValueError("pending Tempo session top-up is incomplete")
        return {
            "action": "topUp",
            "type": "transaction",
            "channelId": channel.channel_id,
            "transaction": transaction,
            "descriptor": channel.descriptor.wire(),
            "additionalDeposit": str(additional),
        }

    async def _voucher(
        self, request: _Request, channel: _Channel, cumulative: int
    ) -> dict[str, Any]:
        channel.cumulative = cumulative
        await self._save(request, channel)
        return {
            "action": "voucher",
            "channelId": channel.channel_id,
            "descriptor": channel.descriptor.wire(),
            "cumulativeAmount": str(cumulative),
            "signature": _voucher_signature(
                self.account,
                channel.channel_id,
                cumulative,
                channel.escrow,
                channel.chain_id,
            ),
        }

    async def _transaction(
        self,
        request: _Request,
        data: bytes,
        *,
        distinguish: bool = False,
    ) -> tuple[str, Any]:
        from pytempo import Call, TempoTransaction

        chain_id, _, gas_price = await get_tx_params(self.rpc_url, self.account.address)
        if chain_id != request.chain_id:
            raise TransactionError(
                f"Chain ID mismatch: RPC returned {chain_id}, expected {request.chain_id}"
            )
        priority = gas_price
        if request.fee_payer:
            priority = min(gas_price, get_policy(chain_id).max_priority_fee_per_gas)
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=SESSION_GAS_LIMIT,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=priority,
            nonce=0,
            nonce_key=EXPIRING_NONCE_KEY,
            fee_token=None if request.fee_payer else request.token,
            awaiting_fee_payer=request.fee_payer,
            valid_before=int(time.time()) + FEE_PAYER_VALID_BEFORE_SECS,
            valid_after=(_random_valid_after() if distinguish else None),
            calls=(Call.create(to=request.escrow, value=0, data=data),),
        )
        signed = tx.sign(self.account.private_key)
        if request.fee_payer:
            from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope

            return "0x" + encode_fee_payer_envelope(signed).hex(), tx
        return "0x" + signed.encode().hex(), tx

    async def _replace_expired_pending(
        self, request: _Request, channel: _Channel
    ) -> dict[str, Any] | None:
        transaction = channel.pending_transaction
        if transaction is None:
            return None
        valid_before = _transaction_valid_before(transaction)
        if valid_before is None or valid_before > int(time.time()):
            return None
        chain_timestamp, block_number = await self._expiry_block()
        if chain_timestamp < valid_before:
            return None

        settled, deposit, closing = await self._channel_state(channel, block_number)
        if (
            closing != 0
            or settled > channel.cumulative
            or (deposit < channel.deposit and (channel.status == "open" or deposit != 0))
        ):
            raise ValueError("expired Tempo session transaction cannot be safely reconciled")
        _limit(deposit, self.max_deposit, "channel deposit")

        if channel.status == "pending":
            if deposit == 0:
                return await self._open(request, channel.deposit, channel.cumulative)
            channel.status = "open"
            channel.deposit = deposit
            channel.pending_transaction = None
            await self._save(request, channel)
            return None

        additional = channel.pending_top_up
        if additional is None:
            raise ValueError("expired Tempo session top-up is incomplete")
        target = channel.deposit + additional
        channel.deposit = deposit
        channel.pending_transaction = None
        channel.pending_top_up = None
        if deposit < target:
            return await self._top_up(request, channel, target - deposit)
        await self._save(request, channel)
        return None

    async def _expiry_block(self) -> tuple[int, dict[str, object]]:
        block = await _rpc_call(self.rpc_url, "eth_getBlockByNumber", ["finalized", False])
        if not isinstance(block, dict):
            raise ValueError("invalid finalized block RPC response")
        timestamp = _rpc_quantity(block.get("timestamp"), "finalized block timestamp")
        block_hash = _bytes32(block.get("hash"), "finalized block hash")
        return timestamp, {"blockHash": block_hash, "requireCanonical": True}

    async def _recover(self, request: _Request) -> _Channel:
        snapshot = request.snapshot
        assert snapshot is not None
        accepted = _amount(snapshot.get("acceptedCumulative"), "acceptedCumulative")
        signed = snapshot.get("highestVoucher")
        if not isinstance(signed, dict):
            raise ValueError("session snapshot is missing its highest signed voucher")
        channel_id = _bytes32(snapshot.get("channelId"), "sessionSnapshot.channelId")
        if _bytes32(signed.get("channelId"), "highestVoucher.channelId") != channel_id:
            raise ValueError("session snapshot voucher references the wrong channel")
        cumulative = _amount(signed.get("cumulativeAmount"), "highestVoucher.cumulativeAmount")
        if cumulative != accepted:
            raise ValueError("session snapshot voucher amount does not match acceptedCumulative")
        channel = _Channel(
            channel_id=channel_id,
            descriptor=_Descriptor.parse(snapshot.get("descriptor")),
            escrow=_address(snapshot.get("escrow"), "sessionSnapshot.escrow"),
            chain_id=_chain_id(snapshot.get("chainId"), "sessionSnapshot.chainId"),
            deposit=_amount(snapshot.get("deposit"), "sessionSnapshot.deposit"),
            cumulative=accepted,
            accepted=accepted,
            status="open",
        )
        self._snapshot(request, channel)
        self._validate(channel, request)
        if not _verify_voucher(
            signed.get("signature"),
            channel.channel_id,
            cumulative,
            channel.escrow,
            channel.chain_id,
            channel.descriptor.authorized_signer,
        ):
            raise ValueError("session snapshot highest voucher signature is invalid")
        settled, deposit, closing = await self._channel_state(channel)
        if deposit == 0 or closing != 0 or settled > deposit:
            raise ValueError("session channel is not reusable on chain")
        _limit(deposit, self.max_deposit, "channel deposit")
        if channel.cumulative > deposit:
            raise ValueError("session snapshot exceeds on-chain channel deposit")
        channel.deposit = deposit
        channel.cumulative = max(channel.cumulative, settled)
        await self._save(request, channel)
        return channel

    async def _channel_state(
        self, channel: _Channel, block: str | dict[str, object] = "latest"
    ) -> tuple[int, int, int]:
        from eth_abi.abi import decode

        data = _call(
            "getChannelState(bytes32)", ["bytes32"], [bytes.fromhex(channel.channel_id[2:])]
        )
        result = await _rpc_call(
            self.rpc_url,
            "eth_call",
            [{"to": channel.escrow, "data": "0x" + data.hex()}, block],
        )
        if not isinstance(result, str) or not result.startswith("0x"):
            raise ValueError("invalid getChannelState RPC response")
        try:
            values = decode(["uint96", "uint96", "uint32"], bytes.fromhex(result[2:]))
        except Exception as error:
            raise ValueError("invalid getChannelState RPC response") from error
        return cast("tuple[int, int, int]", tuple(map(int, values)))

    async def _reconcile_deposit(self, channel: _Channel, advertised: int) -> None:
        if advertised == channel.deposit:
            return
        previous = channel.deposit
        settled, deposit, closing = await self._channel_state(channel)
        if closing != 0 or settled > channel.cumulative or deposit < channel.deposit:
            raise ValueError("Tempo session deposit cannot be safely reconciled")
        _limit(deposit, self.max_deposit, "channel deposit")
        channel.deposit = deposit
        if channel.pending_top_up is not None and deposit >= previous + channel.pending_top_up:
            channel.pending_transaction = None
            channel.pending_top_up = None

    async def _need_voucher_async(
        self, exchange: AsyncHttpResponseContext, request: _Request, event: dict[str, Any]
    ) -> None:
        channel, target = await self._prepare_voucher(request, event)
        if target > channel.deposit:
            additional = target - channel.deposit
            credential = await exchange.create_credential(
                {
                    "action": "topUp",
                    "channelId": channel.channel_id,
                    "additionalDeposit": str(additional),
                }
            )
            await self._post_async(exchange, request, credential)
        credential = await exchange.create_credential(
            {
                "action": "voucher",
                "channelId": channel.channel_id,
                "cumulativeAmount": str(target),
            }
        )
        await self._post_async(exchange, request, credential)

    def _need_voucher_sync(
        self, exchange: SyncHttpResponseContext, request: _Request, event: dict[str, Any]
    ) -> None:
        channel, target = exchange.run_sync(self._prepare_voucher(request, event))
        if target > channel.deposit:
            additional = target - channel.deposit
            credential = exchange.create_credential(
                {
                    "action": "topUp",
                    "channelId": channel.channel_id,
                    "additionalDeposit": str(additional),
                }
            )
            self._post_sync(exchange, request, credential)
        credential = exchange.create_credential(
            {
                "action": "voucher",
                "channelId": channel.channel_id,
                "cumulativeAmount": str(target),
            }
        )
        self._post_sync(exchange, request, credential)

    async def _prepare_voucher(
        self, request: _Request, event: dict[str, Any]
    ) -> tuple[_Channel, int]:
        channel = await self._require(request)
        if channel.pending_top_up is not None:
            await self._replace_expired_pending(request, channel)
        await self._reconcile_deposit(channel, _amount(event.get("deposit"), "deposit"))
        self._validate(channel, request)
        await self._save(request, channel)
        return channel, self._voucher_target(request, channel, event)

    def _voucher_target(self, request: _Request, channel: _Channel, event: dict[str, Any]) -> int:
        if event.get("channelId") != channel.channel_id:
            raise ValueError("need-voucher event references the wrong channel")
        required = _amount(event.get("requiredCumulative"), "requiredCumulative")
        accepted = _amount(event.get("acceptedCumulative"), "acceptedCumulative")
        if accepted > channel.cumulative or accepted > required:
            raise ValueError("need-voucher event exceeds locally signed state")
        accepted = max(accepted, channel.accepted)
        target = max(required, channel.cumulative, accepted + request.min_voucher_delta)
        _limit(target, self.max_deposit, "voucher")
        return target

    async def _post_async(
        self, exchange: AsyncHttpResponseContext, request: _Request, credential: Credential
    ) -> None:
        async def post(value: Credential) -> httpx.Response:
            response = await exchange.send(
                httpx.Request(
                    "POST",
                    exchange.request.url,
                    headers={"Authorization": value.to_authorization()},
                )
            )
            try:
                await response.aread()
            except BaseException:
                await response.aclose()
                raise
            return response

        active_challenge = exchange.challenge
        response = await post(credential)
        replacement = self._replacement_challenge(response)
        if replacement is not None:
            await response.aclose()
            active_challenge = replacement
            credential = await exchange.create_credential(credential.payload, replacement)
            response = await post(credential)
        try:
            if not response.is_success:
                raise TransactionError(
                    f"Tempo session management POST failed with status {response.status_code}"
                )
            await self._accept_response(request, response, active_challenge, credential.payload)
        finally:
            await response.aclose()

    def _post_sync(
        self, exchange: SyncHttpResponseContext, request: _Request, credential: Credential
    ) -> None:
        def post(value: Credential) -> httpx.Response:
            response = exchange.send(
                httpx.Request(
                    "POST",
                    exchange.request.url,
                    headers={"Authorization": value.to_authorization()},
                )
            )
            try:
                response.read()
            except BaseException:
                response.close()
                raise
            return response

        active_challenge = exchange.challenge
        response = post(credential)
        replacement = self._replacement_challenge(response)
        if replacement is not None:
            response.close()
            active_challenge = replacement
            credential = exchange.create_credential(credential.payload, replacement)
            response = post(credential)
        try:
            if not response.is_success:
                raise TransactionError(
                    f"Tempo session management POST failed with status {response.status_code}"
                )
            exchange.run_sync(
                self._accept_response(request, response, active_challenge, credential.payload)
            )
        finally:
            response.close()

    def _replacement_challenge(self, response: httpx.Response) -> Challenge | None:
        if response.status_code != 402:
            return None
        for header in response.headers.get_list("www-authenticate"):
            for auth_field in _auth_challenges(header):
                if auth_field.partition(" ")[0].lower() != "payment":
                    continue
                try:
                    challenge = Challenge.from_www_authenticate(auth_field)
                except ParseError:
                    continue
                if self.can_handle_challenge(challenge):
                    return challenge
        return None

    async def _accept_response(
        self,
        request: _Request,
        response: httpx.Response,
        challenge: Challenge,
        payload: dict[str, Any],
    ) -> None:
        channel = await self._require(request)
        self._apply_receipt_header(response, challenge, channel)
        self._apply_accepted_response(channel, payload)
        await self._save(request, channel)

    async def _record_receipt(self, request: _Request, value: object, challenge: Challenge) -> None:
        channel = await self._require(request)
        self._apply_receipt(value, challenge, channel)
        await self._save(request, channel)

    def _apply_accepted_response(self, channel: _Channel, payload: dict[str, Any]) -> None:
        action = payload.get("action")
        if action == "topUp":
            additional = _amount(payload.get("additionalDeposit"), "additionalDeposit")
            if channel.pending_top_up == additional and channel.pending_transaction == payload.get(
                "transaction"
            ):
                channel.deposit += additional
                channel.pending_transaction = None
                channel.pending_top_up = None
        elif action in {"open", "voucher"}:
            channel.status = "open"
            channel.accepted = max(
                channel.accepted, _amount(payload.get("cumulativeAmount"), "cumulativeAmount")
            )
            if action == "open" and channel.pending_transaction == payload.get("transaction"):
                channel.pending_transaction = None

    def _apply_receipt_header(
        self, response: httpx.Response, challenge: Challenge, channel: _Channel
    ) -> None:
        header = response.headers.get("payment-receipt")
        if header is None:
            return
        receipt = Receipt.from_payment_receipt(header)
        value = {
            "method": receipt.method,
            "status": receipt.status,
            "timestamp": receipt.timestamp.isoformat(),
            "reference": receipt.reference,
            **(receipt.extensions or {}),
        }
        self._apply_receipt(value, challenge, channel)

    def _apply_receipt(self, value: object, challenge: Challenge, channel: _Channel) -> None:
        self._validate_receipt(value, challenge, channel)
        assert isinstance(value, dict)
        channel.accepted = max(
            channel.accepted, _amount(value["acceptedCumulative"], "acceptedCumulative")
        )
        channel.status = "open"

    def _validate_receipt(self, value: object, challenge: Challenge, channel: _Channel) -> None:
        if not isinstance(value, dict):
            raise ValueError("invalid Tempo session receipt")
        if (
            value.get("method") != "tempo"
            or value.get("intent") != "session"
            or value.get("status") != "success"
        ):
            raise ValueError("invalid Tempo session receipt")
        if (
            _bytes32(value.get("channelId"), "receipt.channelId") != channel.channel_id
            or value.get("reference") != channel.channel_id
            or value.get("challengeId") != challenge.id
        ):
            raise ValueError("Tempo session receipt references the wrong payment")
        timestamp = value.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("invalid Tempo session receipt timestamp")
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("invalid Tempo session receipt timestamp") from error
        accepted = _amount(value.get("acceptedCumulative"), "acceptedCumulative")
        spent = _amount(value.get("spent"), "spent")
        if spent > accepted or accepted > channel.cumulative:
            raise ValueError("Tempo session receipt exceeds locally authorized spend")
        units = value.get("units")
        if units is not None and (
            not isinstance(units, (int, float))
            or isinstance(units, bool)
            or not math.isfinite(units)
            or units < 0
        ):
            raise ValueError("invalid Tempo session receipt units")
        if value.get("txHash") is not None:
            _bytes32(value["txHash"], "receipt.txHash")

    async def _load(self, request: _Request) -> _Channel | None:
        value = await self.channel_store.get("tempo:session:" + request.scope)
        if value is None:
            return None
        channel = _Channel.load(value)
        self._validate(channel, request)
        return channel

    async def _require(self, request: _Request) -> _Channel:
        channel = await self._load(request)
        if channel is None:
            raise ValueError("no local Tempo session channel available")
        return channel

    async def _save(self, request: _Request, channel: _Channel) -> None:
        await self.channel_store.put("tempo:session:" + request.scope, channel.dump())

    def _validate(self, channel: _Channel, request: _Request) -> None:
        descriptor = channel.descriptor
        if (
            channel.chain_id != request.chain_id
            or channel.escrow != request.escrow
            or descriptor.payer != self.account.address.lower()
            or descriptor.authorized_signer != self.account.address.lower()
            or descriptor.payee != request.payee
            or descriptor.operator != request.operator
            or descriptor.token != request.token
        ):
            raise ValueError("stored Tempo session channel is outside this payment scope")
        if channel.channel_id != _channel_id(descriptor, channel.escrow, channel.chain_id):
            raise ValueError("stored Tempo session channelId does not match its descriptor")
        _limit(channel.deposit, self.max_deposit, "stored channel deposit")
        if channel.deposit == 0:
            raise ValueError("stored Tempo session deposit must be greater than zero")
        if not 0 <= channel.accepted <= channel.cumulative <= channel.deposit:
            raise ValueError("stored Tempo session amounts are inconsistent")
        if channel.status == "pending":
            if channel.pending_transaction is None or channel.pending_top_up is not None:
                raise ValueError("stored pending Tempo session open is incomplete")
        elif channel.pending_top_up is None:
            if channel.pending_transaction is not None:
                raise ValueError("stored Tempo session pending state is inconsistent")
        elif (
            channel.pending_transaction is None
            or channel.pending_top_up == 0
            or channel.deposit + channel.pending_top_up > self.max_deposit
        ):
            raise ValueError("stored pending Tempo session top-up is inconsistent")

    def _snapshot(self, request: _Request, channel: _Channel) -> dict[str, Any]:
        snapshot = request.snapshot
        assert snapshot is not None
        if (
            _bytes32(snapshot.get("channelId"), "sessionSnapshot.channelId") != channel.channel_id
            or _address(snapshot.get("escrow"), "sessionSnapshot.escrow") != request.escrow
            or _chain_id(snapshot.get("chainId"), "sessionSnapshot.chainId") != request.chain_id
            or _Descriptor.parse(snapshot.get("descriptor")) != channel.descriptor
        ):
            raise ValueError("session snapshot does not match the active channel")
        settled = _amount(snapshot.get("settled"), "settled")
        spent = _amount(snapshot.get("spent"), "spent")
        accepted = _amount(snapshot.get("acceptedCumulative"), "acceptedCumulative")
        required = _amount(snapshot.get("requiredCumulative"), "requiredCumulative")
        _amount(snapshot.get("deposit"), "deposit")
        closing = snapshot.get("closeRequestedAt")
        if closing is not None and _amount(closing, "closeRequestedAt") != 0:
            raise ValueError("session snapshot channel is closing")
        if settled > accepted or spent > accepted or accepted > required:
            raise ValueError("session snapshot amounts are inconsistent")
        return snapshot

    def _resolve(self, challenge: Challenge) -> _Request:
        if challenge.method != "tempo" or challenge.intent != "session":
            raise ValueError("TempoSessionMethod only handles tempo/session challenges")
        raw = challenge.request
        amount = _amount(raw.get("amount"), "amount")
        token = _address(raw.get("currency"), "currency")
        payee = _address(raw.get("recipient"), "recipient")
        details = raw.get("methodDetails")
        if not isinstance(details, dict) or details.get("sessionProtocol") != "v2":
            raise ValueError("TempoSessionMethod requires methodDetails.sessionProtocol v2")
        chain_id = _chain_id(details.get("chainId"), "methodDetails.chainId")
        if chain_id != self.chain_id:
            raise ValueError(
                f"Challenge requests chain ID {chain_id}, "
                f"but client is restricted to {self.chain_id}"
            )
        escrow = _address(details.get("escrowContract"), "methodDetails.escrowContract")
        if escrow != self.escrow:
            raise ValueError("session challenge escrow is outside local policy")
        operator = _address(details.get("operator", ZERO_ADDRESS), "methodDetails.operator")
        fee_payer = details.get("feePayer", False)
        if not isinstance(fee_payer, bool):
            raise ValueError("methodDetails.feePayer must be a boolean")
        suggested = raw.get("suggestedDeposit")
        min_delta = details.get("minVoucherDelta")
        snapshot = details.get("sessionSnapshot")
        if snapshot is not None and not isinstance(snapshot, dict):
            raise ValueError("methodDetails.sessionSnapshot must be an object")
        payer = self.account.address.lower()
        scope = ":".join((str(chain_id), escrow, payer, payee, operator, token, payer))
        return _Request(
            amount=amount,
            payee=payee,
            token=token,
            operator=operator,
            escrow=escrow,
            chain_id=chain_id,
            fee_payer=fee_payer,
            suggested_deposit=(
                _amount(suggested, "suggestedDeposit") if suggested is not None else None
            ),
            min_voucher_delta=(
                _amount(min_delta, "minVoucherDelta") if min_delta is not None else 0
            ),
            snapshot=cast("dict[str, Any] | None", snapshot),
            scope=scope,
        )

    def _lock(self, scope: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(scope, threading.Lock())

    @asynccontextmanager
    async def _locked(self, scope: str):
        key = (id(self), scope)
        if key in _HELD.get():
            yield
            return
        lock = self._lock(scope)
        acquire = asyncio.create_task(asyncio.to_thread(lock.acquire))
        try:
            await asyncio.shield(acquire)
        except BaseException:
            await asyncio.shield(acquire)
            lock.release()
            raise
        token = _HELD.set(_HELD.get() | {key})
        try:
            yield
        finally:
            _HELD.reset(token)
            lock.release()

    @contextmanager
    def _locked_sync(self, scope: str):
        key = (id(self), scope)
        if key in _HELD.get():
            yield
            return
        lock = self._lock(scope)
        lock.acquire()
        token = _HELD.set(_HELD.get() | {key})
        try:
            yield
        finally:
            _HELD.reset(token)
            lock.release()


def tempo_session(
    *,
    account: TempoAccount,
    max_deposit: int,
    rpc_url: str | None = None,
    chain_id: int = CHAIN_ID,
    escrow: str = TIP20_CHANNEL_ESCROW,
    channel_store: Store | None = None,
) -> TempoSessionMethod:
    """Create a private-key TIP-1034 session method.

    ``max_deposit`` is a required cap in raw token base units. The generic
    ``mpp.Store`` defaults to process-local memory; multi-process callers need
    external locking or atomic channel updates.
    """
    if not isinstance(max_deposit, int) or isinstance(max_deposit, bool):
        raise TypeError("max_deposit must be an integer in raw token base units")
    _limit(max_deposit, MAX_UINT96, "max_deposit")
    if max_deposit == 0:
        raise ValueError("max_deposit must be greater than zero")
    from pytempo import TempoTransaction

    if not hasattr(TempoTransaction, "encode_for_signing"):
        raise RuntimeError("Tempo sessions require pytempo with encode_for_signing()")
    resolved_chain_id = _chain_id(chain_id, "chain_id")
    return TempoSessionMethod(
        account=account,
        max_deposit=max_deposit,
        rpc_url=rpc_url if rpc_url is not None else rpc_url_for_chain(resolved_chain_id),
        chain_id=resolved_chain_id,
        escrow=_address(escrow, "escrow"),
        channel_store=channel_store if channel_store is not None else MemoryStore(),
    )


def _descriptor_tuple(descriptor: _Descriptor) -> tuple[object, ...]:
    return (
        descriptor.payer,
        descriptor.payee,
        descriptor.operator,
        descriptor.token,
        bytes.fromhex(descriptor.salt[2:]),
        descriptor.authorized_signer,
        bytes.fromhex(descriptor.expiring_nonce_hash[2:]),
    )


def _random_valid_after() -> int:
    """Distinguish otherwise-identical sponsored transactions with a past timestamp."""
    latest = int(time.time()) - 60
    return 1 + int.from_bytes(os.urandom(8)) % latest if latest > 0 else 0


def _channel_id(descriptor: _Descriptor, escrow: str, chain_id: int) -> str:
    from eth_abi.abi import encode

    encoded = encode(
        [
            "address",
            "address",
            "address",
            "address",
            "bytes32",
            "address",
            "bytes32",
            "address",
            "uint256",
        ],
        [*_descriptor_tuple(descriptor), escrow, chain_id],
    )
    return "0x" + _keccak(encoded).hex()


def _voucher_signature(
    account: TempoAccount, channel_id: str, cumulative: int, escrow: str, chain_id: int
) -> str:
    return "0x" + account.sign_hash(_voucher_digest(channel_id, cumulative, escrow, chain_id)).hex()


def _voucher_digest(channel_id: str, cumulative: int, escrow: str, chain_id: int) -> bytes:
    from eth_abi.abi import encode

    _uint96(cumulative, "cumulativeAmount")
    domain = _keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                _keccak(
                    b"EIP712Domain(string name,string version,uint256 chainId,"
                    b"address verifyingContract)"
                ),
                _keccak(b"TIP20 Channel Reserve"),
                _keccak(b"1"),
                chain_id,
                escrow,
            ],
        )
    )
    voucher = _keccak(
        encode(
            ["bytes32", "bytes32", "uint96"],
            [
                _keccak(b"Voucher(bytes32 channelId,uint96 cumulativeAmount)"),
                bytes.fromhex(channel_id[2:]),
                cumulative,
            ],
        )
    )
    return _keccak(b"\x19\x01" + domain + voucher)


def _verify_voucher(
    signature: object,
    channel_id: str,
    cumulative: int,
    escrow: str,
    chain_id: int,
    signer: str,
) -> bool:
    if not isinstance(signature, str) or re.fullmatch(r"0x[0-9a-fA-F]{130}", signature) is None:
        return False
    raw = bytes.fromhex(signature[2:])
    recovery = raw[64] - 27 if raw[64] in {27, 28} else raw[64]
    if recovery not in {0, 1}:
        return False
    try:
        from eth_keys.datatypes import Signature

        recovered = Signature(
            vrs=(
                recovery,
                int.from_bytes(raw[:32], "big"),
                int.from_bytes(raw[32:64], "big"),
            )
        ).recover_public_key_from_msg_hash(
            _voucher_digest(channel_id, cumulative, escrow, chain_id)
        )
    except Exception:
        return False
    return recovered.to_checksum_address().lower() == signer.lower()


def _call(signature: str, types: Sequence[str], values: Sequence[object]) -> bytes:
    from eth_abi.abi import encode

    return _keccak(signature.encode())[:4] + encode(types, values)


def _keccak(value: bytes) -> bytes:
    from eth_hash.auto import keccak

    return cast("bytes", keccak(value))


def _address(value: object, name: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a 20-byte hex address")
    return value.lower()


def _bytes32(value: object, name: str) -> str:
    if not isinstance(value, str) or _BYTES32_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a 32-byte hex value")
    return value.lower()


def _transaction_hex(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.startswith("0x") or len(value) == 2:
        raise ValueError("pending_transaction must be hex encoded")
    try:
        bytes.fromhex(value[2:])
    except ValueError as error:
        raise ValueError("pending_transaction must be hex encoded") from error
    return value.lower()


def _transaction_valid_before(transaction: str) -> int | None:
    import rlp

    raw = bytes.fromhex(transaction[2:])
    try:
        fields = rlp.decode(raw[1:])
        valid_before = fields[8]
    except (IndexError, rlp.DecodingError) as error:
        raise ValueError("invalid stored Tempo session transaction") from error
    if not isinstance(fields, list) or raw[0] not in {0x76, 0x78}:
        raise ValueError("invalid stored Tempo session transaction")
    if not isinstance(valid_before, bytes):
        raise ValueError("invalid stored Tempo session transaction")
    return int.from_bytes(valid_before) if valid_before else None


def _amount(value: object, name: str) -> int:
    if not isinstance(value, str) or _AMOUNT_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a canonical decimal string")
    return _uint96(int(value), name)


def _uint96(value: int, name: str) -> int:
    if not 0 <= value <= MAX_UINT96:
        raise ValueError(f"{name} is outside uint96 bounds")
    return value


def _chain_id(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _rpc_quantity(value: object, name: str) -> int:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value) is None
    ):
        raise ValueError(f"invalid {name} RPC response")
    return int(value, 16)


def _limit(value: int, limit: int, name: str) -> None:
    _uint96(value, name)
    if value > limit:
        raise ValueError(f"{name} exceeds max_deposit")


def _is_sse(response: httpx.Response) -> bool:
    return response.headers.get("content-type", "").lower().startswith("text/event-stream")
