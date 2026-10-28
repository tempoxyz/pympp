"""TIP-1034 chain layer against a fake JSON-RPC node (mppx precompile/Chain.test.ts, unit cases).

Builds real client-signed transactions offline, then drives the server-side validation,
broadcast, readback and server contract calls through httpx.MockTransport.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

import httpx
import pytest
from eth_abi.abi import decode, encode
from pytempo import Call, TempoTransaction  # pyright: ignore[reportMissingTypeStubs]

from mpp.errors import BadRequestError, VerificationError, VerificationFailedError
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo.session import abi, chain
from mpp.methods.tempo.session.channel import compute_channel_id, expiring_nonce_hash
from mpp.methods.tempo.session.protocol import ESCROW_ADDRESS, ZERO_ADDRESS, ChannelDescriptor

CHAIN_ID = 1337
RPC = "http://rpc.test"
CURRENCY = "0x20C0000000000000000000000000000000000000"
OTHER_TOKEN = "0x20C0000000000000000000000000000000000001"
GAS_PRICE = 20_000_000_000
PAYER = TempoAccount.from_key("0x" + "11" * 32)
PAYEE = TempoAccount.from_key("0x" + "22" * 32)
SPONSOR = TempoAccount.from_key("0x" + "33" * 32)
ACCESS_KEY = TempoAccount.from_key("0x" + "44" * 32)
DEPOSIT = 1_000_000
BALANCE_OF = "0x70a08231"
DESCRIPTOR = ChannelDescriptor(
    payer=PAYER.address,
    payee=PAYEE.address,
    operator=ZERO_ADDRESS,
    token=CURRENCY,
    salt="0x" + "01" * 32,
    authorized_signer=PAYER.address,
    expiring_nonce_hash="0x" + "ab" * 32,
)
SIGNATURE = "0x" + "aa" * 64 + "1b"


class RpcError(Exception):
    """Raised by a fake handler to answer with a JSON-RPC error."""


def fail(message: str) -> Callable[[list[Any]], Any]:
    def handler(params: list[Any]) -> Any:
        raise RpcError(message)

    return handler


@dataclass
class FakeRpc:
    """A scripted Tempo node: answers JSON-RPC requests and records them."""

    chain_id: int = CHAIN_ID
    states: dict[str, tuple[int, int, int]] = field(default_factory=dict)
    default_state: tuple[int, int, int] = (0, DEPOSIT, 0)
    logs: list[dict[str, Any]] = field(default_factory=list)
    receipt_status: str = "0x1"
    pending_receipts: int = 0
    balances: dict[str, int] = field(default_factory=dict)
    overrides: dict[str, Callable[[list[Any]], Any]] = field(default_factory=dict)
    requests: list[tuple[str, list[Any]]] = field(default_factory=list)
    sent: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def methods(self, name: str) -> list[list[Any]]:
        return [params for method, params in self.requests if method == name]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method, params = body["method"], body["params"]
        self.requests.append((method, params))
        handlers: dict[str, Callable[[list[Any]], Any]] = {
            "eth_chainId": lambda p: hex(self.chain_id),
            "eth_gasPrice": lambda p: hex(GAS_PRICE),
            "eth_estimateGas": lambda p: hex(100_000),
            "eth_sendRawTransaction": self._send,
            "eth_getTransactionReceipt": self._receipt,
            "eth_call": self._call,
        }
        try:
            result = (self.overrides.get(method) or handlers[method])(params)
        except RpcError as error:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": str(error)})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    def _send(self, params: list[Any]) -> str:
        self.sent.append(params[0])
        return "0x" + f"{len(self.sent):064x}"

    def _receipt(self, params: list[Any]) -> dict[str, Any] | None:
        if self.pending_receipts > 0:
            self.pending_receipts -= 1
            return None
        return {
            "status": self.receipt_status,
            "blockNumber": "0x10",
            "transactionHash": params[0],
            "logs": self.logs,
        }

    def _state(self, channel_id: str) -> tuple[int, int, int]:
        return self.states.get(channel_id, self.default_state)

    def _call(self, params: list[Any]) -> str:
        request = params[0]
        if "calls" in request:  # a simulation
            return "0x"
        data: str = request["data"]
        selector, args = bytes.fromhex(data[2:10]), bytes.fromhex(data[10:])
        if data.startswith(BALANCE_OF):
            (owner,) = decode(["address"], args)
            balance = self.balances.get(f"{request['to']}:{owner}".lower(), 0)
            if balance < 0:
                raise RpcError("balance read failed")
            return "0x" + encode(["uint256"], [balance]).hex()
        if selector == abi.SELECTORS["getChannel"]:
            (raw,) = decode([abi.DESCRIPTOR_TYPE], args)
            descriptor = abi._descriptor_from_tuple(raw)
            state = self._state(compute_channel_id(descriptor, chain_id=self.chain_id))
            result = encode([f"({abi.DESCRIPTOR_TYPE},{abi.STATE_TYPE})"], [(raw, state)])
            return "0x" + result.hex()
        if selector == abi.SELECTORS["getChannelState"]:
            (channel_id,) = decode(["bytes32"], args)
            return "0x" + encode([abi.STATE_TYPE], [self._state("0x" + channel_id.hex())]).hex()
        if selector == abi.SELECTORS["getChannelStatesBatch"]:
            (ids,) = decode(["bytes32[]"], args)
            states = [self._state("0x" + i.hex()) for i in ids]
            return "0x" + encode([f"{abi.STATE_TYPE}[]"], [states]).hex()
        assert selector == abi.SELECTORS["computeChannelId"]
        raw = decode(
            ["address", "address", "address", "address", "bytes32", "address", "bytes32"], args
        )
        channel_id = compute_channel_id(abi._descriptor_from_tuple(raw), chain_id=self.chain_id)
        return "0x" + bytes.fromhex(channel_id[2:]).hex()


def topic(value: str) -> str:
    return "0x" + value.removeprefix("0x").lower().rjust(64, "0")


def event_log(
    name: str,
    descriptor: ChannelDescriptor,
    channel_id: str,
    types: list[str],
    values: list[Any],
    *,
    address: str = ESCROW_ADDRESS,
) -> dict[str, Any]:
    coerced = [
        bytes.fromhex(v[2:]) if t == "bytes32" else v for t, v in zip(types, values, strict=True)
    ]
    return {
        "address": address,
        "topics": [
            abi.EVENT_TOPICS[name],
            channel_id,
            topic(descriptor.payer),
            topic(descriptor.payee),
        ],
        "data": "0x" + encode(types, coerced).hex(),
    }


def opened_log(
    descriptor: ChannelDescriptor,
    channel_id: str,
    *,
    deposit: int = DEPOSIT,
    address: str = ESCROW_ADDRESS,
) -> dict[str, Any]:
    return event_log(
        "ChannelOpened",
        descriptor,
        channel_id,
        ["address", "address", "address", "bytes32", "bytes32", "uint96"],
        [
            descriptor.operator,
            descriptor.token,
            descriptor.authorized_signer,
            descriptor.salt,
            descriptor.expiring_nonce_hash,
            deposit,
        ],
        address=address,
    )


def top_up_log(
    descriptor: ChannelDescriptor, channel_id: str, additional: int, new_deposit: int
) -> dict[str, Any]:
    return event_log(
        "TopUp", descriptor, channel_id, ["uint96", "uint96"], [additional, new_deposit]
    )


def raw_tx(
    calls: list[tuple[str, int, str]],
    *,
    signed: bool = True,
    fee_payer: bool = False,
    valid_before: int | None = None,
) -> str:
    """A hand-built expiring-nonce Tempo transaction, for shapes the builders never make."""
    tx = TempoTransaction.create(
        chain_id=CHAIN_ID,
        gas_limit=200_000,
        max_fee_per_gas=GAS_PRICE,
        max_priority_fee_per_gas=GAS_PRICE // 10,
        nonce=0,
        nonce_key=chain.EXPIRING_NONCE_KEY,
        valid_before=valid_before or int(time.time()) + 60,
        fee_token=CURRENCY,
        awaiting_fee_payer=fee_payer,
        calls=tuple(Call.create(to=to, value=value, data=data) for to, value, data in calls),
    )
    if not signed:
        return "0x" + tx.encode().hex()
    return chain._serialize_client_transaction(tx.sign(PAYER.private_key), fee_payer)


def rlp_fields(raw: str) -> list[Any]:
    from mpp.methods.tempo import _rlp as rlp

    fields = rlp.decode(bytes.fromhex(raw[4:]))
    assert isinstance(fields, list)
    return fields


@pytest.fixture
def rpc() -> FakeRpc:
    return FakeRpc()


async def build_open(
    rpc: FakeRpc, *, fee_payer: bool = False, **kwargs: Any
) -> tuple[str, ChannelDescriptor, str]:
    return await chain.build_open_transaction(
        PAYER,
        rpc_url=RPC,
        payee=PAYEE.address,
        token=CURRENCY,
        deposit=DEPOSIT,
        fee_payer=fee_payer,
        client=rpc.client,
        **kwargs,
    )


def open_kwargs(raw: str, descriptor: ChannelDescriptor, channel_id: str) -> dict[str, Any]:
    return {
        "serialized_transaction": raw,
        "chain_id": CHAIN_ID,
        "escrow_contract": ESCROW_ADDRESS,
        "expected_authorized_signer": descriptor.authorized_signer,
        "expected_channel_id": channel_id,
        "expected_currency": descriptor.token,
        "expected_expiring_nonce_hash": descriptor.expiring_nonce_hash,
        "expected_operator": descriptor.operator,
        "expected_payee": descriptor.payee,
        "expected_payer": descriptor.payer,
    }


# ──────────────────────────────────────────────────────────────────
# Reads
# ──────────────────────────────────────────────────────────────────


class TestReads:
    async def test_reads_channel_and_states_at_a_block(self, rpc: FakeRpc) -> None:
        channel_id = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
        rpc.states[channel_id] = (5, 50, 7)

        channel = await chain.get_channel(RPC, DESCRIPTOR, block=16, client=rpc.client)
        assert channel.descriptor == DESCRIPTOR
        assert channel.state == chain.ChannelState(settled=5, deposit=50, close_requested_at=7)
        state = await chain.get_channel_state(RPC, channel_id, block="safe", client=rpc.client)
        assert state == channel.state
        batch = await chain.get_channel_states_batch(
            RPC, [channel_id, "0x" + "00" * 32], client=rpc.client
        )
        assert batch == [channel.state, chain.ChannelState(0, DEPOSIT, 0)]
        on_chain_id = await chain.compute_channel_id_on_chain(RPC, DESCRIPTOR, client=rpc.client)
        assert on_chain_id == channel_id
        assert [p[1] for p in rpc.methods("eth_call")] == ["0x10", "safe", "latest", "latest"]

    async def test_rejects_state_beyond_uint96(self, rpc: FakeRpc) -> None:
        rpc.overrides["eth_call"] = lambda params: (
            "0x" + encode(["uint256", "uint256", "uint256"], [1 << 96, 0, 0]).hex()
        )
        with pytest.raises(Exception, match="Padding"):
            await chain.get_channel_state(RPC, "0x" + "00" * 32, client=rpc.client)

    async def test_eth_call_without_data_and_rpc_errors_raise(self, rpc: FakeRpc) -> None:
        rpc.overrides["eth_call"] = lambda params: None
        with pytest.raises(RuntimeError, match="no data"):
            await chain.get_channel_state(RPC, "0x" + "00" * 32, client=rpc.client)
        rpc.overrides["eth_call"] = fail("reverted")
        with pytest.raises(RuntimeError, match="RPC error"):
            await chain.get_channel_state(RPC, "0x" + "00" * 32, client=rpc.client)

    async def test_readback_retries_until_the_replica_catches_up(self) -> None:
        attempts: list[int] = []

        async def read() -> int:
            attempts.append(1)
            if len(attempts) < 3:
                raise RuntimeError("header not found")
            return 42

        assert await chain.readback_with_retry(read, delay=0) == 42
        assert len(attempts) == 3

    async def test_readback_gives_up(self) -> None:
        attempts: list[int] = []

        async def read() -> int:
            attempts.append(1)
            raise ValueError(f"attempt {len(attempts)}")

        with pytest.raises(ValueError, match="attempt 3"):
            await chain.readback_with_retry(read, retries=2, delay=0)
        attempts.clear()
        with pytest.raises(ValueError, match="attempt 1"):
            await chain.readback_with_retry(read, delay=0, should_retry=lambda e: False)


# ──────────────────────────────────────────────────────────────────
# Broadcast, receipts and events
# ──────────────────────────────────────────────────────────────────


class TestReceipts:
    async def test_send_raw_transaction_requires_a_hash(self, rpc: FakeRpc) -> None:
        rpc.overrides["eth_sendRawTransaction"] = lambda params: None
        with pytest.raises(RuntimeError, match="no hash"):
            await chain.send_raw_transaction(RPC, "0x76", client=rpc.client)

    async def test_waits_for_a_receipt(self, rpc: FakeRpc, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(chain, "RECEIPT_POLL_INTERVAL", 0)
        rpc.pending_receipts = 2
        receipt = await chain.wait_for_successful_receipt(RPC, "0xabc", client=rpc.client)
        assert receipt["transactionHash"] == "0xabc"
        assert len(rpc.methods("eth_getTransactionReceipt")) == 3

    async def test_reverted_receipt_and_timeout(self, rpc: FakeRpc) -> None:
        rpc.receipt_status = "0x0"
        with pytest.raises(VerificationFailedError, match="reverted"):
            await chain.wait_for_successful_receipt(RPC, "0xabc", client=rpc.client)
        rpc.pending_receipts = 10
        with pytest.raises(TimeoutError, match="0xdef"):
            await chain.wait_for_successful_receipt(RPC, "0xdef", client=rpc.client, timeout=0)

    def test_get_channel_event_skips_foreign_and_malformed_logs(self) -> None:
        channel_id = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
        good = top_up_log(DESCRIPTOR, channel_id, 5, 10)
        logs: list[Any] = [
            "not a log",
            {"address": ESCROW_ADDRESS, "topics": []},
            {**good, "data": "0x1234"},  # undecodable
            {**good, "topics": good["topics"][:2]},  # wrong arity
            top_up_log(DESCRIPTOR, "0x" + "99" * 32, 5, 10),  # another channel
            opened_log(DESCRIPTOR, channel_id),
            good,
        ]
        args = chain.get_channel_event({"logs": logs}, "TopUp", "0x" + channel_id[2:].upper())
        assert args["newDeposit"] == 10
        with pytest.raises(VerificationFailedError, match="expected one ChannelClosed"):
            chain.get_channel_event({"logs": logs}, "ChannelClosed", channel_id)
        with pytest.raises(VerificationFailedError):
            chain.get_channel_event({"logs": None}, "TopUp", channel_id)


class TestReceiptChecks:
    def _opened(self, **overrides: Any) -> None:
        channel_id = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
        kwargs: dict[str, Any] = {
            "chain_id": CHAIN_ID,
            "descriptor": DESCRIPTOR,
            "emitted_channel_id": channel_id,
            "emitted_deposit": 10,
            "emitted_expiring_nonce_hash": DESCRIPTOR.expiring_nonce_hash,
            "escrow": ESCROW_ADDRESS,
            "expected_channel_id": channel_id,
            "open_deposit": 10,
        }
        chain.validate_channel_opened_receipt(**{**kwargs, **overrides})

    def test_channel_opened_must_match_credential_and_descriptor(self) -> None:
        self._opened()
        with pytest.raises(VerificationFailedError, match="channelId does not match credential"):
            self._opened(expected_channel_id="0x" + "00" * 32)
        with pytest.raises(VerificationFailedError, match="expiringNonceHash"):
            self._opened(emitted_expiring_nonce_hash="0x" + "00" * 32)
        other = replace(DESCRIPTOR, salt="0x" + "02" * 32)
        with pytest.raises(VerificationFailedError, match="descriptor does not match"):
            self._opened(descriptor=other)

    def test_top_up_receipt_and_readback(self) -> None:
        chain.validate_top_up_receipt(emitted_channel_id="0xAB", expected_channel_id="0xab")
        with pytest.raises(VerificationFailedError, match="TopUp channelId"):
            chain.validate_top_up_receipt(emitted_channel_id="0xab", expected_channel_id="0xcd")
        chain.validate_top_up_readback_state(new_deposit=5, state=chain.ChannelState(0, 5, 0))
        with pytest.raises(VerificationFailedError, match="topUp receipt"):
            chain.validate_top_up_readback_state(new_deposit=5, state=chain.ChannelState(0, 4, 0))


# ──────────────────────────────────────────────────────────────────
# Calldata
# ──────────────────────────────────────────────────────────────────


def open_data(**overrides: Any) -> str:
    fields: dict[str, Any] = {
        "payee": PAYEE.address,
        "operator": ZERO_ADDRESS,
        "token": CURRENCY,
        "deposit": 100,
        "salt": "0x" + "01" * 32,
        "authorized_signer": PAYER.address,
    }
    return abi.encode_open(**{**fields, **overrides})


class TestCalldata:
    def test_parse_open_call_checks_each_expected_field(self) -> None:
        data = open_data()
        call = chain.parse_open_call(
            data,
            payee=PAYEE.address.lower(),
            operator=ZERO_ADDRESS,
            token=CURRENCY,
            authorized_signer=PAYER.address,
            deposit=100,
        )
        assert call.deposit == 100 and call.salt == "0x" + "01" * 32
        with pytest.raises(VerificationFailedError, match="operator"):
            chain.parse_open_call(data, operator=PAYEE.address)
        with pytest.raises(VerificationFailedError, match="deposit"):
            chain.parse_open_call(data, deposit=99)
        with pytest.raises(VerificationFailedError, match="Expected TIP-1034 open"):
            chain.parse_open_call(abi.encode_withdraw(DESCRIPTOR))
        with pytest.raises(VerificationFailedError, match="Expected TIP-1034 open"):
            chain.parse_open_call(data + "00")  # trailing bytes are not canonical

    def test_amounts_beyond_uint96_are_rejected(self) -> None:
        words = ["address", "address", "address", "uint256", "bytes32", "address"]
        values = [PAYEE.address, ZERO_ADDRESS, CURRENCY, 1 << 96, b"\x01" * 32, PAYER.address]
        data = "0x" + (abi.SELECTORS["open"] + encode(words, values)).hex()
        with pytest.raises(VerificationFailedError, match="Expected TIP-1034 open"):
            chain.parse_open_call(data)
        top_up = abi.encode_top_up(DESCRIPTOR, 1)
        overflowing = top_up[:-64] + f"{1 << 96:064x}"
        with pytest.raises(VerificationFailedError, match="Expected TIP-1034 topUp"):
            chain.parse_top_up_call(overflowing)

    def test_parse_top_up_call_rejects_other_calldata(self) -> None:
        with pytest.raises(VerificationFailedError, match="Expected TIP-1034 topUp"):
            chain.parse_top_up_call(open_data())
        assert chain.parse_top_up_call(abi.encode_top_up(DESCRIPTOR, 7)) == (DESCRIPTOR, 7)

    def test_descriptor_from_open(self) -> None:
        call = chain.parse_open_call(open_data())
        kwargs: dict[str, Any] = {
            "open_call": call,
            "expiring_nonce_hash": DESCRIPTOR.expiring_nonce_hash,
            "chain_id": CHAIN_ID,
        }
        assert chain.descriptor_from_open(payer=PAYER.address, **kwargs) == DESCRIPTOR
        channel_id = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
        assert (
            chain.descriptor_from_open(payer=PAYER.address, channel_id=channel_id, **kwargs)
            == DESCRIPTOR
        )
        with pytest.raises(VerificationFailedError, match="does not match descriptor"):
            chain.descriptor_from_open(payer=PAYEE.address, channel_id=channel_id, **kwargs)


def approve_call(spender: str = chain.STABLECOIN_DEX, amount: int = 120) -> bytes:
    return chain._APPROVE_SELECTOR + encode(["address", "uint256"], [spender, amount])


def swap_call(
    token_in: str = OTHER_TOKEN, token_out: str = CURRENCY, amount_out: int = 100, max_in: int = 120
) -> bytes:
    return chain._SWAP_EXACT_AMOUNT_OUT_SELECTOR + encode(
        ["address", "address", "uint128", "uint128"], [token_in, token_out, amount_out, max_in]
    )


def swap_prefix(**overrides: Any) -> list[tuple[str, int, bytes]]:
    calls: dict[str, Any] = {
        "approve_to": OTHER_TOKEN,
        "approve_value": 0,
        "approve_data": approve_call(),
        "swap_to": chain.STABLECOIN_DEX,
        "swap_value": 0,
        "swap_data": swap_call(),
    }
    calls.update(overrides)
    return [
        (calls["approve_to"], calls["approve_value"], calls["approve_data"]),
        (calls["swap_to"], calls["swap_value"], calls["swap_data"]),
    ]


class TestAutoSwapPrefix:
    """mppx ChannelOps assertAutoSwapCalls: only approve + swapExactAmountOut buying the token."""

    def _check(self, prefix: list[tuple[str, int, bytes]]) -> None:
        chain._validate_auto_swap_prefix(prefix, amount_out=100, currency=CURRENCY, label="open")

    def test_accepts_a_canonical_swap_and_no_prefix(self) -> None:
        self._check(swap_prefix())
        self._check([])

    @pytest.mark.parametrize(
        ("prefix", "reason"),
        [
            (swap_prefix()[:1], "exactly approve and swap"),
            (swap_prefix(approve_data=b""), "missing a target or calldata"),
            (swap_prefix(swap_value=1), "native value"),
            (swap_prefix(swap_to=OTHER_TOKEN), "wrong DEX"),
            (swap_prefix(approve_data=swap_call(), swap_data=approve_call()), "approve followed"),
            (
                swap_prefix(approve_data=chain._APPROVE_SELECTOR + b"\x01"),
                "approval calldata is invalid",
            ),
            (
                swap_prefix(swap_data=chain._SWAP_EXACT_AMOUNT_OUT_SELECTOR + b"\x01"),
                "swap calldata is invalid",
            ),
            (swap_prefix(approve_to=CURRENCY), "approval token does not match"),
            (
                swap_prefix(approve_data=approve_call(spender=PAYEE.address)),
                "spender is not the DEX",
            ),
            (swap_prefix(approve_data=approve_call(amount=119)), "approval amount"),
            (swap_prefix(swap_data=swap_call(token_out=OTHER_TOKEN)), "output token"),
            (swap_prefix(swap_data=swap_call(amount_out=0)), "output amount"),
            (swap_prefix(swap_data=swap_call(amount_out=101)), "output amount"),
            (
                swap_prefix(
                    approve_to=CURRENCY, swap_data=swap_call(token_in=CURRENCY, token_out=CURRENCY)
                ),
                "must differ",
            ),
            (swap_prefix(approve_data=approve_call() + b"\x00" * 32), "approval calldata is not"),
            (swap_prefix(swap_data=swap_call() + b"\x00" * 32), "swap calldata is not canonical"),
        ],
    )
    def test_rejects(self, prefix: list[tuple[str, int, bytes]], reason: str) -> None:
        with pytest.raises(VerificationFailedError, match=reason):
            self._check(prefix)


# ──────────────────────────────────────────────────────────────────
# Client-signed credential transactions
# ──────────────────────────────────────────────────────────────────


class TestParseCredentialTransaction:
    def _parse(self, raw: str, *, fee_payer: bool = False) -> chain.ParsedCredentialTransaction:
        return chain.parse_credential_transaction(
            raw, escrow_contract=ESCROW_ADDRESS, label="open", fee_payer=fee_payer
        )

    def test_parses_sender_chain_and_validity(self) -> None:
        valid_before = int(time.time()) + 30
        parsed = self._parse(raw_tx([(ESCROW_ADDRESS, 0, "0x01")], valid_before=valid_before))
        assert parsed.sender == PAYER.address
        assert parsed.chain_id == CHAIN_ID
        assert parsed.valid_before == valid_before
        assert parsed.type_id == 0x76
        assert parsed.management_call == (ESCROW_ADDRESS.lower(), 0, b"\x01")

    @pytest.mark.parametrize(
        ("raw", "match"),
        [("0xzz", "Invalid serialized"), ("0x02f8", "0x76"), ("0x76ff", "Invalid serialized")],
    )
    def test_rejects_malformed_transactions(self, raw: str, match: str) -> None:
        with pytest.raises(BadRequestError, match=match):
            self._parse(raw)

    def test_rejects_malformed_fields_and_calls(self) -> None:
        from mpp.methods.tempo import _rlp as rlp

        fields = rlp_fields(raw_tx([(ESCROW_ADDRESS, 0, "0x01")]))
        for tampered in (
            fields[:10],
            [*fields[:4], [[b"\x01"]], *fields[5:]],
            [*fields[:4], [[[b"\x01"], b"", b""]], *fields[5:]],
        ):
            with pytest.raises(BadRequestError, match="Invalid serialized"):
                self._parse("0x76" + rlp.encode(tampered).hex())

    def test_requires_one_escrow_call_with_calldata(self) -> None:
        with pytest.raises(VerificationFailedError, match="one management call"):
            self._parse(raw_tx([(ESCROW_ADDRESS, 0, "0x01")] * 2))
        with pytest.raises(VerificationFailedError, match="missing calldata"):
            self._parse(raw_tx([(ESCROW_ADDRESS, 0, "0x")]))

    def test_requires_a_sender_signature(self) -> None:
        with pytest.raises(BadRequestError, match="signed by the sender"):
            self._parse(raw_tx([(ESCROW_ADDRESS, 0, "0x01")], signed=False))

    def test_accepts_fee_payer_envelopes_only_when_sponsoring(self) -> None:
        raw = raw_tx([(ESCROW_ADDRESS, 0, "0x01")], fee_payer=True)
        assert self._parse(raw, fee_payer=True).type_id == 0x78
        with pytest.raises(BadRequestError, match="without a fee payer"):
            self._parse(raw)


class TestValidateOpen:
    async def test_round_trips_a_built_open_transaction(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        validated = chain.validate_open_credential_transaction(
            **open_kwargs(raw, descriptor, channel_id)
        )
        assert validated.descriptor == descriptor
        assert validated.open_deposit == DEPOSIT
        assert validated.transaction.sender == PAYER.address
        (estimate,) = rpc.methods("eth_estimateGas")
        assert estimate[0]["nonceKey"] == hex(chain.EXPIRING_NONCE_KEY)
        # The estimate gets headroom for the expiring nonce and signature checks.
        assert int.from_bytes(rlp_fields(raw)[3], "big") == 100_000 + 20_000 + 25_000

    async def test_access_key_opens_for_its_root_account(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await chain.build_open_transaction(
            ACCESS_KEY,
            rpc_url=RPC,
            payee=PAYEE.address,
            token=CURRENCY,
            deposit=DEPOSIT,
            root_account=PAYER.address,
            client=rpc.client,
        )
        assert descriptor.payer == PAYER.address
        assert descriptor.authorized_signer == ACCESS_KEY.address
        validated = chain.validate_open_credential_transaction(
            **open_kwargs(raw, descriptor, channel_id)
        )
        assert validated.descriptor.payer == PAYER.address

    async def test_accepts_an_auto_swap_prefix(self, rpc: FakeRpc) -> None:
        prefix = [
            (OTHER_TOKEN, "0x" + approve_call(amount=2 * DEPOSIT).hex()),
            (chain.STABLECOIN_DEX, "0x" + swap_call(amount_out=DEPOSIT, max_in=2 * DEPOSIT).hex()),
        ]
        raw, descriptor, channel_id = await build_open(rpc, prefix_calls=prefix)
        validated = chain.validate_open_credential_transaction(
            **open_kwargs(raw, descriptor, channel_id)
        )
        assert len(validated.transaction.calls) == 3

    async def test_rejects_a_swap_buying_another_token(self, rpc: FakeRpc) -> None:
        swap = swap_call(token_out=PAYEE.address, amount_out=DEPOSIT, max_in=2 * DEPOSIT)
        prefix = [
            (OTHER_TOKEN, "0x" + approve_call(amount=2 * DEPOSIT).hex()),
            (chain.STABLECOIN_DEX, "0x" + swap.hex()),
        ]
        raw, descriptor, channel_id = await build_open(rpc, prefix_calls=prefix)
        with pytest.raises(VerificationFailedError, match="output token"):
            chain.validate_open_credential_transaction(**open_kwargs(raw, descriptor, channel_id))

    async def test_sponsored_open_must_be_an_envelope_on_the_challenge_chain(
        self, rpc: FakeRpc
    ) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        with pytest.raises(BadRequestError, match="0x78 fee payer envelopes"):
            chain.validate_open_credential_transaction(
                **open_kwargs(raw, descriptor, channel_id), fee_payer=SPONSOR
            )
        raw, descriptor, _ = await build_open(FakeRpc(chain_id=4217), fee_payer=True)
        channel_id = compute_channel_id(descriptor, chain_id=CHAIN_ID)
        with pytest.raises(VerificationError, match="chainId does not match"):
            chain.validate_open_credential_transaction(
                **open_kwargs(raw, descriptor, channel_id), fee_payer=SPONSOR
            )

    def test_sponsored_calls_must_not_transfer_value(self) -> None:
        raw = raw_tx([(ESCROW_ADDRESS, 1, open_data(deposit=DEPOSIT))], fee_payer=True)
        descriptor = replace(
            DESCRIPTOR, expiring_nonce_hash=expiring_nonce_hash(raw, PAYER.address, fee_payer=True)
        )
        channel_id = compute_channel_id(descriptor, chain_id=CHAIN_ID)
        with pytest.raises(VerificationError, match="call value is not allowed"):
            chain.validate_open_credential_transaction(
                **open_kwargs(raw, descriptor, channel_id), fee_payer=SPONSOR
            )

    async def test_sponsored_validity_is_capped_by_the_challenge_expiry(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc, fee_payer=True)
        kwargs = open_kwargs(raw, descriptor, channel_id)
        chain.validate_open_credential_transaction(
            **kwargs, fee_payer=SPONSOR, challenge_expires="2999-01-01T00:00:00Z"
        )
        with pytest.raises(VerificationError, match="validity window"):
            chain.validate_open_credential_transaction(
                **kwargs, fee_payer=SPONSOR, challenge_expires="2020-01-01T00:00:00Z"
            )


class TestValidateTopUp:
    async def test_validates_plain_and_sponsored_top_ups(self, rpc: FakeRpc) -> None:
        _, descriptor, channel_id = await build_open(rpc)
        kwargs: dict[str, Any] = {
            "additional_deposit": 500,
            "chain_id": CHAIN_ID,
            "descriptor": descriptor,
            "escrow_contract": ESCROW_ADDRESS,
            "expected_channel_id": channel_id,
            "expected_currency": CURRENCY,
        }
        raw = await chain.build_top_up_transaction(
            PAYER, descriptor, 500, rpc_url=RPC, client=rpc.client
        )
        validated = chain.validate_top_up_credential_transaction(
            serialized_transaction=raw, **kwargs
        )
        assert validated.additional_deposit == 500
        # Identical top-ups stay distinct through a random past valid_after.
        again = await chain.build_top_up_transaction(
            PAYER, descriptor, 500, rpc_url=RPC, client=rpc.client
        )
        assert again != raw

        sponsored = await chain.build_top_up_transaction(
            PAYER, descriptor, 500, rpc_url=RPC, fee_payer=True, client=rpc.client
        )
        assert sponsored.startswith("0x78")
        chain.validate_top_up_credential_transaction(
            serialized_transaction=sponsored, fee_payer=SPONSOR, **kwargs
        )
        with pytest.raises(VerificationFailedError, match="deposit does not match"):
            chain.validate_top_up_credential_transaction(
                serialized_transaction=raw, **{**kwargs, "additional_deposit": 501}
            )

    def test_random_valid_after_near_the_epoch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(chain.time, "time", lambda: 30.0)
        assert chain._random_valid_after() == 0


# ──────────────────────────────────────────────────────────────────
# Broadcast of credential transactions
# ──────────────────────────────────────────────────────────────────


class TestBroadcastOpen:
    async def _broadcast(
        self, rpc: FakeRpc, raw: str, descriptor: ChannelDescriptor, channel_id: str, **kwargs: Any
    ) -> chain.BroadcastOpenResult:
        return await chain.broadcast_open_transaction(
            RPC, **open_kwargs(raw, descriptor, channel_id), client=rpc.client, **kwargs
        )

    async def test_broadcasts_and_reads_back_at_the_receipt_block(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        rpc.logs = [opened_log(descriptor, channel_id)]
        seen: list[chain.ValidatedOpenTransaction] = []
        result = await self._broadcast(
            rpc, raw, descriptor, channel_id, before_broadcast=seen.append
        )
        assert len(seen) == 1 and seen[0].descriptor == descriptor
        assert result.descriptor == descriptor
        assert result.state == chain.ChannelState(0, DEPOSIT, 0)
        assert result.open_deposit == DEPOSIT
        assert result.expiring_nonce_hash == descriptor.expiring_nonce_hash
        assert rpc.sent == [raw]
        assert rpc.methods("eth_call")[-1][1] == "0x10"

    async def test_awaits_an_async_before_broadcast_hook(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        rpc.logs = [opened_log(descriptor, channel_id)]
        order: list[int] = []

        async def before(validated: chain.ValidatedOpenTransaction) -> None:
            order.append(len(rpc.sent))

        await self._broadcast(rpc, raw, descriptor, channel_id, before_broadcast=before)
        assert order == [0]

    async def test_sponsored_open_is_preflighted_cosigned_and_simulated(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc, fee_payer=True)
        rpc.logs = [opened_log(descriptor, channel_id)]
        await self._broadcast(rpc, raw, descriptor, channel_id, fee_payer=SPONSOR)
        simulations = [p[0] for p in rpc.methods("eth_call") if "calls" in p[0]]
        assert len(simulations) == 2
        # First the calls as the sender, then the completed sponsored envelope.
        assert simulations[0]["from"] == PAYER.address and "feePayer" not in simulations[0]
        assert simulations[0]["calls"][0]["to"] == ESCROW_ADDRESS.lower()
        assert simulations[1]["feePayer"] == SPONSOR.address
        assert simulations[1]["nonceKey"] == hex(chain.EXPIRING_NONCE_KEY)
        assert "validBefore" in simulations[1] and "validAfter" not in simulations[1]
        # The co-signed 0x76 is what reaches the node.
        assert rpc.sent[0].startswith("0x76")

    async def test_failed_preflight_is_a_verification_failure(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc, fee_payer=True)
        rpc.overrides["eth_call"] = fail("execution reverted: insufficient balance")
        with pytest.raises(VerificationFailedError, match="insufficient balance"):
            await self._broadcast(rpc, raw, descriptor, channel_id, fee_payer=SPONSOR)
        assert not rpc.sent

    async def test_reverted_open_names_the_transaction(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        rpc.receipt_status = "0x0"
        with pytest.raises(VerificationFailedError, match="open precompile transaction reverted"):
            await self._broadcast(rpc, raw, descriptor, channel_id)

    async def test_rejects_a_receipt_without_the_open_event(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        rpc.logs = [opened_log(descriptor, channel_id, address=PAYEE.address)]
        with pytest.raises(VerificationFailedError, match="expected one ChannelOpened"):
            await self._broadcast(rpc, raw, descriptor, channel_id)

    async def test_rejects_an_event_with_another_deposit(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        rpc.logs = [opened_log(descriptor, channel_id, deposit=DEPOSIT - 1)]
        with pytest.raises(VerificationFailedError, match="deposit does not match calldata"):
            await self._broadcast(rpc, raw, descriptor, channel_id)

    async def test_rejects_a_readback_that_disagrees(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await build_open(rpc)
        rpc.logs = [opened_log(descriptor, channel_id)]
        rpc.states[channel_id] = (1, DEPOSIT, 0)
        with pytest.raises(VerificationFailedError, match="does not match open receipt"):
            await self._broadcast(rpc, raw, descriptor, channel_id)


class TestBroadcastTopUp:
    async def _setup(
        self, rpc: FakeRpc, *, fee_payer: bool = False
    ) -> tuple[str, ChannelDescriptor, str]:
        _, descriptor, channel_id = await build_open(rpc)
        raw = await chain.build_top_up_transaction(
            PAYER, descriptor, 500, rpc_url=RPC, fee_payer=fee_payer, client=rpc.client
        )
        rpc.logs = [top_up_log(descriptor, channel_id, 500, DEPOSIT + 500)]
        return raw, descriptor, channel_id

    async def _broadcast(
        self, rpc: FakeRpc, raw: str, descriptor: ChannelDescriptor, channel_id: str, **kwargs: Any
    ) -> chain.BroadcastTopUpResult:
        return await chain.broadcast_top_up_transaction(
            RPC,
            serialized_transaction=raw,
            additional_deposit=500,
            chain_id=CHAIN_ID,
            descriptor=descriptor,
            escrow_contract=ESCROW_ADDRESS,
            expected_channel_id=channel_id,
            expected_currency=CURRENCY,
            client=rpc.client,
            **kwargs,
        )

    async def test_broadcasts_and_checks_the_new_deposit(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await self._setup(rpc)
        rpc.states[channel_id] = (0, DEPOSIT + 500, 0)
        result = await self._broadcast(rpc, raw, descriptor, channel_id)
        assert result.new_deposit == DEPOSIT + 500
        assert result.state.deposit == DEPOSIT + 500
        assert rpc.sent == [raw]

    async def test_sponsored_top_up(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await self._setup(rpc, fee_payer=True)
        rpc.states[channel_id] = (0, DEPOSIT + 500, 0)
        result = await self._broadcast(rpc, raw, descriptor, channel_id, fee_payer=SPONSOR)
        assert result.new_deposit == DEPOSIT + 500
        assert rpc.sent[0].startswith("0x76")

    async def test_reads_back_at_an_integer_receipt_block(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await self._setup(rpc)
        rpc.states[channel_id] = (0, DEPOSIT + 500, 0)
        receipt = {"status": 1, "blockNumber": 33, "transactionHash": "0x01", "logs": rpc.logs}
        rpc.overrides["eth_getTransactionReceipt"] = lambda params: receipt
        await self._broadcast(rpc, raw, descriptor, channel_id)
        assert rpc.methods("eth_call")[-1][1] == "0x21"
        receipt.pop("blockNumber")
        await self._broadcast(rpc, raw, descriptor, channel_id)
        assert rpc.methods("eth_call")[-1][1] == "latest"

    async def test_owns_and_closes_a_client_when_none_is_given(
        self, rpc: FakeRpc, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw, _, _ = await self._setup(rpc)
        parsed = chain.parse_credential_transaction(
            raw, escrow_contract=ESCROW_ADDRESS, label="topUp"
        )
        created: list[httpx.AsyncClient] = []
        real_client = httpx.AsyncClient

        def factory(**kwargs: Any) -> httpx.AsyncClient:
            client = real_client(transport=httpx.MockTransport(rpc._handle))
            created.append(client)
            return client

        monkeypatch.setattr(httpx, "AsyncClient", factory)
        receipt = await chain.send_credential_transaction(
            RPC, parsed, chain_id=CHAIN_ID, label="topUp", expected_currency=CURRENCY
        )
        assert receipt["status"] == "0x1"
        assert len(created) == 1 and created[0].is_closed

    async def test_rejects_a_stale_readback(self, rpc: FakeRpc) -> None:
        raw, descriptor, channel_id = await self._setup(rpc)
        with pytest.raises(VerificationFailedError, match="topUp receipt"):
            await self._broadcast(rpc, raw, descriptor, channel_id)


class TestSimulate:
    async def test_simulates_unsponsored_transactions_only(self, rpc: FakeRpc) -> None:
        raw, _, _ = await build_open(rpc)
        parsed = chain.parse_credential_transaction(
            raw, escrow_contract=ESCROW_ADDRESS, label="open"
        )
        await chain.simulate_credential_transaction(
            RPC, parsed, fee_payer=SPONSOR, client=rpc.client
        )
        assert not rpc.methods("eth_call")
        await chain.simulate_credential_transaction(RPC, parsed, client=rpc.client)
        assert [p[0]["from"] for p in rpc.methods("eth_call")] == [PAYER.address]


# ──────────────────────────────────────────────────────────────────
# Building transactions
# ──────────────────────────────────────────────────────────────────


class TestBuild:
    async def test_falls_back_to_the_default_gas_limit(self, rpc: FakeRpc) -> None:
        rpc.overrides["eth_estimateGas"] = fail("nope")
        raw, _, _ = await build_open(rpc)
        assert int.from_bytes(rlp_fields(raw)[3], "big") == chain.DEFAULT_GAS_LIMIT

    async def test_rejects_an_rpc_on_another_chain(self, rpc: FakeRpc) -> None:
        with pytest.raises(ValueError, match="Chain ID mismatch"):
            await build_open(rpc, chain_id=4217)

    async def test_sponsored_envelope_caps_the_priority_fee(self, rpc: FakeRpc) -> None:
        rpc.overrides["eth_gasPrice"] = lambda params: hex(60_000_000_000)
        raw, _, _ = await build_open(rpc, fee_payer=True)
        fields = rlp_fields(raw)
        assert int.from_bytes(fields[1], "big") == 10_000_000_000
        assert int.from_bytes(fields[2], "big") == 60_000_000_000


class TestResolveFeeToken:
    async def test_prefers_a_held_token(self, rpc: FakeRpc) -> None:
        owner = SPONSOR.address
        rpc.balances[f"{CURRENCY}:{owner}".lower()] = -1  # the read fails
        rpc.balances[f"{OTHER_TOKEN}:{owner}".lower()] = 5
        token = await chain.resolve_fee_token(
            RPC, owner, [CURRENCY, OTHER_TOKEN], client=rpc.client
        )
        assert token == OTHER_TOKEN

    async def test_falls_back_to_the_first_candidate(self, rpc: FakeRpc) -> None:
        owner = SPONSOR.address
        token = await chain.resolve_fee_token(
            RPC, owner, [OTHER_TOKEN, CURRENCY], client=rpc.client
        )
        assert token == OTHER_TOKEN
        assert await chain.resolve_fee_token(RPC, owner, [], client=rpc.client) is None


# ──────────────────────────────────────────────────────────────────
# Server and payer contract calls
# ──────────────────────────────────────────────────────────────────


def sent_call(rpc: FakeRpc, index: int = 0) -> tuple[int, str, str, bool]:
    """(type, to, calldata, co-signed) of a transaction sent to the fake node."""
    raw = rpc.sent[index]
    fields = rlp_fields(raw)
    (to, _, data), *_ = fields[4]
    return int(raw[2:4], 16), "0x" + to.hex(), "0x" + data.hex(), fields[11] != b""


class TestContractCalls:
    @pytest.mark.parametrize(
        ("send", "expected"),
        [
            (
                lambda rpc: chain.settle_on_chain(
                    RPC, PAYEE, DESCRIPTOR, 5, SIGNATURE, client=rpc.client
                ),
                abi.encode_settle(DESCRIPTOR, 5, SIGNATURE),
            ),
            (
                lambda rpc: chain.close_on_chain(
                    RPC, PAYEE, DESCRIPTOR, 5, 4, SIGNATURE, client=rpc.client
                ),
                abi.encode_close(DESCRIPTOR, 5, 4, SIGNATURE),
            ),
            (
                lambda rpc: chain.top_up_on_chain(RPC, PAYER, DESCRIPTOR, 9, client=rpc.client),
                abi.encode_top_up(DESCRIPTOR, 9),
            ),
            (
                lambda rpc: chain.request_close_on_chain(RPC, PAYER, DESCRIPTOR, client=rpc.client),
                abi.encode_request_close(DESCRIPTOR),
            ),
            (
                lambda rpc: chain.withdraw_on_chain(RPC, PAYER, DESCRIPTOR, client=rpc.client),
                abi.encode_withdraw(DESCRIPTOR),
            ),
        ],
        ids=["settle", "close", "topUp", "requestClose", "withdraw"],
    )
    async def test_sends_one_escrow_call(self, rpc: FakeRpc, send: Any, expected: str) -> None:
        tx_hash = await send(rpc)
        assert tx_hash == "0x" + f"{1:064x}"
        assert sent_call(rpc) == (0x76, ESCROW_ADDRESS.lower(), expected, False)
        # Unsponsored sends return at broadcast without waiting for the receipt.
        assert not rpc.methods("eth_getTransactionReceipt")

    async def test_sponsored_settle_resolves_a_fee_token_and_waits(self, rpc: FakeRpc) -> None:
        rpc.balances[f"{OTHER_TOKEN}:{SPONSOR.address}".lower()] = 1
        await chain.settle_on_chain(
            RPC,
            PAYEE,
            DESCRIPTOR,
            5,
            SIGNATURE,
            fee_payer=SPONSOR,
            candidate_fee_tokens=[CURRENCY, OTHER_TOKEN],
            client=rpc.client,
        )
        type_id, _, _, cosigned = sent_call(rpc)
        assert type_id == 0x76 and cosigned
        assert "0x" + rlp_fields(rpc.sent[0])[10].hex() == OTHER_TOKEN.lower()
        assert rpc.methods("eth_getTransactionReceipt")

    async def test_sponsor_defaults_to_the_chain_fee_tokens(self, rpc: FakeRpc) -> None:
        from mpp.methods.tempo._defaults import fee_tokens_for_chain

        await chain.settle_on_chain(
            RPC, PAYEE, DESCRIPTOR, 5, SIGNATURE, fee_payer=SPONSOR, client=rpc.client
        )
        balance_reads = [p[0]["to"] for p in rpc.methods("eth_call")]
        assert balance_reads == list(fee_tokens_for_chain(CHAIN_ID))

    async def test_self_sponsored_send_is_unsponsored(self, rpc: FakeRpc) -> None:
        await chain.settle_on_chain(
            RPC,
            PAYEE,
            DESCRIPTOR,
            5,
            SIGNATURE,
            fee_payer=PAYEE,
            fee_token=CURRENCY,
            client=rpc.client,
        )
        assert sent_call(rpc)[3] is False
        assert not rpc.methods("eth_call")

    @pytest.mark.parametrize(
        ("policy", "match"),
        [
            ({"max_gas": 1}, "maxGas"),
            ({"max_fee_per_gas": 1}, "maxFeePerGas"),
            ({"max_priority_fee_per_gas": 1}, "maxPriorityFeePerGas"),
            ({"max_total_fee": 1}, "maxTotalFee"),
        ],
    )
    async def test_sponsored_send_respects_the_fee_payer_policy(
        self, rpc: FakeRpc, policy: dict[str, int], match: str
    ) -> None:
        with pytest.raises(BadRequestError, match=match):
            await chain.settle_on_chain(
                RPC,
                PAYEE,
                DESCRIPTOR,
                5,
                SIGNATURE,
                fee_payer=SPONSOR,
                fee_payer_policy=policy,
                fee_token=CURRENCY,
                client=rpc.client,
            )
        assert not rpc.sent

    async def test_reverted_sponsored_send_names_the_call(self, rpc: FakeRpc) -> None:
        rpc.receipt_status = "0x0"
        with pytest.raises(VerificationFailedError, match="close precompile transaction reverted"):
            await chain.close_on_chain(
                RPC,
                PAYEE,
                DESCRIPTOR,
                5,
                5,
                SIGNATURE,
                fee_payer=SPONSOR,
                fee_token=CURRENCY,
                client=rpc.client,
            )


# ──────────────────────────────────────────────────────────────────
# Local fee-payer co-signing (shared with the charge intent)
# ──────────────────────────────────────────────────────────────────


def envelope(**overrides: Any) -> str:
    fields: dict[str, Any] = {
        "chain_id": CHAIN_ID,
        "gas_limit": 200_000,
        "max_fee_per_gas": GAS_PRICE,
        "max_priority_fee_per_gas": GAS_PRICE // 10,
        "nonce_key": chain.EXPIRING_NONCE_KEY,
        "valid_before": int(time.time()) + 60,
        "fee_token": CURRENCY,
        "awaiting_fee_payer": True,
        "calls": (Call.create(to=ESCROW_ADDRESS, value=0, data="0x01"),),
    }
    fields.update(overrides)
    signed = TempoTransaction.create(**fields).sign(PAYER.private_key)
    return chain._serialize_client_transaction(signed, True)


def with_signature(raw: str, signature: bytes) -> str:
    from mpp.methods.tempo import _rlp as rlp

    fields = rlp_fields(raw)
    return "0x78" + rlp.encode([*fields[:-1], signature]).hex()


class TestFeePayerCosign:
    def _cosign(self, raw: str, fee_payer: Any = SPONSOR, **kwargs: Any) -> tuple[str, Any, str]:
        from mpp.methods.tempo import _fee_payer
        from mpp.methods.tempo.fee_payer_policy import get_policy

        options: dict[str, Any] = {"allowed_fee_tokens": [CURRENCY]}
        options.update(kwargs)
        return _fee_payer.cosign_fee_payer_envelope(
            raw, fee_payer=fee_payer, policy=get_policy, **options
        )

    def test_cosigns_without_a_call_validator(self) -> None:
        raw, cosigned, sender = self._cosign(envelope())
        assert raw.startswith("0x76")
        assert sender == PAYER.address
        assert "0x" + bytes(cosigned.fee_token).hex() == CURRENCY.lower()

    def test_simulation_payload_keeps_call_order_and_validity(self) -> None:
        from mpp.methods.tempo._fee_payer import build_simulate_payload

        calls = (
            Call.create(to=OTHER_TOKEN, value=0, data="0x02"),
            Call.create(to=ESCROW_ADDRESS, value=0, data="0x01"),
        )
        _, cosigned, sender = self._cosign(envelope(calls=calls, valid_after=123))
        (request,) = build_simulate_payload(cosigned, sender)["blockStateCalls"][0]["calls"]
        assert request["to"] == ESCROW_ADDRESS.lower() and request["data"] == "0x01"
        assert [c["to"] for c in request["calls"]] == [OTHER_TOKEN.lower()]
        assert request["validAfter"] == hex(123)

    def test_rejects_fee_tokens_outside_the_allowed_list(self) -> None:
        with pytest.raises(VerificationError, match="feeToken is not allowed"):
            self._cosign(envelope(), allowed_fee_tokens=[OTHER_TOKEN])

    def test_rejects_a_priority_fee_above_the_max_fee(self) -> None:
        from mpp.methods.tempo import _rlp as rlp

        # pytempo refuses to sign such a transaction, so tamper with a signed one.
        fields = rlp_fields(envelope())
        fields[1] = (2 * GAS_PRICE).to_bytes(5, "big")
        raw = "0x78" + rlp.encode(fields).hex()
        with pytest.raises(VerificationError, match="exceeds max fee per gas"):
            self._cosign(raw)

    def test_rejects_a_priority_fee_above_the_sponsor_policy(self) -> None:
        # The default policy allows 10 gwei of priority fee.
        with pytest.raises(VerificationError, match="priority fee per gas exceeds sponsor"):
            self._cosign(envelope(max_priority_fee_per_gas=GAS_PRICE))

    def test_rejects_signatures_it_cannot_recover(self) -> None:
        with pytest.raises(VerificationError, match="Only 65-byte"):
            self._cosign(with_signature(envelope(), b"\x01" * 64))
        with pytest.raises(VerificationError, match="Invalid sender signature"):
            self._cosign(with_signature(envelope(), b"\x00" * 64 + b"\x1b"))

    def test_signing_failures_are_internal_errors(self) -> None:
        from types import SimpleNamespace

        from mpp.errors import InternalPaymentError

        broken = SimpleNamespace(private_key="0x" + "00" * 32)
        with pytest.raises(InternalPaymentError):
            self._cosign(envelope(), fee_payer=broken)

    def test_rpc_error_message(self) -> None:
        from mpp.methods.tempo._fee_payer import rpc_error_message

        assert rpc_error_message({"error": "boom"}) == "boom"
        assert rpc_error_message({"error": {"message": "reverted", "data": "0x12"}}) == (
            "reverted: 0x12"
        )
        assert rpc_error_message({"error": {"name": "Halt"}}) == "Halt"

    def test_simulation_payload_refuses_authorization_bearing_transactions(self) -> None:
        from types import SimpleNamespace

        from mpp.methods.tempo._fee_payer import build_simulate_payload

        tx = SimpleNamespace(key_authorization=object(), tempo_authorization_list=())
        with pytest.raises(VerificationError, match="authorization-bearing"):
            build_simulate_payload(tx, PAYER.address)

    @pytest.mark.parametrize(
        ("answer", "error", "match"),
        [
            ({"result": {"blocks": [{"calls": [{"status": "0x1"}]}]}}, None, None),
            ({"error": {"message": "nope"}}, "internal", None),
            ({"result": {"blocks": []}}, "internal", None),
            (
                {"result": {"blocks": [{"calls": [{"status": "0x0", "error": {"message": "x"}}]}]}},
                "verification",
                "would revert in pre-broadcast simulation: x",
            ),
            (
                {"result": {"blocks": [{"calls": [{"status": "0x0"}]}]}},
                "verification",
                "no revert reason returned",
            ),
        ],
    )
    async def test_simulate_before_broadcast(
        self, answer: dict[str, Any], error: str | None, match: str | None
    ) -> None:
        from mpp.errors import InternalPaymentError
        from mpp.methods.tempo._fee_payer import simulate_before_broadcast

        def handle(request: httpx.Request) -> httpx.Response:
            assert json.loads(request.content)["method"] == "tempo_simulateV1"
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, **answer})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        if error is None:
            await simulate_before_broadcast(client, {}, RPC)
            return
        expected = InternalPaymentError if error == "internal" else VerificationError
        with pytest.raises(expected, match=match):
            await simulate_before_broadcast(client, {}, RPC)

    async def test_simulation_transport_errors_fail_closed(self) -> None:
        from mpp.errors import InternalPaymentError
        from mpp.methods.tempo._fee_payer import simulate_before_broadcast

        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(502))
        )
        with pytest.raises(InternalPaymentError):
            await simulate_before_broadcast(client, {}, RPC)
