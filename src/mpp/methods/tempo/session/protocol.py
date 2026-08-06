"""TIP-1034 channel, transaction, voucher, and header primitives."""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from eth_abi.abi import decode, encode
from eth_hash.auto import keccak

from mpp.methods.tempo._rpc import _rpc_call, estimate_gas
from mpp.methods.tempo.fee_payer_policy import get_policy

from .credentials import SessionCredentialProvider
from .models import (
    MAX_UINT96,
    ZERO_ADDRESS,
    ChannelDescriptor,
    SessionReceipt,
    SessionSnapshot,
    normalize_address,
    normalize_hash,
)

EXPIRING_NONCE_KEY = (1 << 256) - 1
DEFAULT_GAS_LIMIT = 1_000_000
VALID_BEFORE_SECONDS = 25


def _selector(signature: str) -> bytes:
    return keccak(signature.encode())[:4]


OPEN_SELECTOR = _selector("open(address,address,address,uint96,bytes32,address)")
TOP_UP_SELECTOR = _selector(
    "topUp((address,address,address,address,bytes32,address,bytes32),uint96)"
)
GET_CHANNEL_STATE_SELECTOR = _selector("getChannelState(bytes32)")


@dataclass(frozen=True, slots=True)
class ChannelState:
    """On-chain TIP-1034 packed channel state."""

    settled: int
    deposit: int
    close_requested_at: int

    @property
    def open(self) -> bool:
        return self.deposit > 0


class SessionRpc(Protocol):
    """Chain reads needed by the reusable session manager."""

    async def gas_price(self) -> int: ...

    async def channel_state(self, escrow: str, channel_id: str) -> ChannelState: ...


@dataclass(frozen=True, slots=True)
class TempoSessionRpc:
    """JSON-RPC implementation for a Tempo network."""

    url: str

    async def gas_price(self) -> int:
        return int(await _rpc_call(self.url, "eth_gasPrice", []), 16)

    async def channel_state(self, escrow: str, channel_id: str) -> ChannelState:
        call = GET_CHANNEL_STATE_SELECTOR + encode(["bytes32"], [bytes.fromhex(channel_id[2:])])
        data = "0x" + call.hex()
        result = await _rpc_call(
            self.url,
            "eth_call",
            [{"to": escrow, "data": data}, "latest"],
        )
        raw = bytes.fromhex(result[2:])
        settled, deposit, close_requested_at = decode(["uint96", "uint96", "uint32"], raw)
        return ChannelState(int(settled), int(deposit), int(close_requested_at))


def channel_scope(*, payee: str, token: str, escrow: str, chain_id: int) -> str:
    """Return the same reusable-channel scope key used by mppx."""

    return ":".join(
        (
            normalize_address(payee, "payee"),
            normalize_address(token, "token"),
            normalize_address(escrow, "escrow"),
            str(chain_id),
        )
    )


def compute_channel_id(
    descriptor: ChannelDescriptor,
    *,
    escrow: str,
    chain_id: int,
) -> str:
    """Compute the canonical TIP-1034 descriptor/escrow/chain hash."""

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
        [
            descriptor.payer,
            descriptor.payee,
            descriptor.operator,
            descriptor.token,
            bytes.fromhex(descriptor.salt[2:]),
            descriptor.authorized_signer,
            bytes.fromhex(descriptor.expiring_nonce_hash[2:]),
            normalize_address(escrow, "escrow"),
            chain_id,
        ],
    )
    return "0x" + keccak(encoded).hex()


def compute_expiring_nonce_hash(transaction: Any, payer: str) -> str:
    """Hash the exact Tempo sender-signing preimage and sender address."""

    encoder = getattr(transaction, "encode_for_signing", None)
    if encoder is None:
        raise RuntimeError("Tempo sessions require pytempo>=0.6.0")
    preimage = encoder()
    return "0x" + keccak(preimage + bytes.fromhex(normalize_address(payer, "payer")[2:])).hex()


def voucher_digest(
    *,
    channel_id: str,
    cumulative_amount: int,
    chain_id: int,
    escrow: str,
) -> bytes:
    """Compute the v2 EIP-712 voucher digest used by mppx and TIP-1034."""

    if cumulative_amount < 0 or cumulative_amount > MAX_UINT96:
        raise ValueError("cumulative amount is outside uint96 bounds")
    domain_type = keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    )
    domain = keccak(
        encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                domain_type,
                keccak(b"TIP20 Channel Reserve"),
                keccak(b"1"),
                chain_id,
                normalize_address(escrow, "escrow"),
            ],
        )
    )
    voucher_type = keccak(b"Voucher(bytes32 channelId,uint96 cumulativeAmount)")
    struct = keccak(
        encode(
            ["bytes32", "bytes32", "uint96"],
            [
                voucher_type,
                bytes.fromhex(normalize_hash(channel_id, "channelId")[2:]),
                cumulative_amount,
            ],
        )
    )
    return keccak(b"\x19\x01" + domain + struct)


async def sign_voucher(
    provider: SessionCredentialProvider,
    *,
    channel_id: str,
    cumulative_amount: int,
    chain_id: int,
    escrow: str,
) -> str:
    signature = await provider.sign_digest(
        voucher_digest(
            channel_id=channel_id,
            cumulative_amount=cumulative_amount,
            chain_id=chain_id,
            escrow=escrow,
        )
    )
    if len(signature) != 65:
        raise ValueError("TIP-1034 vouchers require a primitive 65-byte signature")
    return "0x" + signature.hex()


def verify_voucher_signature(
    *,
    channel_id: str,
    cumulative_amount: int,
    signature: str,
    expected_signer: str,
    chain_id: int,
    escrow: str,
) -> bool:
    """Verify a primitive secp256k1 snapshot voucher."""

    try:
        from eth_account import Account

        raw = bytes.fromhex(signature.removeprefix("0x"))
        if len(raw) == 64:
            r, compact_s = raw[:32], int.from_bytes(raw[32:], "big")
            parity = compact_s >> 255
            s = (compact_s & ((1 << 255) - 1)).to_bytes(32, "big")
            raw = r + s + bytes([parity])
        if len(raw) != 65:
            return False
        recovered = Account._recover_hash(  # type: ignore[attr-defined]
            voucher_digest(
                channel_id=channel_id,
                cumulative_amount=cumulative_amount,
                chain_id=chain_id,
                escrow=escrow,
            ),
            signature=raw,
        )
        return recovered.lower() == normalize_address(expected_signer, "expectedSigner")
    except (TypeError, ValueError):
        return False


def encode_open_call(
    *,
    payee: str,
    operator: str,
    token: str,
    deposit: int,
    salt: str,
    authorized_signer: str,
) -> bytes:
    return OPEN_SELECTOR + encode(
        ["address", "address", "address", "uint96", "bytes32", "address"],
        [
            normalize_address(payee, "payee"),
            normalize_address(operator, "operator"),
            normalize_address(token, "token"),
            deposit,
            bytes.fromhex(normalize_hash(salt, "salt")[2:]),
            normalize_address(authorized_signer, "authorizedSigner"),
        ],
    )


def encode_top_up_call(descriptor: ChannelDescriptor, additional_deposit: int) -> bytes:
    return TOP_UP_SELECTOR + encode(
        ["(address,address,address,address,bytes32,address,bytes32)", "uint96"],
        [
            (
                descriptor.payer,
                descriptor.payee,
                descriptor.operator,
                descriptor.token,
                bytes.fromhex(descriptor.salt[2:]),
                descriptor.authorized_signer,
                bytes.fromhex(descriptor.expiring_nonce_hash[2:]),
            ),
            additional_deposit,
        ],
    )


@dataclass(slots=True)
class TempoSessionProtocol:
    """Construct exact signed v2 session payloads."""

    provider: SessionCredentialProvider
    rpc: SessionRpc
    clock: Callable[[], float] = time.time
    random_bytes: Callable[[int], bytes] = secrets.token_bytes

    async def _transaction(
        self,
        *,
        chain_id: int,
        escrow: str,
        token: str,
        data: bytes,
        fee_payer: bool,
        valid_after: int | None = None,
    ) -> Any:
        from pytempo import Call, TempoTransaction

        gas_price = await self.rpc.gas_price()
        priority_fee = gas_price
        if fee_payer:
            priority_fee = min(gas_price, get_policy(chain_id).max_priority_fee_per_gas)
        gas_limit = DEFAULT_GAS_LIMIT
        if isinstance(self.rpc, TempoSessionRpc):
            try:
                estimate = await estimate_gas(
                    self.rpc.url,
                    self.provider.payer_address,
                    escrow,
                    "0x" + data.hex(),
                )
                gas_limit = max(gas_limit, estimate + 5_000)
            except Exception:
                pass
        return TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=gas_limit,
            max_fee_per_gas=gas_price,
            max_priority_fee_per_gas=priority_fee,
            nonce=0,
            nonce_key=EXPIRING_NONCE_KEY,
            valid_before=int(self.clock()) + VALID_BEFORE_SECONDS,
            valid_after=valid_after,
            fee_token=token,
            awaiting_fee_payer=fee_payer,
            calls=(Call.create(to=escrow, value=0, data=data),),
        )

    async def open_payload(
        self,
        *,
        chain_id: int,
        escrow: str,
        payee: str,
        operator: str | None,
        token: str,
        deposit: int,
        initial_cumulative: int,
        fee_payer: bool,
    ) -> dict[str, Any]:
        salt = "0x" + self.random_bytes(32).hex()
        operator = operator or ZERO_ADDRESS
        data = encode_open_call(
            payee=payee,
            operator=operator,
            token=token,
            deposit=deposit,
            salt=salt,
            authorized_signer=self.provider.signer_address,
        )
        transaction = await self._transaction(
            chain_id=chain_id,
            escrow=escrow,
            token=token,
            data=data,
            fee_payer=fee_payer,
        )
        descriptor = ChannelDescriptor(
            payer=self.provider.payer_address,
            payee=payee,
            operator=operator,
            token=token,
            salt=salt,
            authorized_signer=self.provider.signer_address,
            expiring_nonce_hash=compute_expiring_nonce_hash(
                transaction, self.provider.payer_address
            ),
        )
        channel_id = compute_channel_id(descriptor, escrow=escrow, chain_id=chain_id)
        signature, raw_transaction = await asyncio.gather(
            sign_voucher(
                self.provider,
                channel_id=channel_id,
                cumulative_amount=initial_cumulative,
                chain_id=chain_id,
                escrow=escrow,
            ),
            self.provider.sign_transaction(transaction),
        )
        return {
            "action": "open",
            "type": "transaction",
            "channelId": channel_id,
            "transaction": raw_transaction,
            "signature": signature,
            "descriptor": descriptor.to_wire(),
            "cumulativeAmount": str(initial_cumulative),
            "authorizedSigner": descriptor.authorized_signer,
        }

    async def top_up_payload(
        self,
        *,
        descriptor: ChannelDescriptor,
        additional_deposit: int,
        chain_id: int,
        escrow: str,
        fee_payer: bool,
    ) -> dict[str, Any]:
        latest = max(0, int(self.clock()) - 60)
        valid_after = 0 if latest == 0 else int.from_bytes(self.random_bytes(8), "big") % latest
        transaction = await self._transaction(
            chain_id=chain_id,
            escrow=escrow,
            token=descriptor.token,
            data=encode_top_up_call(descriptor, additional_deposit),
            fee_payer=fee_payer,
            valid_after=valid_after,
        )
        return {
            "action": "topUp",
            "type": "transaction",
            "channelId": compute_channel_id(descriptor, escrow=escrow, chain_id=chain_id),
            "transaction": await self.provider.sign_transaction(transaction),
            "descriptor": descriptor.to_wire(),
            "additionalDeposit": str(additional_deposit),
        }

    async def voucher_payload(
        self,
        *,
        action: str,
        descriptor: ChannelDescriptor,
        cumulative_amount: int,
        chain_id: int,
        escrow: str,
    ) -> dict[str, Any]:
        if action not in {"voucher", "close"}:
            raise ValueError("voucher action must be voucher or close")
        channel_id = compute_channel_id(descriptor, escrow=escrow, chain_id=chain_id)
        return {
            "action": action,
            "channelId": channel_id,
            "descriptor": descriptor.to_wire(),
            "cumulativeAmount": str(cumulative_amount),
            "signature": await sign_voucher(
                self.provider,
                channel_id=channel_id,
                cumulative_amount=cumulative_amount,
                chain_id=chain_id,
                escrow=escrow,
            ),
        }


def _decode_json_header(value: str) -> Any:
    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + padding)
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid base64 JSON header") from error


def decode_session_snapshot(value: str) -> SessionSnapshot:
    """Decode the `Payment-Session-Snapshot` base64 JSON header."""

    return SessionSnapshot.from_wire(_decode_json_header(value))


def decode_session_receipt(value: str) -> SessionReceipt:
    """Decode the session-specific `Payment-Receipt` header."""

    return SessionReceipt.from_wire(_decode_json_header(value))
