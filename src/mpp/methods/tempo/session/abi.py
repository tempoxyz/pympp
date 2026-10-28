"""TIP20EscrowChannel precompile ABI (mppx src/tempo/session/precompile/escrow.abi.ts).

Encodes calldata for the escrow's management calls and decodes its view
results and events, with eth-abi.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from eth_abi.abi import decode, encode
from eth_hash.auto import keccak

from mpp.methods.tempo.session.protocol import ChannelDescriptor, uint96

DESCRIPTOR_TYPE = "(address,address,address,address,bytes32,address,bytes32)"
"""ABI tuple type of a channel descriptor."""
STATE_TYPE = "(uint96,uint96,uint32)"
"""ABI tuple type of a channel's packed state: settled, deposit, closeRequestedAt."""


def _selector(signature: str) -> bytes:
    return keccak(signature.encode())[:4]


def _topic(signature: str) -> str:
    return "0x" + keccak(signature.encode()).hex()


SELECTORS: dict[str, bytes] = {
    "open": _selector("open(address,address,address,uint96,bytes32,address)"),
    "settle": _selector(f"settle({DESCRIPTOR_TYPE},uint96,bytes)"),
    "topUp": _selector(f"topUp({DESCRIPTOR_TYPE},uint96)"),
    "close": _selector(f"close({DESCRIPTOR_TYPE},uint96,uint96,bytes)"),
    "requestClose": _selector(f"requestClose({DESCRIPTOR_TYPE})"),
    "withdraw": _selector(f"withdraw({DESCRIPTOR_TYPE})"),
    "getChannel": _selector(f"getChannel({DESCRIPTOR_TYPE})"),
    "getChannelState": _selector("getChannelState(bytes32)"),
    "getChannelStatesBatch": _selector("getChannelStatesBatch(bytes32[])"),
    "computeChannelId": _selector(
        "computeChannelId(address,address,address,address,bytes32,address,bytes32)"
    ),
    "getVoucherDigest": _selector("getVoucherDigest(bytes32,uint96)"),
    "domainSeparator": _selector("domainSeparator()"),
    "CLOSE_GRACE_PERIOD": _selector("CLOSE_GRACE_PERIOD()"),
    "VOUCHER_TYPEHASH": _selector("VOUCHER_TYPEHASH()"),
}
"""4-byte selectors of the escrow's functions, by name."""

# Event name -> (signature, [(name, type, indexed)]).
_EVENTS: dict[str, tuple[str, list[tuple[str, str, bool]]]] = {
    "ChannelOpened": (
        "ChannelOpened(bytes32,address,address,address,address,address,bytes32,bytes32,uint96)",
        [
            ("channelId", "bytes32", True),
            ("payer", "address", True),
            ("payee", "address", True),
            ("operator", "address", False),
            ("token", "address", False),
            ("authorizedSigner", "address", False),
            ("salt", "bytes32", False),
            ("expiringNonceHash", "bytes32", False),
            ("deposit", "uint96", False),
        ],
    ),
    "Settled": (
        "Settled(bytes32,address,address,uint96,uint96,uint96)",
        [
            ("channelId", "bytes32", True),
            ("payer", "address", True),
            ("payee", "address", True),
            ("cumulativeAmount", "uint96", False),
            ("deltaPaid", "uint96", False),
            ("newSettled", "uint96", False),
        ],
    ),
    "TopUp": (
        "TopUp(bytes32,address,address,uint96,uint96)",
        [
            ("channelId", "bytes32", True),
            ("payer", "address", True),
            ("payee", "address", True),
            ("additionalDeposit", "uint96", False),
            ("newDeposit", "uint96", False),
        ],
    ),
    "CloseRequested": (
        "CloseRequested(bytes32,address,address,uint256)",
        [
            ("channelId", "bytes32", True),
            ("payer", "address", True),
            ("payee", "address", True),
            ("closeGraceEnd", "uint256", False),
        ],
    ),
    "ChannelClosed": (
        "ChannelClosed(bytes32,address,address,uint96,uint96)",
        [
            ("channelId", "bytes32", True),
            ("payer", "address", True),
            ("payee", "address", True),
            ("settledToPayee", "uint96", False),
            ("refundedToPayer", "uint96", False),
        ],
    ),
    "CloseRequestCancelled": (
        "CloseRequestCancelled(bytes32,address,address)",
        [
            ("channelId", "bytes32", True),
            ("payer", "address", True),
            ("payee", "address", True),
        ],
    ),
}

EventName = Literal[
    "ChannelOpened", "Settled", "TopUp", "CloseRequested", "ChannelClosed", "CloseRequestCancelled"
]

EVENT_TOPICS: dict[str, str] = {name: _topic(sig) for name, (sig, _) in _EVENTS.items()}
"""topic0 of each escrow event, by name."""


@dataclass(frozen=True, slots=True)
class ChannelStateTuple:
    """Raw packed channel state as the precompile returns it."""

    settled: int
    deposit: int
    close_requested_at: int


@dataclass(frozen=True, slots=True)
class DecodedEvent:
    """An escrow event decoded from a log. Addresses are checksummed, bytes32 0x-hex."""

    name: str
    args: dict[str, Any]


def _bytes32(value: str) -> bytes:
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError(f"expected 32 bytes, got {len(raw)}")
    return raw


def descriptor_tuple(descriptor: ChannelDescriptor) -> tuple[str, str, str, str, bytes, str, bytes]:
    """The descriptor as an ABI tuple value."""
    return (
        descriptor.payer,
        descriptor.payee,
        descriptor.operator,
        descriptor.token,
        _bytes32(descriptor.salt),
        descriptor.authorized_signer,
        _bytes32(descriptor.expiring_nonce_hash),
    )


def _descriptor_from_tuple(value: Sequence[Any]) -> ChannelDescriptor:
    from eth_utils.address import to_checksum_address

    return ChannelDescriptor(
        payer=to_checksum_address(value[0]),
        payee=to_checksum_address(value[1]),
        operator=to_checksum_address(value[2]),
        token=to_checksum_address(value[3]),
        salt="0x" + bytes(value[4]).hex(),
        authorized_signer=to_checksum_address(value[5]),
        expiring_nonce_hash="0x" + bytes(value[6]).hex(),
    )


def _hex(selector: bytes, types: list[str], args: list[Any]) -> str:
    return "0x" + (selector + encode(types, args)).hex()


def _signature_bytes(signature: str) -> bytes:
    return bytes.fromhex(signature.removeprefix("0x"))


def encode_open(
    *,
    payee: str,
    operator: str,
    token: str,
    deposit: int,
    salt: str,
    authorized_signer: str,
) -> str:
    """Calldata for `open(payee, operator, token, deposit, salt, authorizedSigner)`."""
    return _hex(
        SELECTORS["open"],
        ["address", "address", "address", "uint96", "bytes32", "address"],
        [payee, operator, token, uint96(deposit), _bytes32(salt), authorized_signer],
    )


def encode_top_up(descriptor: ChannelDescriptor, additional_deposit: int) -> str:
    """Calldata for `topUp(descriptor, additionalDeposit)`."""
    return _hex(
        SELECTORS["topUp"],
        [DESCRIPTOR_TYPE, "uint96"],
        [descriptor_tuple(descriptor), uint96(additional_deposit)],
    )


def encode_settle(descriptor: ChannelDescriptor, cumulative_amount: int, signature: str) -> str:
    """Calldata for `settle(descriptor, cumulativeAmount, signature)`."""
    return _hex(
        SELECTORS["settle"],
        [DESCRIPTOR_TYPE, "uint96", "bytes"],
        [descriptor_tuple(descriptor), uint96(cumulative_amount), _signature_bytes(signature)],
    )


def encode_close(
    descriptor: ChannelDescriptor, cumulative_amount: int, capture_amount: int, signature: str
) -> str:
    """Calldata for `close(descriptor, cumulativeAmount, captureAmount, signature)`."""
    return _hex(
        SELECTORS["close"],
        [DESCRIPTOR_TYPE, "uint96", "uint96", "bytes"],
        [
            descriptor_tuple(descriptor),
            uint96(cumulative_amount),
            uint96(capture_amount),
            _signature_bytes(signature),
        ],
    )


def encode_request_close(descriptor: ChannelDescriptor) -> str:
    """Calldata for `requestClose(descriptor)`."""
    return _hex(SELECTORS["requestClose"], [DESCRIPTOR_TYPE], [descriptor_tuple(descriptor)])


def encode_withdraw(descriptor: ChannelDescriptor) -> str:
    """Calldata for `withdraw(descriptor)`."""
    return _hex(SELECTORS["withdraw"], [DESCRIPTOR_TYPE], [descriptor_tuple(descriptor)])


def encode_get_channel(descriptor: ChannelDescriptor) -> str:
    """Calldata for `getChannel(descriptor)`."""
    return _hex(SELECTORS["getChannel"], [DESCRIPTOR_TYPE], [descriptor_tuple(descriptor)])


def encode_get_channel_state(channel_id: str) -> str:
    """Calldata for `getChannelState(channelId)`."""
    return _hex(SELECTORS["getChannelState"], ["bytes32"], [_bytes32(channel_id)])


def encode_get_channel_states_batch(channel_ids: Sequence[str]) -> str:
    """Calldata for `getChannelStatesBatch(channelIds)`."""
    return _hex(
        SELECTORS["getChannelStatesBatch"],
        ["bytes32[]"],
        [[_bytes32(channel_id) for channel_id in channel_ids]],
    )


def encode_compute_channel_id(descriptor: ChannelDescriptor) -> str:
    """Calldata for `computeChannelId(payer, payee, operator, token, salt, signer, hash)`."""
    return _hex(
        SELECTORS["computeChannelId"],
        ["address", "address", "address", "address", "bytes32", "address", "bytes32"],
        list(descriptor_tuple(descriptor)),
    )


def _result_bytes(data: str) -> bytes:
    return bytes.fromhex(data.removeprefix("0x"))


def decode_get_channel(data: str) -> tuple[ChannelDescriptor, ChannelStateTuple]:
    """Decode a `getChannel` result into its descriptor and state."""
    (value,) = decode([f"({DESCRIPTOR_TYPE},{STATE_TYPE})"], _result_bytes(data))
    descriptor, state = value
    return _descriptor_from_tuple(descriptor), ChannelStateTuple(*state)


def decode_get_channel_state(data: str) -> ChannelStateTuple:
    """Decode a `getChannelState` result."""
    (state,) = decode([STATE_TYPE], _result_bytes(data))
    return ChannelStateTuple(*state)


def decode_get_channel_states_batch(data: str) -> list[ChannelStateTuple]:
    """Decode a `getChannelStatesBatch` result."""
    (states,) = decode([f"{STATE_TYPE}[]"], _result_bytes(data))
    return [ChannelStateTuple(*state) for state in states]


def decode_bytes32(data: str) -> str:
    """Decode a single `bytes32` result as 0x-hex."""
    (value,) = decode(["bytes32"], _result_bytes(data))
    return "0x" + bytes(value).hex()


def decode_open(data: str) -> dict[str, Any]:
    """Decode `open` calldata; raises ValueError when it is not an `open` call."""
    args = _decode_call(
        data, "open", ["address", "address", "address", "uint96", "bytes32", "address"]
    )
    from eth_utils.address import to_checksum_address

    return {
        "payee": to_checksum_address(args[0]),
        "operator": to_checksum_address(args[1]),
        "token": to_checksum_address(args[2]),
        "deposit": int(args[3]),
        "salt": "0x" + bytes(args[4]).hex(),
        "authorizedSigner": to_checksum_address(args[5]),
    }


def decode_top_up(data: str) -> tuple[ChannelDescriptor, int]:
    """Decode `topUp` calldata into its descriptor and additional deposit."""
    args = _decode_call(data, "topUp", [DESCRIPTOR_TYPE, "uint96"])
    return _descriptor_from_tuple(args[0]), int(args[1])


def _decode_call(data: str, name: str, types: list[str]) -> tuple[Any, ...]:
    try:
        raw = bytes.fromhex(data.removeprefix("0x"))
    except ValueError as error:
        raise ValueError(f"Expected TIP-1034 {name} calldata.") from error
    if raw[:4] != SELECTORS[name]:
        raise ValueError(f"Expected TIP-1034 {name} calldata.")
    try:
        args = decode(types, raw[4:])
    except Exception as error:
        raise ValueError(f"Expected TIP-1034 {name} calldata.") from error
    # Reject trailing bytes and non-canonical encodings, like viem's decoder
    # combined with canonical re-encoding.
    if encode(types, list(args)) != raw[4:]:
        raise ValueError(f"Expected TIP-1034 {name} calldata.")
    return tuple(args)


def decode_event(topics: Sequence[str], data: str) -> DecodedEvent | None:
    """Decode an escrow event log, or return None when topic0 is not an escrow event."""
    from eth_utils.address import to_checksum_address

    if not topics:
        return None
    topic0 = topics[0].lower()
    for name, (_, inputs) in _EVENTS.items():
        if EVENT_TOPICS[name] != topic0:
            continue
        indexed = [item for item in inputs if item[2]]
        if len(topics) != len(indexed) + 1:
            return None
        args: dict[str, Any] = {}
        for (arg_name, arg_type, _), topic in zip(indexed, topics[1:], strict=True):
            (value,) = decode([arg_type], bytes.fromhex(topic.removeprefix("0x")))
            args[arg_name] = _normalize(arg_type, value, to_checksum_address)
        non_indexed = [item for item in inputs if not item[2]]
        values = decode([item[1] for item in non_indexed], _result_bytes(data))
        for (arg_name, arg_type, _), value in zip(non_indexed, values, strict=True):
            args[arg_name] = _normalize(arg_type, value, to_checksum_address)
        return DecodedEvent(name=name, args=args)
    return None


def _normalize(arg_type: str, value: Any, checksum: Any) -> Any:
    if arg_type == "address":
        return checksum(value)
    if arg_type == "bytes32":
        return "0x" + bytes(value).hex()
    return int(value)
