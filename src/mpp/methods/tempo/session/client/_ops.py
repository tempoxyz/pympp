"""Client-side TIP-1034 channel operations (mppx session/client/ChannelOps.ts).

Builds the open, top-up, voucher and close credential payloads that
``tempo.session()`` and the session manager send, and serializes them as
credentials bound to the payer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from mpp import Challenge, Credential
from mpp._typing import is_dict
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    ClosePayload,
    OpenPayload,
    TopUpPayload,
    VoucherPayload,
    uint96,
)
from mpp.methods.tempo.session._voucher import sign_close_authorization, sign_voucher

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.account import TempoAccount

SessionCredentialPayload = OpenPayload | TopUpPayload | VoucherPayload | ClosePayload


def is_same_address(a: str, b: str) -> bool:
    """Case-insensitive EVM address equality."""
    return a.lower() == b.lower()


def _is_address(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


def read_optional_address(value: object) -> str | None:
    """``value`` when it is a 0x-prefixed 20-byte hex address."""
    return value if isinstance(value, str) and _is_address(value) else None


def resolve_authorized_signer(account: TempoAccount) -> str:
    """The voucher authority address for a client account."""
    return account.address


def resolve_escrow(
    request: Mapping[str, Any],
    escrow_override: str | None = None,
    allow_custom_escrow: bool = False,
) -> str:
    """Resolve the server-advertised escrow against the client's trust policy.

    The canonical precompile is trusted unless ``escrow_override`` pins another
    address. A different escrow in the challenge is rejected unless
    ``allow_custom_escrow`` is set and no override is pinned.
    """
    details = request.get("methodDetails")
    challenge_escrow = (
        read_optional_address(details.get("escrowContract"))
        or read_optional_address(details.get("escrow"))
        if is_dict(details)
        else None
    )
    expected = escrow_override or ESCROW_ADDRESS
    if challenge_escrow and not is_same_address(challenge_escrow, expected):
        if not allow_custom_escrow or escrow_override is not None:
            raise ValueError(
                f"Tempo session escrow {challenge_escrow} does not match client escrow {expected}."
            )
        return challenge_escrow
    return expected


def serialize_credential(
    challenge: Challenge,
    payload: SessionCredentialPayload,
    chain_id: int,
    account: TempoAccount,
) -> str:
    """Serialize a session credential with a DID source bound to the payer account."""
    return Credential(
        challenge=challenge.to_echo(),
        payload=payload.to_wire(),
        source=f"did:pkh:eip155:{chain_id}:{account.address}",
    ).to_authorization()


def create_voucher_payload(
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    cumulative_amount: int,
    chain_id: int,
    escrow: str = ESCROW_ADDRESS,
) -> VoucherPayload:
    """Sign a voucher credential payload for an existing channel."""
    channel_id = compute_channel_id(descriptor, chain_id=chain_id, escrow=escrow)
    amount = uint96(cumulative_amount)
    signature = sign_voucher(
        account, channel_id=channel_id, cumulative_amount=amount, chain_id=chain_id, escrow=escrow
    )
    return VoucherPayload.model_validate(
        {
            "channelId": channel_id,
            "descriptor": descriptor.to_wire(),
            "cumulativeAmount": str(amount),
            "signature": signature,
        }
    )


def create_close_payload(
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    cumulative_amount: int,
    chain_id: int,
    escrow: str = ESCROW_ADDRESS,
) -> ClosePayload:
    """Sign a cooperative close credential payload: a voucher plus a close authorization."""
    voucher = create_voucher_payload(account, descriptor, cumulative_amount, chain_id, escrow)
    close_signature = sign_close_authorization(
        account,
        channel_id=voucher.channel_id,
        cumulative_amount=int(voucher.cumulative_amount),
        chain_id=chain_id,
        escrow=escrow,
    )
    return ClosePayload.model_validate(
        {
            "channelId": voucher.channel_id,
            "descriptor": descriptor.to_wire(),
            "cumulativeAmount": voucher.cumulative_amount,
            "signature": voucher.signature,
            "closeSignature": close_signature,
        }
    )


async def create_open_payload(
    account: TempoAccount,
    *,
    rpc_url: str,
    chain_id: int,
    deposit: int,
    initial_amount: int,
    payee: str,
    token: str,
    escrow: str = ESCROW_ADDRESS,
    operator: str | None = None,
    fee_payer: bool | None = None,
    fee_token: str | None = None,
    prefix_calls: Sequence[tuple[str, str]] = (),
    client: httpx.AsyncClient | None = None,
) -> OpenPayload:
    """Sign an expiring-nonce ``open`` transaction and the initial voucher.

    The descriptor binds the signed transaction's expiring nonce hash, as TIP-1034 requires.
    """
    raw_tx, descriptor, channel_id = await chain.build_open_transaction(
        account,
        rpc_url=rpc_url,
        payee=payee,
        token=token,
        deposit=uint96(deposit),
        chain_id=chain_id,
        escrow=escrow,
        operator=operator or ZERO_ADDRESS,
        authorized_signer=resolve_authorized_signer(account),
        fee_payer=bool(fee_payer),
        fee_token=fee_token,
        prefix_calls=prefix_calls,
        client=client,
    )
    amount = uint96(initial_amount)
    signature = sign_voucher(
        account, channel_id=channel_id, cumulative_amount=amount, chain_id=chain_id, escrow=escrow
    )
    return OpenPayload.model_validate(
        {
            "channelId": channel_id,
            "transaction": raw_tx,
            "signature": signature,
            "descriptor": descriptor.to_wire(),
            "cumulativeAmount": str(amount),
            "authorizedSigner": descriptor.authorized_signer,
        }
    )


async def create_top_up_payload(
    account: TempoAccount,
    descriptor: ChannelDescriptor,
    additional_deposit: int,
    *,
    rpc_url: str,
    chain_id: int,
    fee_payer: bool | None = None,
    escrow: str = ESCROW_ADDRESS,
    prefix_calls: Sequence[tuple[str, str]] = (),
    fee_token: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> TopUpPayload:
    """Sign an expiring-nonce ``topUp`` transaction adding ``additional_deposit``."""
    channel_id = compute_channel_id(descriptor, chain_id=chain_id, escrow=escrow)
    deposit = uint96(additional_deposit)
    raw_tx = await chain.build_top_up_transaction(
        account,
        descriptor,
        deposit,
        rpc_url=rpc_url,
        chain_id=chain_id,
        escrow=escrow,
        fee_payer=bool(fee_payer),
        fee_token=fee_token or descriptor.token,
        prefix_calls=prefix_calls,
        client=client,
    )
    return TopUpPayload.model_validate(
        {
            "channelId": channel_id,
            "transaction": raw_tx,
            "descriptor": descriptor.to_wire(),
            "additionalDeposit": str(deposit),
        }
    )
