"""Session server test helpers: one channel driven through the real verification and chain code.

Client-signed transactions are built offline and answered by tests/test_session_chain.py's fake
JSON-RPC node, so open, top-up, voucher and close run through the real chain layer.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from mpp import Challenge, Credential
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ChannelDescriptor,
    ClosePayload,
    OpenPayload,
    SessionReceipt,
    TopUpPayload,
    VoucherPayload,
)
from mpp.methods.tempo.session._voucher import sign_close_authorization, sign_voucher
from mpp.methods.tempo.session.server import _verification as verification
from mpp.methods.tempo.session.server._store import ChannelState, from_store
from mpp.methods.tempo.session.server._verification import CredentialContext
from mpp.server import PaymentRequired, Request
from mpp.store import MemoryStore
from tests.test_session_chain import (
    CHAIN_ID,
    CURRENCY,
    DEPOSIT,
    PAYEE,
    PAYER,
    RPC,
    FakeRpc,
    event_log,
    opened_log,
)

SOURCE = f"did:pkh:eip155:{CHAIN_ID}:{PAYER.address}"


def make_challenge(amount: str = "100", **details: Any) -> Challenge:
    expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    return Challenge(
        id="challenge-1",
        method="tempo",
        intent="session",
        request={
            "amount": amount,
            "currency": CURRENCY,
            "recipient": PAYEE.address,
            "unitType": "request",
            "methodDetails": {
                "chainId": CHAIN_ID,
                "escrowContract": ESCROW_ADDRESS,
                "sessionProtocol": "v2",
                **details,
            },
        },
        expires=expires,
    )


def closed_log(descriptor: ChannelDescriptor, channel_id: str, paid: int, refund: int) -> Any:
    return event_log("ChannelClosed", descriptor, channel_id, ["uint96", "uint96"], [paid, refund])


def settled_log(descriptor: ChannelDescriptor, channel_id: str, amount: int, delta: int) -> Any:
    return event_log(
        "Settled", descriptor, channel_id, ["uint96", "uint96", "uint96"], [amount, delta, amount]
    )


def sign(channel_id: str, amount: int, account: Any = PAYER) -> str:
    return sign_voucher(account, channel_id=channel_id, cumulative_amount=amount, chain_id=CHAIN_ID)


def authorize(challenge: Challenge, payload: dict[str, Any]) -> dict[str, str]:
    credential = Credential(challenge=challenge.to_echo(), payload=payload, source=SOURCE)
    return {"Authorization": credential.to_authorization()}


async def challenge_for(handler: Any, request: Request) -> Challenge:
    result = await handler(request)
    assert isinstance(result, PaymentRequired), result
    return Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])


class Lifecycle:
    """One channel driven through the real verification and chain code by a fake node."""

    def __init__(self) -> None:
        self.rpc = FakeRpc()
        self.raw = MemoryStore()
        self.store = from_store(self.raw)
        self.descriptor: ChannelDescriptor
        self.channel_id = ""
        self.transaction = ""
        self.last_verified: dict[str, int] = {}

    async def build(self, **kwargs: Any) -> Lifecycle:
        self.transaction, self.descriptor, self.channel_id = await chain.build_open_transaction(
            PAYER,
            rpc_url=RPC,
            payee=PAYEE.address,
            token=CURRENCY,
            deposit=DEPOSIT,
            client=self.rpc.client,
            **kwargs,
        )
        return self

    def context(self, payload: Any, **overrides: Any) -> CredentialContext:
        fields: dict[str, Any] = {
            "challenge": make_challenge(),
            "payload": payload,
            "chain_id": CHAIN_ID,
            "escrow": ESCROW_ADDRESS,
            "rpc_url": RPC,
            "store": self.store,
            "account": PAYEE,
            "http_client": self.rpc.client,
            "credential_source": SOURCE,
            "last_on_chain_verified": self.last_verified,
        }
        fields.update(overrides)
        return CredentialContext(**fields)

    def open_payload(self, amount: int = 100, **overrides: Any) -> OpenPayload:
        wire: dict[str, Any] = {
            "action": "open",
            "type": "transaction",
            "channelId": self.channel_id,
            "transaction": self.transaction,
            "signature": sign(self.channel_id, amount),
            "descriptor": self.descriptor.to_wire(),
            "cumulativeAmount": str(amount),
        }
        wire.update(overrides)
        return OpenPayload.model_validate(wire)

    def voucher_payload(self, amount: int, **overrides: Any) -> VoucherPayload:
        wire: dict[str, Any] = {
            "action": "voucher",
            "channelId": self.channel_id,
            "descriptor": self.descriptor.to_wire(),
            "cumulativeAmount": str(amount),
            "signature": sign(self.channel_id, amount),
        }
        wire.update(overrides)
        return VoucherPayload.model_validate(wire)

    async def top_up_payload(self, amount: int = 500) -> TopUpPayload:
        raw = await chain.build_top_up_transaction(
            PAYER, self.descriptor, amount, rpc_url=RPC, client=self.rpc.client
        )
        return TopUpPayload.model_validate(
            {
                "action": "topUp",
                "type": "transaction",
                "channelId": self.channel_id,
                "transaction": raw,
                "descriptor": self.descriptor.to_wire(),
                "additionalDeposit": str(amount),
            }
        )

    def close_payload(self, amount: int, *, close_signer: Any = PAYER) -> ClosePayload:
        return ClosePayload.model_validate(
            {
                "action": "close",
                "channelId": self.channel_id,
                "descriptor": self.descriptor.to_wire(),
                "cumulativeAmount": str(amount),
                "signature": sign(self.channel_id, amount),
                "closeSignature": sign_close_authorization(
                    close_signer,
                    channel_id=self.channel_id,
                    cumulative_amount=amount,
                    chain_id=CHAIN_ID,
                ),
            }
        )

    async def open(self, amount: int = 100, **overrides: Any) -> SessionReceipt:
        self.rpc.logs = [opened_log(self.descriptor, self.channel_id)]
        return await verification.broadcast_credential_payload(
            self.context(self.open_payload(amount), **overrides)
        )

    async def accept(self, payload: Any, **overrides: Any) -> SessionReceipt:
        return await verification.broadcast_credential_payload(self.context(payload, **overrides))

    async def channel(self) -> ChannelState:
        channel = await self.store.get_channel(self.channel_id)
        assert channel is not None
        return channel

    async def update(self, **fields: Any) -> None:
        await self.store.update_channel(self.channel_id, lambda c: replace(c, **fields) if c else c)
