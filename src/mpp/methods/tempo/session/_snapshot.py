"""Session snapshots (mppx ``tempo/session/Snapshot.ts``).

A snapshot is the server's view of a reusable channel: its descriptor, deposit, settled and spent
amounts and the highest voucher the payer signed. Servers advertise one in a session challenge's
``methodDetails.sessionSnapshot`` and in a bootstrap response's ``Payment-Session-Snapshot``
header (base64 JSON), so a client without local channel state can resume the channel instead of
opening a new one. Clients check it against the voucher signature and the chain before use.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mpp._typing import is_dict
from mpp.methods.tempo.session._protocol import ChannelDescriptor, SignedVoucher

if TYPE_CHECKING:
    import httpx

    from mpp.methods.tempo.session.client._store import ChannelEntry

__all__ = [
    "PAYMENT_SESSION_HEADER",
    "PAYMENT_SESSION_SNAPSHOT_HEADER",
    "SessionSnapshot",
    "deserialize_snapshot",
    "hydrate_session_snapshot",
    "serialize_snapshot",
]

PAYMENT_SESSION_HEADER = "Payment-Session"
"""Names the channel a bootstrap response (or a client request) refers to."""
PAYMENT_SESSION_SNAPSHOT_HEADER = "Payment-Session-Snapshot"
"""Carries a bootstrap response's serialized snapshot."""

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionSnapshot:
    """Server-provided reusable channel state (mppx ``SessionSnapshot``); amounts in raw units.

    Attributes:
        accepted_cumulative: Highest cumulative voucher amount the server accepted.
        chain_id: Tempo chain ID used to derive the channel ID and voucher domain.
        channel_id: TIP-1034 channel ID.
        deposit: Current on-chain deposit.
        descriptor: Full channel descriptor.
        escrow: Escrow address used to derive the channel ID.
        required_cumulative: Minimum cumulative authorization the next request needs.
        settled: Amount settled on-chain.
        spent: Amount consumed by delivered content.
        close_requested_at: When a close was requested, for a closing channel.
        highest_voucher: The payer's signed voucher for ``accepted_cumulative``.
        units: Paid units delivered, when reported.
    """

    accepted_cumulative: int
    chain_id: int
    channel_id: str
    deposit: int
    descriptor: ChannelDescriptor
    escrow: str
    required_cumulative: int
    settled: int
    spent: int
    close_requested_at: int | None = None
    highest_voucher: SignedVoucher | None = None
    units: int | None = None

    def to_wire(self) -> dict[str, Any]:
        """The camelCase JSON form mppx puts in challenges and headers."""
        wire: dict[str, Any] = {
            "acceptedCumulative": str(self.accepted_cumulative),
            "chainId": self.chain_id,
            "channelId": self.channel_id,
        }
        if self.close_requested_at is not None:
            wire["closeRequestedAt"] = str(self.close_requested_at)
        wire["deposit"] = str(self.deposit)
        wire["descriptor"] = self.descriptor.to_wire()
        wire["escrow"] = self.escrow
        if self.highest_voucher is not None:
            wire["highestVoucher"] = {
                "channelId": self.highest_voucher.channel_id,
                "cumulativeAmount": str(self.highest_voucher.cumulative_amount),
                "signature": self.highest_voucher.signature,
            }
        wire["requiredCumulative"] = str(self.required_cumulative)
        wire["settled"] = str(self.settled)
        wire["spent"] = str(self.spent)
        if self.units is not None:
            wire["units"] = self.units
        return wire

    @classmethod
    def from_wire(cls, value: Any) -> SessionSnapshot:
        """Parse and check the camelCase JSON form; raises ValueError when it is invalid."""
        if not is_dict(value):
            raise ValueError("session snapshot must be an object")
        try:
            descriptor = ChannelDescriptor.from_wire(value["descriptor"])
            for field in (
                descriptor.authorized_signer,
                descriptor.operator,
                descriptor.payee,
                descriptor.payer,
                descriptor.token,
            ):
                _match(_ADDRESS, field, "descriptor address")
            _match(_HASH, descriptor.salt, "descriptor salt")
            _match(_HASH, descriptor.expiring_nonce_hash, "descriptor expiringNonceHash")
            voucher: Any = value.get("highestVoucher")
            highest = None
            if voucher is not None:
                if not is_dict(voucher):
                    raise ValueError("session snapshot highestVoucher must be an object")
                highest = SignedVoucher(
                    channel_id=_match(_HASH, voucher["channelId"], "highestVoucher channelId"),
                    cumulative_amount=_amount(voucher["cumulativeAmount"]),
                    signature=_match(_HEX, voucher["signature"], "highestVoucher signature"),
                )
            close = value.get("closeRequestedAt")
            units = value.get("units")
            if units is not None and (not isinstance(units, int) or isinstance(units, bool)):
                raise ValueError("session snapshot units must be a number")
            chain_id = value["chainId"]
            if not isinstance(chain_id, int) or isinstance(chain_id, bool):
                raise ValueError("session snapshot chainId must be a number")
            return cls(
                accepted_cumulative=_amount(value["acceptedCumulative"]),
                chain_id=chain_id,
                channel_id=_match(_HASH, value["channelId"], "channelId"),
                deposit=_amount(value["deposit"]),
                descriptor=descriptor,
                escrow=_match(_ADDRESS, value["escrow"], "escrow"),
                required_cumulative=_amount(value["requiredCumulative"]),
                settled=_amount(value["settled"]),
                spent=_amount(value["spent"]),
                close_requested_at=_amount(close) if close is not None else None,
                highest_voucher=highest,
                units=units,
            )
        except KeyError as error:
            raise ValueError(f"session snapshot is missing {error.args[0]}") from error


def _match(pattern: re.Pattern[str], value: Any, label: str) -> str:
    if not isinstance(value, str) or pattern.match(value) is None:
        raise ValueError(f"invalid session snapshot {label}")
    return value


def _amount(value: Any) -> int:
    if not isinstance(value, str) or not value.isdigit() or not value.isascii():
        raise ValueError("session snapshot amounts must be decimal strings")
    return int(value)


def serialize_snapshot(snapshot: SessionSnapshot) -> str:
    """Serialize a snapshot for the ``Payment-Session-Snapshot`` header (base64 JSON)."""
    data = json.dumps(snapshot.to_wire(), separators=(",", ":"))
    return base64.b64encode(data.encode()).decode("ascii")


def deserialize_snapshot(value: str) -> SessionSnapshot:
    """Parse a ``Payment-Session-Snapshot`` header; raises ValueError when it is invalid."""
    try:
        text = value.strip()
        raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=False)
        decoded = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError) as error:
        raise ValueError("Invalid base64 JSON header.") from error
    return SessionSnapshot.from_wire(decoded)


async def hydrate_session_snapshot(
    account: Any,
    snapshot: SessionSnapshot,
    *,
    rpc_url: str,
    client: httpx.AsyncClient | None = None,
) -> tuple[ChannelEntry, int]:
    """Check a server snapshot and return the channel entry to cache and the server's spend.

    Mirrors mppx ``hydrateSessionSnapshot``: the highest voucher must match the accepted amount
    and carry the descriptor's voucher signer's signature, the descriptor must derive the
    snapshot's channel ID and belong to ``account``, and the channel must be open on-chain with a
    deposit covering the recovered cumulative amount.

    Raises:
        ValueError: The snapshot is inconsistent, not ``account``'s, or not reusable on-chain.
    """
    from mpp.methods.tempo.session import _chain as chain
    from mpp.methods.tempo.session._channel import compute_channel_id
    from mpp.methods.tempo.session._channel import (
        resolve_authorized_signer as resolve_descriptor_signer,
    )
    from mpp.methods.tempo.session._voucher import verify_voucher
    from mpp.methods.tempo.session.client._ops import is_same_address, resolve_authorized_signer
    from mpp.methods.tempo.session.client._store import ChannelEntry

    signed = snapshot.highest_voucher
    if signed is None:
        raise ValueError("session snapshot is missing its highest signed voucher")
    if signed.channel_id.lower() != snapshot.channel_id.lower():
        raise ValueError("session snapshot voucher channelId does not match snapshot channelId")
    if signed.cumulative_amount != snapshot.accepted_cumulative:
        raise ValueError("session snapshot voucher amount does not match acceptedCumulative")
    if snapshot.spent > snapshot.accepted_cumulative:
        raise ValueError("session snapshot spent exceeds acceptedCumulative")
    if snapshot.settled > snapshot.deposit:
        raise ValueError("session snapshot settled amount exceeds deposit")
    descriptor = snapshot.descriptor
    if not verify_voucher(
        snapshot.escrow, snapshot.chain_id, signed, resolve_descriptor_signer(descriptor)
    ):
        raise ValueError("session snapshot highest voucher signature is invalid")
    channel_id = compute_channel_id(descriptor, chain_id=snapshot.chain_id, escrow=snapshot.escrow)
    if channel_id.lower() != snapshot.channel_id.lower():
        raise ValueError("context channelId does not match descriptor")
    if not is_same_address(descriptor.payer, account.address):
        raise ValueError("context descriptor payer does not match account")
    if not is_same_address(
        resolve_descriptor_signer(descriptor), resolve_authorized_signer(account)
    ):
        raise ValueError("context descriptor authorizedSigner does not match account")
    state = await chain.get_channel_state(
        rpc_url, channel_id, escrow=snapshot.escrow, client=client
    )
    if state.deposit == 0:
        raise ValueError(f"Channel {channel_id} cannot be reused (closed or not found on-chain).")
    if state.close_requested_at != 0:
        raise ValueError(f"Channel {channel_id} cannot be reused (pending close request).")
    cumulative = max(snapshot.accepted_cumulative, snapshot.required_cumulative, state.settled)
    if cumulative > state.deposit:
        raise ValueError("recovered session cumulative amount exceeds on-chain channel deposit")
    entry = ChannelEntry(
        channel_id=channel_id,
        cumulative_amount=cumulative,
        deposit=state.deposit,
        descriptor=descriptor,
        escrow=snapshot.escrow,
        chain_id=snapshot.chain_id,
        opened=True,
    )
    return entry, snapshot.spent
