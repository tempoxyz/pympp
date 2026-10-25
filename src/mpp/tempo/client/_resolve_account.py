"""Account selection hook for Tempo client credential operations."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import ClassVar

from pytempo import Call

from mpp.method import MaybeAwaitable
from mpp.tempo._internal.account import TempoAccount


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecuteCalls:
    """The selected account executes calls.

    ``calls`` is ``None`` when the calls depend on which account is selected
    (e.g. balance-dependent auto-swap routing).
    """

    calls: Sequence[Call] | None = None
    kind: ClassVar = "executeCalls"


@dataclass(frozen=True, slots=True, kw_only=True)
class SignPaymentProof:
    """The selected account signs a zero-amount payment proof without executing calls."""

    kind: ClassVar = "signPaymentProof"


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthorizePaymentChannel:
    """The selected account authorizes a payment channel.

    ``authority`` is the signer an existing reusable channel requires (``None``
    when opening a new channel or no signer is fixed yet).
    """

    authority: str | None = None
    kind: ClassVar = "authorizePaymentChannel"


type ResolveAccountOperation = ExecuteCalls | SignPaymentProof | AuthorizePaymentChannel
"""Capability an mpp-selected account must satisfy."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolveAccountInfo:
    """Account-resolution details for a client credential operation."""

    account: TempoAccount
    """Account mpp uses when the hook returns ``None``."""
    chain_id: int
    operation: ResolveAccountOperation


type ResolveAccount = Callable[[ResolveAccountInfo], MaybeAwaitable[TempoAccount | None]]
"""Selects the account that satisfies an operation (``None`` keeps the default account)."""
