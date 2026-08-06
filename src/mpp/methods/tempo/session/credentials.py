"""Credential-provider seam for Tempo session transaction and voucher signing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from mpp.methods.tempo.account import TempoAccount


class SessionCredentialProvider(Protocol):
    """Minimal signer contract a private key or managed wallet can implement."""

    @property
    def payer_address(self) -> str: ...

    @property
    def signer_address(self) -> str: ...

    async def sign_transaction(self, transaction: Any) -> str:
        """Return a serialized sender-signed Tempo transaction."""
        ...

    async def sign_digest(self, digest: bytes) -> bytes:
        """Return a primitive 65-byte signature over a 32-byte digest."""
        ...


@dataclass(frozen=True, slots=True)
class TempoAccountCredentialProvider:
    """Current private-key implementation of :class:`SessionCredentialProvider`."""

    account: TempoAccount
    root_account: str | None = None

    @property
    def payer_address(self) -> str:
        return self.root_account or self.account.address

    @property
    def signer_address(self) -> str:
        return self.account.address

    async def sign_transaction(self, transaction: Any) -> str:
        if self.root_account:
            from pytempo import sign_tx_access_key

            signed = sign_tx_access_key(
                transaction,
                self.account.private_key,
                self.root_account,
            )
        else:
            signed = transaction.sign(self.account.private_key)
        return "0x" + signed.encode().hex()

    async def sign_digest(self, digest: bytes) -> bytes:
        return self.account.sign_hash(digest)
