"""Tempo accounts: root keys and access keys that sign for an account."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import attrs
from eth_account import Account as EthAccount
from pytempo import KeyAuthorization, Signature, SignedKeyAuthorization, TempoTransaction

from mpp.tempo._internal import remote_fee_payer as remote
from mpp.tempo._internal.address import is_address
from mpp.tempo._internal.envelope import sign_payload as transaction_sign_payload
from mpp.tempo._internal.proof import hash_typed_data
from mpp.tempo._internal.remote_fee_payer import RemoteFeePayer
from mpp.tempo._internal.signature import (
    KeychainVersion,
    PrimitiveSignature,
    SignatureEnvelope,
    keychain_sign_payload,
    keychain_signature,
    secp256k1_signature,
    serialize,
)

type AuthorizationKeyType = Literal["secp256k1", "p256", "webAuthn", "multisig"]


@dataclass(frozen=True, slots=True, kw_only=True)
class TempoAccount:
    """A local signer for a Tempo account.

    Root accounts sign directly. Access-key accounts sign on behalf of
    ``address`` and wrap their signature in a keychain envelope; with
    keychain ``v2`` they sign ``keccak256(0x04 || hash || address)``.
    """

    address: str
    """The account address (the parent account for access keys)."""
    key_type: AuthorizationKeyType
    sign_raw: Callable[[bytes], PrimitiveSignature]
    """Signs a 32-byte digest with the underlying key (no keychain wrapping)."""
    access_key_address: str | None = None
    keychain_version: KeychainVersion = "v2"

    @property
    def is_access_key(self) -> bool:
        return self.access_key_address is not None

    @property
    def signer_address(self) -> str:
        """The address that authorizes direct signatures (the access key, if any)."""
        return self.access_key_address or self.address

    def sign(self, digest: bytes, *, raw: bool = False) -> SignatureEnvelope:
        """Signs ``digest``; access keys return a keychain envelope unless ``raw``.

        Raises:
            ValueError: When ``digest`` is not 32 bytes.
        """
        if len(digest) != 32:
            raise ValueError(f"digest must be 32 bytes, got {len(digest)}")
        if raw or self.access_key_address is None:
            return self.sign_raw(digest)
        inner_digest = (
            keychain_sign_payload(digest, self.address) if self.keychain_version == "v2" else digest
        )
        return keychain_signature(
            user_address=self.address,
            inner=self.sign_raw(inner_digest),
            version=self.keychain_version,
        )

    def sign_transaction(self, transaction: TempoTransaction) -> TempoTransaction:
        """Returns the transaction with ``sender_address`` and ``sender_signature`` set."""
        signature = self.sign(transaction_sign_payload(transaction))
        return attrs.evolve(transaction, sender_address=self.address, sender_signature=signature)

    def sign_typed_data(self, typed_data: dict[str, Any]) -> str:
        """Signs EIP-712 typed data, returning a serialized signature envelope."""
        return serialize(self.sign(hash_typed_data(typed_data)))

    def sign_key_authorization(self, authorization: KeyAuthorization) -> SignedKeyAuthorization:
        """Signs a key authorization (access keys bind it to their parent account)."""
        if self.access_key_address is not None and authorization.account is None:
            authorization = attrs.evolve(authorization, account=self.address)
        signature = self.sign(authorization.signature_hash(), raw=True)
        if not isinstance(signature, Signature):
            raise TypeError("pytempo key authorizations require a secp256k1 signature.")
        return SignedKeyAuthorization(authorization=authorization, signature=signature)


def secp256k1_account(
    private_key: str,
    *,
    access: str | None = None,
    keychain_version: KeychainVersion = "v2",
) -> TempoAccount:
    """A secp256k1 account; with ``access`` it is an access key for that account.

    Raises:
        ValueError: When ``access`` is not a 0x-prefixed 20-byte hex address.
    """
    if access is not None and not is_address(access, strict=False):
        raise ValueError(f"access must be a 0x-prefixed 20-byte hex address: {access!r}")
    local = EthAccount.from_key(private_key)

    def sign_raw(digest: bytes) -> PrimitiveSignature:
        signed = local.unsafe_sign_hash(digest)
        return secp256k1_signature(r=signed.r, s=signed.s, y_parity=signed.v % 27)

    return TempoAccount(
        address=access or local.address,
        key_type="secp256k1",
        sign_raw=sign_raw,
        access_key_address=local.address if access else None,
        keychain_version=keychain_version,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedAccounts:
    account: TempoAccount | None
    fee_payer: TempoAccount | None
    remote_fee_payer: RemoteFeePayer | None
    recipient: str | None


def resolve(
    *,
    account: TempoAccount | str | None = None,
    recipient: str | None = None,
    fee_payer: TempoAccount | RemoteFeePayer | str | Literal[True] | None = None,
) -> ResolvedAccounts:
    """Resolves the recipient and fee payer from flexible method parameters.

    ``account`` may be an account or an address. ``fee_payer=True`` makes the
    account sponsor fees; a separate account or a remote fee-payer (a string is
    shorthand for its URL) can be given instead.
    """
    local_account = account if isinstance(account, TempoAccount) else None
    resolved_recipient = recipient or (local_account.address if local_account else account)
    return ResolvedAccounts(
        account=local_account,
        fee_payer=local_account
        if fee_payer is True
        else fee_payer
        if isinstance(fee_payer, TempoAccount)
        else None,
        remote_fee_payer=remote.from_value(fee_payer),
        recipient=resolved_recipient if isinstance(resolved_recipient, str) else None,
    )
