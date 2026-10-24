"""EVM charge intent: EIP-3009 authorizations for MPP and x402 clients.

Port of mppx's ``src/evm/server/Charge.ts`` and the x402 path in
``src/x402/server/EvmCharge.ts``. One intent verifies both native
Payment-auth ``evm/charge`` credentials and x402 ``exact`` payloads, and
settles either through an x402 facilitator or a custom ``settle`` hook.
"""

from __future__ import annotations

import inspect
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeAlias

from eth_utils.address import to_checksum_address

from mpp import Credential, Receipt
from mpp._did import parse_pkh_source
from mpp._validation import Validation
from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    InvalidPayloadError,
    VerificationFailedError,
)
from mpp.methods.evm._eip3009 import (
    authorization_domain,
    challenge_hash,
    network_of,
    recover_authorizer,
    to_source,
)
from mpp.x402._server import is_x402_credential
from mpp.x402._types import (
    EIP3009,
    EXACT_SCHEME,
    X402_VERSION,
    PaymentPayload,
    PaymentRequirements,
    X402FormatError,
    parse_eip3009_payload,
)
from mpp.x402.facilitator import Facilitator, FacilitatorError

if TYPE_CHECKING:
    from mpp.store import Store

CREDENTIAL_TYPE = "authorization"
"""The only EVM charge credential type: an EIP-3009 authorization."""

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_SIGNATURE_RE = re.compile(r"0x[0-9a-fA-F]{130}")
_ATOMIC_RE = re.compile(r"[0-9]+")
_UINT256_MAX = 2**256 - 1


@dataclass(frozen=True, slots=True)
class Authorization:
    """A verified EIP-3009 authorization passed to a custom ``settle`` hook.

    Attributes:
        credential: The credential that carried the authorization.
        payload: The native ``authorization`` payload.
        request: The canonical charge request it pays.
        source: The payer's ``did:pkh`` source.
    """

    credential: Credential
    payload: dict[str, Any]
    request: dict[str, Any]
    source: str


SettleFn: TypeAlias = Callable[[Authorization], str | Awaitable[str]]
"""Settles a verified authorization and returns its reference (a transaction hash)."""


def _parse_authorization_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise InvalidPayloadError("EVM charge payload must be an object")
    if payload.get("type") != CREDENTIAL_TYPE:
        raise InvalidPayloadError("EVM charge payload type must be 'authorization'")
    for key, pattern in (
        ("from", _ADDRESS_RE),
        ("to", _ADDRESS_RE),
        ("nonce", _HASH_RE),
        ("signature", _SIGNATURE_RE),
        ("value", _ATOMIC_RE),
        ("validAfter", _ATOMIC_RE),
        ("validBefore", _ATOMIC_RE),
    ):
        value = payload.get(key)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise InvalidPayloadError(f"EVM charge payload {key} is malformed")
    for key in ("value", "validAfter", "validBefore"):
        if int(payload[key]) > _UINT256_MAX:
            raise InvalidPayloadError(f"EVM charge payload {key} is out of range")
    return dict(payload)


def _same_address(left: Any, right: Any) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.lower() == right.lower()


class ChargeIntent:
    """Verify and settle EVM charges paid with EIP-3009 authorizations.

    Created by :func:`mpp.methods.evm.evm`; most servers don't construct it
    directly.

    Args:
        name: EIP-712 domain name of the token's authorizations.
        version: EIP-712 domain version of the token's authorizations.
        facilitator: x402 facilitator that verifies and settles payments.
        settle: Custom settlement hook. When set, the facilitator is not used,
            and the hook is responsible for chain-state checks and replay
            protection beyond this intent's store claim.
        max_timeout_seconds: x402 ``maxTimeoutSeconds`` advertised to clients.
        store: Optional store that claims each authorization before
            settlement so concurrent requests can't settle it twice.
            ``Mpp.create(store=...)`` wires it automatically.
    """

    name = "charge"

    def __init__(
        self,
        *,
        name: str,
        version: str,
        facilitator: Facilitator | None = None,
        settle: SettleFn | None = None,
        max_timeout_seconds: int = 300,
        store: Store | None = None,
    ) -> None:
        if facilitator is None and settle is None:
            raise ValueError("EVM charge requires a facilitator or a settle hook")
        if isinstance(max_timeout_seconds, bool) or not isinstance(max_timeout_seconds, int):
            raise ValueError("max_timeout_seconds must be an integer")
        if max_timeout_seconds <= 0:
            raise ValueError("max_timeout_seconds must be positive")
        self.domain_name = name
        self.domain_version = version
        self.facilitator = facilitator
        self.settle = settle
        self.max_timeout_seconds = max_timeout_seconds
        self._store = store

    # -- request helpers -------------------------------------------------

    @staticmethod
    def _chain_id(request: Mapping[str, Any]) -> int:
        details = request.get("methodDetails")
        chain_id = details.get("chainId") if isinstance(details, Mapping) else None
        if isinstance(chain_id, bool) or not isinstance(chain_id, int):
            raise VerificationFailedError("EVM charge request is missing methodDetails.chainId")
        return chain_id

    def _domain(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return authorization_domain(
            name=self.domain_name,
            version=self.domain_version,
            chain_id=self._chain_id(request),
            currency=request["currency"],
        )

    def x402_requirements(self, request: dict[str, Any]) -> PaymentRequirements:
        """Return the x402 ``exact`` requirements that pay a charge request."""
        return {
            "scheme": EXACT_SCHEME,
            "network": network_of(self._chain_id(request)),
            "amount": request["amount"],
            "asset": to_checksum_address(request["currency"]),
            "payTo": to_checksum_address(request["recipient"]),
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": {
                "assetTransferMethod": EIP3009,
                "name": self.domain_name,
                "version": self.domain_version,
            },
        }

    def x402_credential_payload(
        self, payment: PaymentPayload, request: dict[str, Any]
    ) -> tuple[dict[str, Any], str | None]:
        """Convert an x402 EIP-3009 payload to the native authorization payload."""
        body = payment["payload"]
        if not isinstance(body.get("authorization"), Mapping):
            raise VerificationFailedError(
                "EVM charge only supports x402 EIP-3009 authorization payloads"
            )
        try:
            parsed = parse_eip3009_payload(body)
        except X402FormatError as error:
            raise InvalidPayloadError(str(error)) from error
        authorization = parsed["authorization"]
        payload = {
            "type": CREDENTIAL_TYPE,
            "from": authorization["from"],
            "to": authorization["to"],
            "value": authorization["value"],
            "validAfter": authorization["validAfter"],
            "validBefore": authorization["validBefore"],
            "nonce": authorization["nonce"],
            "signature": parsed["signature"],
        }
        return payload, to_source(address=authorization["from"], chain_id=self._chain_id(request))

    def _facilitator_payment(
        self, payload: Mapping[str, Any], request: dict[str, Any]
    ) -> tuple[PaymentPayload, PaymentRequirements]:
        requirements = self.x402_requirements(request)
        payment: PaymentPayload = {
            "x402Version": X402_VERSION,
            "accepted": requirements,
            "payload": {
                "authorization": {
                    "from": payload["from"],
                    "to": payload["to"],
                    "value": payload["value"],
                    "validAfter": payload["validAfter"],
                    "validBefore": payload["validBefore"],
                    "nonce": payload["nonce"],
                },
                "signature": payload["signature"],
            },
        }
        return payment, requirements

    # -- verification ----------------------------------------------------

    async def validate(self, credential: Credential, request: dict[str, Any]) -> Validation:
        """Check an authorization without settling it.

        Checks the payment terms, validity window, challenge binding and
        signature locally, then asks the facilitator (when it settles) whether
        the authorization is still payable.
        """
        payload = _parse_authorization_payload(credential.payload)
        details = request.get("methodDetails")
        details = details if isinstance(details, Mapping) else {}
        chain_id = self._chain_id(request)

        credential_types = details.get("credentialTypes")
        if not isinstance(credential_types, list) or CREDENTIAL_TYPE not in credential_types:
            raise VerificationFailedError(
                "EVM authorization credentials are not supported for this challenge"
            )
        if details.get("splits"):
            raise VerificationFailedError("EVM authorization credentials do not support splits")
        if not _same_address(payload["to"], request.get("recipient")):
            raise VerificationFailedError("EVM authorization recipient mismatch")
        if payload["value"] != request.get("amount"):
            raise VerificationFailedError("EVM authorization amount mismatch")
        if not is_x402_credential(credential):
            expected_nonce = challenge_hash(credential.challenge.id, credential.challenge.realm)
            if payload["nonce"].lower() != expected_nonce:
                raise VerificationFailedError("EVM authorization challenge hash mismatch")

        now = int(time.time())
        if int(payload["validAfter"]) > now:
            raise VerificationFailedError("EVM authorization is not valid yet")
        if int(payload["validBefore"]) <= now:
            raise VerificationFailedError("EVM authorization has expired")

        try:
            signer = recover_authorizer(
                domain=self._domain(request), payload=payload, signature=payload["signature"]
            )
        except Exception as error:
            raise VerificationFailedError("EVM authorization signature is invalid") from error
        if not _same_address(signer, payload["from"]):
            raise VerificationFailedError("EVM authorization signature mismatch")

        payer = to_checksum_address(payload["from"])
        if credential.source is not None:
            source = parse_pkh_source(credential.source)
            if (
                source is None
                or source.chain_id != chain_id
                or not _same_address(source.address, payer)
            ):
                raise VerificationFailedError("EVM authorization source mismatch")

        if self.settle is None and self.facilitator is not None:
            payment, requirements = self._facilitator_payment(payload, request)
            try:
                verified = await self.facilitator.verify(payment, requirements)
            except FacilitatorError as error:
                raise InternalPaymentError() from error
            if not verified["isValid"]:
                reason = (
                    verified.get("invalidMessage")
                    or verified.get("invalidReason")
                    or "EVM facilitator verify failed"
                )
                raise VerificationFailedError(reason)

        return Validation(
            credential=credential,
            details={"payer": payer},
            intent=self.name,
            request=request,
            payer=payer,
        )

    def _claim_key(self, payload: Mapping[str, Any], request: Mapping[str, Any]) -> str:
        return ":".join(
            (
                "mpp:evm:authorization",
                str(self._chain_id(request)),
                str(request["currency"]).lower(),
                str(payload["from"]).lower(),
                str(payload["nonce"]).lower(),
            )
        )

    async def broadcast(self, credential: Credential, request: dict[str, Any]) -> Receipt:
        """Settle a validated authorization and return its receipt."""
        payload = _parse_authorization_payload(credential.payload)
        payer = to_checksum_address(payload["from"])
        claim_key = self._claim_key(payload, request)
        if self._store is not None and not await self._store.put_if_absent(claim_key, "pending"):
            raise CredentialReplayedError("EVM authorization has already been used")

        try:
            reference = await self._settle(credential, payload, request)
        except (VerificationFailedError, InvalidPayloadError):
            # Nothing settled: let the payer retry with the same authorization.
            if self._store is not None:
                await self._store.delete(claim_key)
            raise
        if self._store is not None:
            await self._store.put(claim_key, reference)

        return Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference=reference,
            method="evm",
            payer=payer,
        )

    async def _settle(
        self, credential: Credential, payload: dict[str, Any], request: dict[str, Any]
    ) -> str:
        if self.settle is not None:
            authorization = Authorization(
                credential=credential,
                payload=payload,
                request=request,
                source=to_source(address=payload["from"], chain_id=self._chain_id(request)),
            )
            reference = self.settle(authorization)
            if inspect.isawaitable(reference):
                reference = await reference
            if not isinstance(reference, str) or not reference:
                raise InternalPaymentError() from TypeError(
                    "settle hook must return a non-empty reference string"
                )
            return reference

        assert self.facilitator is not None
        payment, requirements = self._facilitator_payment(payload, request)
        try:
            settled = await self.facilitator.settle(payment, requirements)
        except FacilitatorError as error:
            # The facilitator may have broadcast the transfer before failing.
            raise InternalPaymentError() from error
        if not settled["success"]:
            reason = (
                settled.get("errorMessage")
                or settled.get("errorReason")
                or "EVM facilitator settlement failed"
            )
            raise VerificationFailedError(reason)
        if not settled["transaction"]:
            raise InternalPaymentError() from ValueError(
                "facilitator reported success without a transaction"
            )
        return settled["transaction"]
