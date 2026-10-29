"""EVM charge: EIP-3009 authorizations for MPP and x402 clients.

``charge`` defines the ``evm/charge`` method. One intent verifies both native
Payment-auth ``evm/charge`` credentials and x402 ``exact`` payloads, and
settles either through an x402 facilitator or a custom ``settle`` hook.
"""

from __future__ import annotations

import heapq
import inspect
import logging
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, TypeAlias

from eth_utils.address import to_checksum_address
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator

from mpp import Credential, Receipt
from mpp._did import parse_pkh_source
from mpp._typing import is_list, is_mapping
from mpp._validation import Validation
from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    InvalidPayloadError,
    VerificationFailedError,
)
from mpp.methods import Method
from mpp.methods.evm._eip3009 import (
    authorization_domain,
    challenge_hash,
    network_of,
    recover_authorizer,
    to_source,
)
from mpp.store import MemoryStore
from mpp.x402._server import RouteBinding, is_x402_credential
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

logger = logging.getLogger(__name__)
_warned_fallback_store = False


class _ClaimCacheFull(Exception):
    """The in-process claim cache holds as many live claims as it may."""


class _ClaimCache(MemoryStore):
    """In-process claims that expire with their authorization.

    A claim only has to outlive its authorization's ``validBefore``: after that
    the authorization can't settle on-chain, and ``ChargeIntent`` caps how far in
    the future that can be. Expired claims are pruned from a heap on write, so
    memory is bounded by the payment rate times that window. Live claims, pending
    or settled, are never evicted: at ``max_entries`` the cache refuses new claims
    (the payment fails without a new challenge) rather than forget a payment and
    invite a second one. The heap is compacted when rolled-back claims leave
    stale entries in it.
    """

    def __init__(self, max_entries: int = 1_000_000) -> None:
        super().__init__()
        self._limit = max_entries
        self._expires: dict[str, float] = {}
        self._heap: list[tuple[float, str]] = []

    def claim_until(self, key: str, valid_before: int) -> None:
        expires = valid_before + 60
        self._expires[key] = expires
        heapq.heappush(self._heap, (expires, key))
        if len(self._heap) > 2 * len(self._expires) + 1024:
            self._heap = [(when, name) for name, when in self._expires.items()]
            heapq.heapify(self._heap)

    def _prune(self, now: float) -> None:
        while self._heap and self._heap[0][0] <= now:
            expires, key = heapq.heappop(self._heap)
            if self._expires.get(key) == expires:
                del self._expires[key]
                self._data.pop(key, None)

    async def put_if_absent(self, key: str, value: Any) -> bool:
        self._prune(time.time())
        if key in self._data:
            return False
        if len(self._data) >= self._limit:
            raise _ClaimCacheFull("in-process EVM claim cache is full; configure a store")
        self._data[key] = value
        return True

    async def delete(self, key: str) -> None:
        self._expires.pop(key, None)
        self._data.pop(key, None)


def _fallback_store() -> _ClaimCache:
    """Create the in-memory claim store used when no store is configured."""
    global _warned_fallback_store
    if not _warned_fallback_store:
        _warned_fallback_store = True
        logger.warning(
            "evm.charge has no store configured and is using an in-memory store. Replay "
            "protection is scoped to this process, so an authorization accepted by one "
            "worker or replica can be submitted again through another. Pass a shared "
            "store (e.g. mpp.stores.RedisStore) via evm.charge(store=...) when running "
            "more than one instance."
        )
    return _ClaimCache()


CREDENTIAL_TYPE = "authorization"
"""The only EVM charge credential type: an EIP-3009 authorization."""

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_SIGNATURE_RE = re.compile(r"0x[0-9a-fA-F]{130}")
# uint256 values have at most 78 digits; longer strings could not be parsed safely.
_ATOMIC_RE = re.compile(r"[0-9]{1,78}")
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
    if not is_mapping(payload):
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


class AuthorizationPayload(BaseModel):
    """The native ``authorization`` credential payload: a signed EIP-3009 transfer."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    type: Literal["authorization"]
    from_: str = Field(alias="from")
    to: str
    value: str
    valid_after: str = Field(alias="validAfter")
    valid_before: str = Field(alias="validBefore")
    nonce: str
    signature: str

    @model_validator(mode="before")
    @classmethod
    def _check(cls, data: Any) -> dict[str, Any]:
        return _parse_authorization_payload(data)


class MethodDetails(BaseModel):
    """EVM details of a charge request."""

    model_config = ConfigDict(populate_by_name=True)

    chain_id: StrictInt = Field(alias="chainId")
    credential_types: list[StrictStr] = Field(alias="credentialTypes")
    decimals: StrictInt


class ChargeRequest(BaseModel):
    """The wire ``evm/charge`` request: atomic amount and checksummed addresses."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    amount: str = Field(pattern=r"^[0-9]{1,78}$")
    currency: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    recipient: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    method_details: MethodDetails = Field(alias="methodDetails")
    extra: dict[str, str] | None = None
    external_id: str | None = Field(default=None, alias="externalId")


charge: Method[ChargeRequest, AuthorizationPayload] = Method(
    name="evm",
    intent="charge",
    request_model=ChargeRequest,
    payload_model=AuthorizationPayload,
)
"""The native Payment-auth ``evm/charge`` method."""


def _timestamp(value: str | None) -> int:
    """Return an ISO 8601 instant as Unix seconds, or 0 when absent or invalid."""
    if not value:
        return 0
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return int(parsed.timestamp()) if parsed.tzinfo is not None else 0


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
        route_binding: How x402 payments bind to scoped routes, as in mppx.
            ``"required"`` accepts only payments carrying mppx's route binding on
            routes with a framework scope, body digest or metadata;
            ``"resource"`` also accepts payments bound by their echoed terms and
            resource URL, which other x402 clients send.
        max_validity_seconds: Longest an x402 authorization may stay valid from
            now (default one hour); longer-lived ones are rejected. Native
            credentials may also run to their challenge's expiry.
        store: Optional store that claims each authorization before
            settlement so concurrent requests can't settle it twice.
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
        route_binding: RouteBinding = "required",
        store: Store | None = None,
        max_validity_seconds: int = 3600,
    ) -> None:
        if facilitator is None and settle is None:
            raise ValueError("EVM charge requires a facilitator or a settle hook")
        if isinstance(max_timeout_seconds, bool) or not isinstance(max_timeout_seconds, int):
            raise ValueError("max_timeout_seconds must be an integer")
        if max_timeout_seconds <= 0:
            raise ValueError("max_timeout_seconds must be positive")
        if (
            isinstance(max_validity_seconds, bool)
            or not isinstance(max_validity_seconds, int)
            or max_validity_seconds < max_timeout_seconds
        ):
            raise ValueError("max_validity_seconds must be an integer >= max_timeout_seconds")
        self.max_validity_seconds = max_validity_seconds
        if route_binding not in ("required", "resource"):
            raise ValueError("route_binding must be 'required' or 'resource'")
        self.route_binding: RouteBinding = route_binding
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
        chain_id = details.get("chainId") if is_mapping(details) else None
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
        raw_details = request.get("methodDetails")
        details: Mapping[str, Any] = raw_details if is_mapping(raw_details) else {}
        chain_id = self._chain_id(request)

        credential_types = details.get("credentialTypes")
        if not is_list(credential_types) or CREDENTIAL_TYPE not in credential_types:
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
        # The payer picks validBefore; cap it so claims (and an authorization a
        # facilitator holds) can't stay live indefinitely. A native credential
        # may run to its challenge's expiry, which the server set and HMAC-binds.
        limit = now + self.max_validity_seconds
        if not is_x402_credential(credential):
            limit = max(limit, _timestamp(credential.challenge.expires))
        if int(payload["validBefore"]) > limit:
            raise VerificationFailedError("EVM authorization is valid for too long")

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

        # A claimed authorization was settled (or is settling) already. Report it
        # as a replay (403) before the facilitator calls it unpayable, so clients
        # aren't offered a fresh challenge and invited to pay twice.
        claim = self._claim_key(payload, request)
        if self._store is not None and await self._store.get(claim) is not None:
            raise CredentialReplayedError("EVM authorization has already been used")

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
        if self._store is None:
            self._store = _fallback_store()
        try:
            claimed = await self._store.put_if_absent(claim_key, "pending")
        except _ClaimCacheFull as error:
            # Refuse without a new challenge rather than forget a live claim.
            raise InternalPaymentError() from error
        if not claimed:
            raise CredentialReplayedError("EVM authorization has already been used")
        if isinstance(self._store, _ClaimCache):
            self._store.claim_until(claim_key, int(payload["validBefore"]))

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
            if settled.get("errorReason") == "settlement_pending":
                # The transfer was broadcast and may still confirm: keep the claim
                # and answer without a retry challenge so the payer isn't charged twice.
                raise InternalPaymentError() from FacilitatorError(
                    "facilitator settlement is pending"
                )
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
