"""MPP payments on routes an official x402 resource server protects.

The official x402 integration keeps x402 credentials, hooks and post-handler
settlement. The negotiator answers MPP credentials with a native ``evm/charge``
backed by the route's x402 requirement, verifier and facilitator, and adds an
MPP challenge to unpaid x402 responses.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from eth_utils.address import to_checksum_address
from x402.http.facilitator_client_base import FacilitatorResponseError
from x402.http.types import (
    HTTPRequestContext,
    HTTPResponseInstructions,
    HTTPTransportContext,
    PaywallConfig,
    RoutesConfig,
)
from x402.http.utils import decode_payment_required_header
from x402.http.x402_http_server import PaywallProvider, x402HTTPResourceServer
from x402.schemas import PaymentPayload, PaymentRequired, PaymentRequirements
from x402.schemas.hooks import SkipHandlerDirective
from x402.server import x402ResourceServer

from mpp import _expires
from mpp.errors import InternalPaymentError, VerificationFailedError
from mpp.methods.evm import server as evm
from mpp.methods.evm.client import AuthorizationConfig
from mpp.methods.evm.intents import Authorization, _fallback_store
from mpp.server.http import PaymentVerified, Request, Response, make_headers
from mpp.server.mpp import Mpp
from mpp.store import Store
from mpp.x402._types import EIP3009, PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER

LEGACY_PAYMENT_SIGNATURE_HEADER = "X-PAYMENT"

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_DIGITS = re.compile(r"[0-9]+")
_EVM_NETWORK_PREFIX = "eip155:"
_MAX_SAFE_INTEGER = 2**53 - 1


@dataclass(frozen=True, slots=True)
class Negotiation:
    """What to do with a request before the official x402 middleware runs.

    ``unprotected``: run the handler. ``x402``: delegate to the official middleware.
    ``handled``: return ``response``. ``paid``: run the handler, then attach the
    receipt with ``payment.with_receipt``.
    """

    status: Literal["handled", "paid", "unprotected", "x402"]
    response: Response | None = None
    payment: PaymentVerified | None = None


class Negotiator:
    """Selects MPP, x402 or an immediate response for requests to x402 routes.

    Args:
        routes: The x402 route configuration.
        server: The x402 resource server that prices, verifies and settles payments.
        secret_key: Secret binding MPP challenge IDs (at least 32 bytes).
        realm: MPP challenge realm. Detected from the environment if omitted.
        paywall_config: Optional x402 paywall configuration.
        paywall_provider: Optional x402 paywall provider for unpaid browser requests.
        store: Store claiming MPP authorizations before settlement, shared by every
            worker and replica. Defaults to an in-process store whose claims expire
            with their authorization.
    """

    def __init__(
        self,
        routes: RoutesConfig,
        server: x402ResourceServer,
        *,
        secret_key: str,
        realm: str | None = None,
        paywall_config: PaywallConfig | None = None,
        paywall_provider: PaywallProvider | None = None,
        store: Store | None = None,
    ) -> None:
        if len(secret_key.encode()) < 32:
            raise ValueError("secret_key must contain at least 32 bytes")
        self.server = server
        self.secret_key = secret_key
        self.realm = realm
        self.paywall_config = paywall_config
        self.store: Store = store if store is not None else _fallback_store()
        self.http_server = x402HTTPResourceServer(server, routes)
        if paywall_provider is not None:
            self.http_server.register_paywall_provider(paywall_provider)
        self._initialized = False
        self._initialize_lock = asyncio.Lock()

    async def negotiate(self, request: Request, context: HTTPRequestContext) -> Negotiation:
        if not self.http_server.requires_payment(context):
            return Negotiation("unprotected")
        if _has_mpp_credential(request) and x402_credential(request):
            return Negotiation(
                "handled",
                Response.json(
                    {
                        "error": "Send either an MPP credential or an x402 payment "
                        "signature, not both."
                    },
                    status=400,
                ),
            )
        try:
            await self._initialize()
            if x402_credential(request):
                return Negotiation("x402")
            result = await self.http_server.process_http_request(
                dataclasses.replace(context, payment_header=None), self.paywall_config
            )
            if result.type == "no-payment-required":
                return Negotiation("unprotected")
            if result.type != "payment-error" or result.response is None:
                raise RuntimeError(f"Expected x402 payment response, received {result.type}.")
            unpaid = _response_from_instructions(result.response)
            payment_required = _payment_required(result.response)
            if payment_required is None:
                return Negotiation("handled", unpaid)
            return await self._pay(request, context, payment_required, unpaid)
        except Exception as error:
            facilitator_error = _facilitator_error(error)
            if facilitator_error is None:
                raise
            return Negotiation(
                "handled", Response.json({"error": str(facilitator_error)}, status=502)
            )

    async def _initialize(self) -> None:
        # x402's initialize fetches facilitator support synchronously: run it off
        # the event loop, once for concurrent requests, and retry on the next
        # protected request when it fails.
        if self._initialized:
            return
        async with self._initialize_lock:
            if not self._initialized:
                await asyncio.to_thread(self.http_server.initialize)
                self._initialized = True

    async def _pay(
        self,
        request: Request,
        context: HTTPRequestContext,
        payment_required: PaymentRequired,
        unpaid: Response,
    ) -> Negotiation:
        requirement = select_requirement(payment_required, self.server)
        chain_id = parse_chain_id(requirement.network) if requirement is not None else None
        if requirement is None or chain_id is None:
            return Negotiation("handled", unpaid)
        decimals = _asset_decimals(self.server, requirement)
        skipped: list[Response] = []

        async def settle(authorization: Authorization) -> str:
            reference, skip_handler = await _settle(
                self.server, context, authorization.payload, payment_required, requirement
            )
            if skip_handler is not None:
                skipped.append(_response_from_skip_handler(skip_handler))
            return reference

        # Only advertise a native rail the selected x402 scheme can verify and
        # settle: an EIP-3009 authorization.
        method = evm.charge(
            currency=to_checksum_address(requirement.asset),
            recipient=to_checksum_address(requirement.pay_to),
            chain_id=chain_id,
            decimals=decimals,
            authorization=AuthorizationConfig(
                name=requirement.extra["name"], version=requirement.extra["version"]
            ),
            settle=settle,
            store=self.store,
        )
        payment = Mpp(methods=method, realm=self.realm, secret_key=self.secret_key)
        resource = payment_required.resource
        result = await payment.evm.charge(
            amount=_format_units(int(requirement.amount), decimals),
            description=(resource.description if resource else None) or None,
            expires=_expires.seconds(requirement.max_timeout_seconds),
        )(request)
        if isinstance(result, PaymentVerified):
            if skipped:
                return Negotiation("handled", result.with_receipt(skipped[0]))
            return Negotiation("paid", payment=result)
        if result.status != 402:
            return Negotiation("handled", result.challenge)
        return Negotiation("handled", _merge_challenge(result.challenge, unpaid))


def x402_credential(request: Request) -> str | None:
    """The request's x402 credential: ``PAYMENT-SIGNATURE``, or legacy ``X-PAYMENT``."""
    return (
        request.headers.get(PAYMENT_SIGNATURE_HEADER)
        or request.headers.get(LEGACY_PAYMENT_SIGNATURE_HEADER)
        or None
    )


def _has_mpp_credential(request: Request) -> bool:
    authorization = request.headers.get("authorization") or ""
    return any(part.strip().lower().startswith("payment ") for part in authorization.split(","))


def select_requirement(
    payment_required: PaymentRequired, server: x402ResourceServer
) -> PaymentRequirements | None:
    """The first extension-free EIP-3009 requirement a native charge represents exactly."""
    if payment_required.extensions:
        return None
    for requirement in payment_required.accepts:
        if requirement.scheme != "exact" or parse_chain_id(requirement.network) is None:
            continue
        extra = requirement.extra or {}
        transfer_method = extra.get("assetTransferMethod")
        if transfer_method is None:
            scheme = server.get_registered_scheme(requirement.network, requirement.scheme)
            transfer_method = getattr(scheme, "default_asset_transfer_method", None)
        if (
            transfer_method == EIP3009
            and _ADDRESS.fullmatch(requirement.asset)
            and _ADDRESS.fullmatch(requirement.pay_to)
            and isinstance(extra.get("name"), str)
            and isinstance(extra.get("version"), str)
            and _DIGITS.fullmatch(requirement.amount)
        ):
            return requirement
    return None


def parse_chain_id(network: str) -> int | None:
    """The positive chain ID of a CAIP-2 ``eip155:`` network."""
    if not network.startswith(_EVM_NETWORK_PREFIX):
        return None
    reference = network[len(_EVM_NETWORK_PREFIX) :]
    if not _DIGITS.fullmatch(reference):
        return None
    chain_id = int(reference)
    return chain_id if 0 < chain_id <= _MAX_SAFE_INTEGER else None


def _asset_decimals(server: x402ResourceServer, requirement: PaymentRequirements) -> int:
    scheme = server.get_registered_scheme(requirement.network, requirement.scheme)
    get_decimals = getattr(scheme, "get_asset_decimals", None)
    decimals = get_decimals(requirement.asset, requirement.network) if get_decimals else None
    return decimals if isinstance(decimals, int) else 6


def _format_units(value: int, decimals: int) -> str:
    whole, fraction = divmod(value, 10**decimals)
    if not fraction:
        return str(whole)
    return f"{whole}.{str(fraction).rjust(decimals, '0').rstrip('0')}"


async def _settle(
    server: x402ResourceServer,
    context: HTTPRequestContext,
    payload: dict[str, Any],
    payment_required: PaymentRequired,
    requirement: PaymentRequirements,
) -> tuple[str, SkipHandlerDirective | None]:
    """Verify and settle an MPP authorization through the x402 resource server."""
    payment = PaymentPayload(
        x402_version=2,
        accepted=requirement,
        payload={
            "authorization": {
                key: payload[key]
                for key in ("from", "nonce", "to", "validAfter", "validBefore", "value")
            },
            "signature": payload["signature"],
        },
        resource=payment_required.resource,
    )
    transport = HTTPTransportContext(request=context)
    try:
        verified = await server.verify_payment(
            payment,
            requirement,
            declared_extensions=payment_required.extensions,
            transport_context=transport,
        )
    except Exception as error:
        # Nothing was broadcast: release the claim so the authorization isn't lost.
        raise VerificationFailedError("x402 verification failed") from error
    if not verified.is_valid:
        raise VerificationFailedError(
            verified.verify.invalid_message
            or verified.verify.invalid_reason
            or "x402 verification failed"
        )
    settled = await server.settle_payment(
        payment,
        requirement,
        declared_extensions=payment_required.extensions,
        transport_context=transport,
    )
    if not settled.success:
        if settled.error_reason == "settlement_pending":
            # The transfer was broadcast and may still confirm: keep the claim and
            # answer without a retry challenge so the payer isn't charged twice.
            raise InternalPaymentError() from RuntimeError("x402 settlement is pending")
        raise VerificationFailedError(
            settled.error_message or settled.error_reason or "x402 settlement failed"
        )
    return settled.transaction, verified.skip_handler


def _response_from_skip_handler(directive: SkipHandlerDirective) -> Response:
    content_type = directive.content_type or "application/json"
    value: Any = directive.body if directive.body is not None else {}
    if "json" in content_type.lower():
        body = json.dumps(value, separators=(",", ":")).encode()
    else:
        body = value if isinstance(value, bytes) else str(value).encode()
    return Response(
        status=200,
        headers={"Cache-Control": "private, no-store", "Content-Type": content_type},
        body=body,
    )


def _response_from_instructions(instructions: HTTPResponseInstructions) -> Response:
    headers = make_headers(instructions.headers)
    body: bytes | None = None
    if instructions.body is not None:
        if instructions.is_html or isinstance(instructions.body, str):
            body = str(instructions.body).encode()
        else:
            body = json.dumps(instructions.body).encode()
            if "content-type" not in headers:
                headers["Content-Type"] = "application/json"
    return Response(status=instructions.status, headers=headers, body=body)


def _merge_challenge(mpp: Response, x402: Response) -> Response:
    challenges = [("WWW-Authenticate", value) for value in mpp.headers.get_list("www-authenticate")]
    headers = make_headers([*x402.headers.multi_items(), *challenges])
    headers["Cache-Control"] = "no-store"
    return Response(status=x402.status, headers=headers, body=x402.body)


def _payment_required(instructions: HTTPResponseInstructions) -> PaymentRequired | None:
    encoded = make_headers(instructions.headers).get(PAYMENT_REQUIRED_HEADER)
    if not encoded:
        return None
    decoded = decode_payment_required_header(encoded)
    return decoded if isinstance(decoded, PaymentRequired) else None


def _facilitator_error(error: BaseException) -> FacilitatorResponseError | None:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, FacilitatorResponseError):
            return current
        current = current.__cause__
    return None
