"""x402 compatibility for MPP servers.

Lets a server that charges with the ``evm`` method also serve x402 v2
``exact`` clients (EIP-3009 ``transferWithAuthorization``) from the same
endpoint, as mppx does. Unpaid responses carry ``PAYMENT-REQUIRED`` next to
``WWW-Authenticate``, x402 clients pay with ``PAYMENT-SIGNATURE``, and paid
x402 responses carry ``PAYMENT-RESPONSE``.

Example:
    from mpp.methods.evm import BASE_USDC, evm
    from mpp.server import Mpp

    server = Mpp.create(
        method=evm(
            currency=BASE_USDC,
            recipient="0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
            facilitator="https://facilitator.example.com",
        ),
    )

    @app.get("/paid")
    @server.pay(amount="0.01")
    async def handler(request, credential, receipt):
        return JSONResponse({"data": "..."})
"""

from mpp.x402._header import (
    InvalidHeaderError,
    decode_payment_required,
    decode_payment_response,
    decode_payment_signature,
    encode_payment_required,
    encode_payment_response,
    encode_payment_signature,
)
from mpp.x402._server import (
    ROUTE_BINDING_EXTENSION,
    RouteBinding,
    X402Input,
    X402Intent,
    is_x402_credential,
    payment_required_header,
    payment_response_header,
    route_extensions,
    route_nonce,
)
from mpp.x402._types import (
    EIP3009,
    EXACT_SCHEME,
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    X402_VERSION,
    PaymentPayload,
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    SettleResponse,
    VerifyResponse,
    X402FormatError,
)
from mpp.x402.facilitator import (
    Facilitator,
    FacilitatorError,
    HttpFacilitator,
    resolve_facilitator,
)

__all__ = [
    "EIP3009",
    "EXACT_SCHEME",
    "PAYMENT_REQUIRED_HEADER",
    "PAYMENT_RESPONSE_HEADER",
    "PAYMENT_SIGNATURE_HEADER",
    "ROUTE_BINDING_EXTENSION",
    "X402_VERSION",
    "Facilitator",
    "FacilitatorError",
    "HttpFacilitator",
    "InvalidHeaderError",
    "PaymentPayload",
    "PaymentRequired",
    "PaymentRequirements",
    "ResourceInfo",
    "RouteBinding",
    "SettleResponse",
    "VerifyResponse",
    "X402FormatError",
    "X402Input",
    "X402Intent",
    "decode_payment_required",
    "decode_payment_response",
    "decode_payment_signature",
    "encode_payment_required",
    "encode_payment_response",
    "encode_payment_signature",
    "is_x402_credential",
    "payment_required_header",
    "payment_response_header",
    "resolve_facilitator",
    "route_extensions",
    "route_nonce",
]
