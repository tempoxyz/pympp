"""MCP (JSON-RPC) payment constants and message shapes.

Payment-required tool calls fail with JSON-RPC error ``-32042`` whose ``data`` carries the
challenge objects; credentials ride in ``params._meta["org.paymentauth/credential"]`` and receipts
in ``result._meta["org.paymentauth/receipt"]``.
"""

from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, Any, NotRequired, TypedDict

from mpp import _base64url, _json, payment_request
from mpp.credential import Credential
from mpp.errors import (
    InternalPaymentError,
    InvalidPayloadError,
    MalformedCredentialError,
    PaymentError,
    PaymentRequiredError,
)

if TYPE_CHECKING:
    from mpp.method import ServerMethod
    from mpp.server import Mpp

__all__ = [
    "CREDENTIAL_META_KEY",
    "INTERNAL_ERROR_CODE",
    "INVALID_PARAMS_CODE",
    "PAYMENT_CAPABILITY",
    "PAYMENT_REQUIRED_CODE",
    "PAYMENT_REQUIRED_META_KEY",
    "PAYMENT_VERIFICATION_FAILED_CODE",
    "RECEIPT_META_KEY",
    "ErrorObject",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "PaymentRequiredData",
    "error_code",
    "parse_credential",
    "payment_capabilities",
]


PAYMENT_REQUIRED_CODE = -32042
"""MCP JSON-RPC error code for payment required."""

PAYMENT_VERIFICATION_FAILED_CODE = -32043
"""MCP JSON-RPC error code for payment verification failed."""

INVALID_PARAMS_CODE = -32602
"""JSON-RPC error code for invalid parameters."""

INTERNAL_ERROR_CODE = -32603
"""JSON-RPC error code for internal errors."""

CREDENTIAL_META_KEY = "org.paymentauth/credential"
"""``_meta`` key carrying the credential object on requests."""

PAYMENT_REQUIRED_META_KEY = "org.paymentauth/payment-required"
"""``_meta`` key carrying payment-required data on tool results."""

RECEIPT_META_KEY = "org.paymentauth/receipt"
"""``_meta`` key carrying the receipt object on results."""

PAYMENT_CAPABILITY = "payment"
"""Key of the payment entry in the server's ``capabilities.experimental``."""


def error_code(error: PaymentError | None = None) -> int:
    """Maps a payment error to its MCP JSON-RPC error code."""
    if error is None or isinstance(error, PaymentRequiredError):
        return PAYMENT_REQUIRED_CODE
    if isinstance(error, MalformedCredentialError | InvalidPayloadError):
        return INVALID_PARAMS_CODE
    if isinstance(error, InternalPaymentError):
        return INTERNAL_ERROR_CODE
    return PAYMENT_VERIFICATION_FAILED_CODE


class PaymentRequiredData(TypedDict):
    """``error.data`` of a payment-required JSON-RPC error."""

    httpStatus: int
    challenges: list[dict[str, Any]]
    problem: NotRequired[dict[str, Any]]


class ErrorObject(TypedDict):
    """JSON-RPC error object."""

    code: int
    message: str
    data: NotRequired[PaymentRequiredData]


class JsonRpcRequest(TypedDict, total=False):
    """A JSON-RPC request (``params._meta`` may carry the credential object)."""

    jsonrpc: str
    id: int | str
    method: str
    params: dict[str, Any]


class JsonRpcResponse(TypedDict, total=False):
    """A JSON-RPC response with either ``result`` or ``error``."""

    jsonrpc: str
    id: int | str | None
    result: dict[str, Any]
    error: ErrorObject


def parse_credential(value: Any) -> Credential[Any]:
    """Validates a ``_meta`` credential object through the canonical wire serializer.

    The object has the credential JSON shape with an expanded ``challenge.request`` object.

    Raises:
        mpp.InvalidCredentialEncodingError: When the value is not a valid credential.
    """
    from mpp.credential import InvalidCredentialEncodingError

    if not isinstance(value, Mapping) or "challenge" not in value or "payload" not in value:
        raise InvalidCredentialEncodingError()
    try:
        challenge = dict(value["challenge"])
        meta = challenge.pop("meta", None)
        opaque = challenge.pop("opaque", None)
        request = challenge.pop("request", None)
        if opaque is None and meta is not None:
            opaque = payment_request.serialize(meta)
        if opaque is not None:
            challenge["opaque"] = opaque
        challenge["request"] = _base64url.encode(_json.canonicalize(request))
        wire: dict[str, Any] = {"challenge": challenge, "payload": value["payload"]}
        if value.get("source"):
            wire["source"] = value["source"]
        header = f"Payment {_base64url.encode(_json.dumps(wire))}"
    except Exception as error:
        raise InvalidCredentialEncodingError() from error
    return Credential.deserialize(header)


def payment_capabilities(
    methods: "Mpp | Iterable[ServerMethod]",
) -> dict[str, dict[str, Any]]:
    """Returns the ``experimental`` server capabilities advertising payment support.

    Per the MCP transport draft (draft-payment-transport-mcp), a server advertises the payment
    methods and intents it accepts under ``capabilities.experimental.payment`` in its
    ``InitializeResult``. Both lists keep configuration order without duplicates::

        server.create_initialization_options(experimental_capabilities=payment_capabilities(mpp))
        # {"payment": {"methods": ["tempo"], "intents": ["charge", "session"]}}

    Args:
        methods: A server ``Mpp`` or its server methods.
    """
    from mpp.server import Mpp

    configured = methods.methods if isinstance(methods, Mpp) else methods
    names: dict[str, None] = {}
    intents: dict[str, None] = {}
    for method in configured:
        names[method.name] = None
        intents[method.intent] = None
    return {PAYMENT_CAPABILITY: {"methods": list(names), "intents": list(intents)}}
