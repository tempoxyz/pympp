"""Protocol constants: header names, scheme, built-in method/intent names."""

from collections.abc import Mapping
from enum import StrEnum
from typing import Any

__all__ = [
    "PAYMENT_SCHEME",
    "Header",
    "Intent",
    "MethodDetailKey",
    "MethodName",
    "SessionProtocol",
    "get_method_detail",
]


class Header(StrEnum):
    """HTTP header names used by the Payment authentication scheme."""

    ACCEPT_PAYMENT = "Accept-Payment"
    AUTHORIZATION = "Authorization"
    PAYMENT_AUTHORIZATION = "Payment-Authorization"
    PAYMENT_RECEIPT = "Payment-Receipt"
    PAYMENT_SESSION = "Payment-Session"
    PAYMENT_SESSION_SNAPSHOT = "Payment-Session-Snapshot"
    WWW_AUTHENTICATE = "WWW-Authenticate"


PAYMENT_SCHEME = "Payment"
"""Authentication scheme name used in ``WWW-Authenticate`` / ``Authorization``."""


class MethodName(StrEnum):
    """Payment method names used by built-in methods."""

    EVM = "evm"
    STRIPE = "stripe"
    TEMPO = "tempo"


class Intent(StrEnum):
    """Payment intent names used by built-in methods."""

    CHARGE = "charge"
    SESSION = "session"
    SUBSCRIPTION = "subscription"


class MethodDetailKey(StrEnum):
    """Keys used inside ``request.methodDetails`` by built-in methods."""

    SESSION_PROTOCOL = "sessionProtocol"
    SESSION_SNAPSHOT = "sessionSnapshot"


class SessionProtocol(StrEnum):
    """Tempo session protocol versions advertised under ``request.methodDetails``."""

    V1 = "v1"
    """Legacy contract-backed Tempo session protocol."""
    V2 = "v2"
    """TIP-1034 precompile-backed Tempo session protocol."""


def get_method_detail(method_details: Any, key: str) -> Any:
    """Reads a method detail value from a challenge request's ``methodDetails``."""
    if not isinstance(method_details, Mapping):
        return None
    return method_details.get(key)
