"""Payment method implementations."""

from collections.abc import Awaitable as _Awaitable
from collections.abc import Callable as _Callable
from typing import Any as _Any
from typing import TypeAlias as _TypeAlias

from mpp.events import ServerPaymentSuccessPayload as _ServerPaymentSuccessPayload

# Decides whether a composed payment offer is available for a canonical request.
CanOfferFn: _TypeAlias = _Callable[[dict[str, _Any]], bool | _Awaitable[bool]]

# Handles a successful payment for its configured method.
PaymentSuccessHandler: _TypeAlias = _Callable[
    [_ServerPaymentSuccessPayload], None | _Awaitable[None]
]
