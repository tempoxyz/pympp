"""Payment method implementations and the method contract they share."""

from collections.abc import Awaitable as _Awaitable
from collections.abc import Callable as _Callable
from collections.abc import Mapping as _Mapping
from dataclasses import dataclass as _dataclass
from typing import Any as _Any
from typing import Generic as _Generic
from typing import TypeAlias as _TypeAlias
from typing import TypeVar as _TypeVar

from pydantic import BaseModel as _BaseModel

from mpp.events import ServerPaymentSuccessPayload as _ServerPaymentSuccessPayload

# Decides whether a composed payment offer is available for a canonical request.
CanOfferFn: _TypeAlias = _Callable[[dict[str, _Any]], bool | _Awaitable[bool]]

# Handles a successful payment for its configured method.
PaymentSuccessHandler: _TypeAlias = _Callable[
    [_ServerPaymentSuccessPayload], None | _Awaitable[None]
]

RequestT = _TypeVar("RequestT", bound=_BaseModel)
PayloadT = _TypeVar("PayloadT", bound=_BaseModel)


@_dataclass(frozen=True, slots=True, kw_only=True)
class Method(_Generic[RequestT, PayloadT]):
    """A payment method definition shared by clients and servers.

    Attributes:
        name: Wire method name, such as ``"tempo"``.
        intent: Wire intent name, such as ``"charge"``.
        request_model: Validates a route's request input and produces its wire form.
            Validators and serializers may transform the input, for example converting a
            decimal ``amount`` to base units.
        payload_model: Validates a credential payload.
    """

    name: str
    intent: str
    request_model: type[RequestT]
    payload_model: type[PayloadT]

    @property
    def key(self) -> str:
        """The ``name/intent`` key."""
        return f"{self.name}/{self.intent}"

    def normalize_request(self, request: _Mapping[str, _Any]) -> dict[str, _Any]:
        """Validate ``request`` and return its wire form.

        Raises:
            pydantic.ValidationError: When the request is invalid.
        """
        return self.request_model.model_validate(dict(request)).model_dump(
            mode="json", by_alias=True, exclude_none=True
        )

    def parse_payload(self, payload: _Any) -> PayloadT:
        """Validate a credential payload.

        Raises:
            pydantic.ValidationError: When the payload is invalid.
        """
        return self.payload_model.model_validate(payload)
