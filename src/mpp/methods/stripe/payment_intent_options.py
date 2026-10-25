"""Private, request-scoped Stripe input; never part of an MPP challenge."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, TypeAlias, TypedDict

from mpp import ChallengeEcho, Credential
from mpp.errors import BadRequestError


class TaxInput(TypedDict):
    calculation: str


class HookInputs(TypedDict):
    tax: TaxInput


class Hooks(TypedDict):
    inputs: HookInputs


class PaymentIntentOptions(TypedDict, total=False):
    customer: str
    receipt_email: str
    metadata: dict[str, str]
    hooks: Hooks


@dataclass(frozen=True)
class PaymentIntentContext:
    """Snapshot of authenticated inputs, with rail validation when available."""

    challenge: ChallengeEcho
    credential: Credential
    request: dict[str, Any]


PaymentIntentInput: TypeAlias = (
    Mapping[str, Any]
    | Callable[
        [PaymentIntentContext], Mapping[str, Any] | None | Awaitable[Mapping[str, Any] | None]
    ]
    | None
)


def _mapping(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BadRequestError(f"{name} must be a mapping")
    if value.keys() - keys:
        raise BadRequestError(f"unsupported {name} field")
    return dict(value)


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadRequestError(f"{name} must be a non-empty string")
    return value


def validate_options(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    options = _mapping(
        value, {"customer", "receipt_email", "metadata", "hooks"}, "payment_intent_options"
    )
    for field in ("customer", "receipt_email"):
        if field in options:
            options[field] = _nonempty(options[field], field)
    if "metadata" in options:
        options["metadata"] = validate_metadata(options["metadata"])
    if "hooks" in options:
        hooks = _mapping(options["hooks"], {"inputs"}, "hooks")
        inputs = _mapping(hooks.get("inputs"), {"tax"}, "hooks.inputs")
        tax = _mapping(inputs.get("tax"), {"calculation"}, "hooks.inputs.tax")
        calculation = _nonempty(tax.get("calculation"), "hooks.inputs.tax.calculation")
        options["hooks"] = {"inputs": {"tax": {"calculation": calculation}}}
    return options


def validate_metadata(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
    ):
        raise BadRequestError("metadata must contain string keys and values")
    if len(value) > 50 or any(
        not k or len(k) > 40 or "[" in k or "]" in k or len(v) > 500 for k, v in value.items()
    ):
        raise BadRequestError("metadata exceeds Stripe's key/value limits")
    return dict(value)


def prepare_options(value: PaymentIntentInput) -> PaymentIntentInput:
    return value if callable(value) else validate_options(value)


async def resolve_options(
    value: PaymentIntentInput,
    credential: Credential,
    request: dict[str, Any],
) -> dict[str, Any]:
    if callable(value):
        # Resolver code must not mutate the inputs already authenticated by MPP.
        snapshot_credential, snapshot_request = deepcopy(credential), deepcopy(request)
        context = PaymentIntentContext(
            snapshot_credential.challenge, snapshot_credential, snapshot_request
        )
        result = value(context)
        value = await result if inspect.isawaitable(result) else result
    return validate_options(value)
