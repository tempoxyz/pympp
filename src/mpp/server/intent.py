"""Intent protocol and decorator for defining payment intents.

An intent describes a type of payment operation (e.g., charge, authorize)
and provides verification logic.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

if TYPE_CHECKING:
    from mpp import Credential, Receipt


from mpp._validation import Validation
from mpp.errors import (
    VerificationError as VerificationError,  # noqa: F401 — re-export
)
from mpp.errors import VerificationFailedError


@runtime_checkable
class Intent(Protocol):
    """Payment intent interface.

    Implement this protocol to define custom payment intents.
    Duck typing is supported - just implement the required attributes.

    Example:
        class MyChargeIntent:
            name = "charge"

            async def verify(
                self,
                credential: Credential,
                request: dict[str, Any],
            ) -> Receipt:
                # Verify the credential and return a receipt
                ...
    """

    name: str

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Verify a credential against a request and return a receipt.

        Args:
            credential: The payment credential from the client.
            request: The original payment request parameters.

        Returns:
            A receipt indicating success or failure.

        Raises:
            VerificationError: If the credential is invalid or payment failed.
        """
        ...


@runtime_checkable
class SplitIntent(Intent, Protocol):
    """Intent with separate validation and terminal broadcast hooks."""

    async def validate(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Validation: ...

    async def broadcast(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt: ...


async def validate_credential(
    *,
    intent: Intent,
    credential: Credential,
    request: dict[str, Any],
) -> Validation:
    """Validate a credential without consuming payment state."""
    validate = cast(
        "Callable[[Credential, dict[str, Any]], Awaitable[Validation]] | None",
        getattr(intent, "validate", None),
    )
    if not callable(validate):
        raise VerificationFailedError(
            f"{intent.name} does not support non-mutating credential validation"
        )
    result = await validate(credential, request)
    if not isinstance(result, Validation):
        raise VerificationFailedError("Intent returned an invalid validation result")
    return result


async def broadcast_credential(
    *,
    intent: Intent,
    credential: Credential,
    request: dict[str, Any],
) -> Receipt:
    """Revalidate and perform the credential's terminal payment operation."""
    validate = getattr(intent, "validate", None)
    broadcast = cast(
        "Callable[[Credential, dict[str, Any]], Awaitable[Receipt]] | None",
        getattr(intent, "broadcast", None),
    )
    if callable(validate) and callable(broadcast):
        await validate_credential(intent=intent, credential=credential, request=request)
    if callable(broadcast):
        return await broadcast(credential, request)
    return await intent.verify(credential, request)


async def verify_credential(
    *,
    intent: Intent,
    credential: Credential,
    request: dict[str, Any],
) -> Receipt:
    """Backward-compatible alias for :func:`broadcast_credential`."""
    return await broadcast_credential(intent=intent, credential=credential, request=request)


class FunctionalIntent:
    """Intent wrapper for function-based definitions."""

    def __init__(
        self,
        name: str,
        verify_fn: Callable[[Credential, dict[str, Any]], Awaitable[Receipt]],
    ) -> None:
        self.name = name
        self._verify_fn = verify_fn

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Verify using the wrapped function."""
        return await self._verify_fn(credential, request)


def intent(
    name: str,
) -> Callable[[Callable[[Credential, dict[str, Any]], Awaitable[Receipt]]], FunctionalIntent]:
    """Decorator to define an intent from a function.

    Example:
        @intent(name="charge")
        async def my_charge(credential: Credential, request: dict) -> Receipt:
            # Custom verification logic
            return Receipt(status="success", ...)
    """

    def decorator(
        fn: Callable[[Credential, dict[str, Any]], Awaitable[Receipt]],
    ) -> FunctionalIntent:
        return FunctionalIntent(name, fn)

    return decorator
