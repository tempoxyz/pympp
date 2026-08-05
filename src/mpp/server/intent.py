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
from mpp.errors import VerificationError as VerificationError  # noqa: F401 — re-export


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
    """Intent with separate non-mutating validation and terminal broadcast hooks."""

    async def validate(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Validation:
        """Validate without settling, reserving, or consuming payment state."""
        ...

    async def broadcast(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Perform the terminal payment operation and return its receipt."""
        ...


async def validate_credential(
    *,
    intent: Intent,
    credential: Credential,
    request: dict[str, Any],
) -> Validation:
    """Run an intent's non-mutating validation hook.

    Legacy intents that only implement ``verify`` cannot safely support this
    operation because verification may consume payment state.
    """
    validate = cast(
        "Callable[[Credential, dict[str, Any]], Awaitable[Validation]] | None",
        getattr(intent, "validate", None),
    )
    if not callable(validate):
        from mpp.errors import VerificationFailedError

        raise VerificationFailedError(
            f"{intent.name} does not support non-mutating credential validation"
        )

    result = await validate(credential, request)
    if not isinstance(result, Validation):
        from mpp.errors import VerificationFailedError

        raise VerificationFailedError("Intent returned an invalid validation result")
    return result


async def broadcast_credential(
    *,
    intent: Intent,
    credential: Credential,
    request: dict[str, Any],
) -> Receipt:
    """Revalidate and perform an intent's terminal payment operation.

    Split intents run ``validate`` before ``broadcast``. Legacy intents fall
    back to their combined ``verify`` hook.
    """
    broadcast = cast(
        "Callable[[Credential, dict[str, Any]], Awaitable[Receipt]] | None",
        getattr(intent, "broadcast", None),
    )
    if callable(broadcast):
        await validate_credential(intent=intent, credential=credential, request=request)
        return await broadcast(credential, request)

    verify = cast(
        "Callable[[Credential, dict[str, Any]], Awaitable[Receipt]] | None",
        getattr(intent, "verify", None),
    )
    if callable(verify):
        return await verify(credential, request)

    from mpp.errors import VerificationFailedError

    raise VerificationFailedError(f"{intent.name} does not support credential broadcast")


async def verify_credential(
    *,
    intent: Intent,
    credential: Credential,
    request: dict[str, Any],
) -> Receipt:
    """Legacy alias for :func:`broadcast_credential`."""
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
