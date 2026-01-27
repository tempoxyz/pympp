"""Intent protocol and decorator for defining payment intents.

An intent describes a type of payment operation (e.g., charge, authorize)
and provides verification logic.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mpay import Credential, Receipt


class VerificationError(Exception):
    """Payment verification failed."""


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
