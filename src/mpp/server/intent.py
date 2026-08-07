"""Intent protocol and decorator for defining payment intents.

An intent describes a type of payment operation (e.g., charge, authorize)
and provides verification logic.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mpp import Credential, Receipt


from mpp._validation import Validation
from mpp.errors import (
    VerificationError as VerificationError,  # noqa: F401 — re-export
)
from mpp.errors import VerificationFailedError


@runtime_checkable
class Intent(Protocol):
    """Payment intent with a combined verification hook.

    This is the original intent interface and remains supported for custom
    intents that combine validation and settlement in ``verify``.

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
class VerifiableIntent(Protocol):
    """Intent with separate non-mutating validation and terminal broadcast hooks.

    Implement both hooks to support validation before broadcast. ``validate``
    must not settle, reserve, or otherwise consume payment state, so it can back
    a safe pre-check. ``broadcast`` performs the terminal payment operation and
    returns its receipt.
    """

    name: str

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
    intent: Intent | VerifiableIntent,
    credential: Credential,
    request: dict[str, Any],
) -> Validation:
    """Run an intent's non-mutating validation hook.

    Legacy intents that only implement ``verify`` are rejected: verification
    may consume payment state, so it cannot back a safe pre-check. This is the
    low-level dispatcher — it does not authenticate that the credential's
    challenge was issued by a particular server. Use
    :meth:`~mpp.server.Mpp.validate_credential` for credentials from
    untrusted callers.

    Raises:
        VerificationFailedError: If the intent does not support non-mutating
            validation or returns an invalid validation result.
    """
    if not isinstance(intent, VerifiableIntent):
        raise VerificationFailedError(
            f"{intent.name} does not support non-mutating credential validation"
        )
    result = await intent.validate(credential, request)
    if not isinstance(result, Validation):
        raise VerificationFailedError("Intent returned an invalid validation result")
    return result


async def broadcast_credential(
    *,
    intent: Intent | VerifiableIntent,
    credential: Credential,
    request: dict[str, Any],
) -> Receipt:
    """Revalidate and perform the credential's terminal payment operation.

    Verifiable intents run ``validate`` before ``broadcast`` so a credential
    that is no longer acceptable fails before settlement; legacy intents fall
    back to their combined ``verify`` hook. Like :func:`validate_credential`,
    this does not authenticate challenge issuance — use
    :meth:`~mpp.server.Mpp.broadcast_credential` for untrusted input.
    """
    if isinstance(intent, VerifiableIntent):
        await validate_credential(intent=intent, credential=credential, request=request)
        return await intent.broadcast(credential, request)
    if isinstance(intent, Intent):
        return await intent.verify(credential, request)
    raise VerificationFailedError(
        f"{intent.name} does not support credential verification or broadcast"
    )


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
