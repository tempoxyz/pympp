"""Stripe payment intents (server-side verification).

Implements the charge intent using Stripe's Shared Payment Token (SPT) flow.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

from mpp import Credential, Receipt
from mpp.errors import (
    PaymentActionRequiredError,
    PaymentExpiredError,
    VerificationFailedError,
)
from mpp.methods.stripe._defaults import STRIPE_API_BASE
from mpp.methods.stripe.schemas import StripeCredentialPayload

DEFAULT_TIMEOUT = 30.0


def _build_analytics(credential: Credential) -> dict[str, str]:
    """Build MPP analytics metadata for the Stripe PaymentIntent."""
    challenge = credential.challenge
    analytics: dict[str, str] = {
        "mpp_challenge_id": challenge.id,
        "mpp_intent": challenge.intent,
        "mpp_is_mpp": "true",
        "mpp_server_id": challenge.realm,
        "mpp_version": "1",
    }
    if credential.source:
        analytics["mpp_client_id"] = credential.source
    return analytics


def _resolve_payment_intents(client: Any) -> Any:
    """Resolve the payment_intents accessor from a Stripe client.

    Supports both the modern ``StripeClient`` (``client.v1.payment_intents``)
    and legacy/custom clients (``client.payment_intents``).
    """
    v1 = getattr(client, "v1", None)
    if v1 is not None:
        pi = getattr(v1, "payment_intents", None)
        if pi is not None:
            return pi
    pi = getattr(client, "payment_intents", None)
    if pi is not None:
        return pi
    raise TypeError("Unsupported Stripe client: expected .v1.payment_intents or .payment_intents")


class ChargeIntent:
    """Stripe charge intent for one-time payments via SPTs.

    Verifies payment by creating a Stripe PaymentIntent with the
    client-supplied Shared Payment Token (SPT).

    Accepts either a ``client`` (a pre-configured Stripe SDK instance)
    or a raw ``secret_key``. Using ``client`` is recommended.

    Example:
        import stripe as stripe_sdk
        from mpp.methods.stripe import ChargeIntent

        client = stripe_sdk.StripeClient("sk_...")
        intent = ChargeIntent(client=client)

        # Or with a raw secret key (no Stripe SDK needed):
        intent = ChargeIntent(secret_key="sk_...")
    """

    name = "charge"

    def __init__(
        self,
        client: Any | None = None,
        secret_key: str | None = None,
        http_client: Any | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the charge intent.

        Args:
            client: Pre-configured Stripe SDK instance (duck-typed).
                Supports both ``StripeClient`` (v8+, ``client.v1.payment_intents``)
                and legacy clients (``client.payment_intents``).
            secret_key: Stripe secret API key for raw HTTP verification.
                Used only when ``client`` is not provided.
            http_client: Optional httpx client for raw HTTP calls.
                If provided, the caller is responsible for closing it.
            timeout: Request timeout in seconds (default: 30).

        Raises:
            ValueError: If neither ``client`` nor ``secret_key`` is provided.
        """
        if client is None and secret_key is None:
            raise ValueError("Either client or secret_key is required")
        self._client = client
        self._secret_key = secret_key
        self._http_client = http_client
        self._owns_client = http_client is None
        self._timeout = timeout

    async def __aenter__(self) -> ChargeIntent:
        """Enter async context, creating HTTP client if needed."""
        if self._client is None:
            await self._get_http_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context, closing owned HTTP client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the HTTP client if we own it."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _get_http_client(self) -> Any:
        """Get or create an httpx async client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=self._timeout)
        return self._http_client

    async def verify(
        self,
        credential: Credential,
        request: dict[str, Any],
    ) -> Receipt:
        """Verify a Stripe charge credential.

        Creates a Stripe PaymentIntent using the SPT from the credential
        payload, then checks that payment succeeded.

        Args:
            credential: The payment credential from the client.
            request: The original payment request parameters.

        Returns:
            A receipt indicating success.

        Raises:
            VerificationFailedError: If the SPT is missing or PaymentIntent fails.
            PaymentExpiredError: If the challenge has expired.
            PaymentActionRequiredError: If 3DS or other action is needed.
        """
        challenge = credential.challenge

        if challenge.expires:
            expires = datetime.fromisoformat(challenge.expires.replace("Z", "+00:00"))
            if expires < datetime.now(UTC):
                raise PaymentExpiredError(challenge.expires)

        try:
            parsed = StripeCredentialPayload.model_validate(credential.payload)
        except Exception as err:
            raise VerificationFailedError(
                "Invalid credential payload: missing or malformed spt"
            ) from err

        spt = parsed.spt
        credential_external_id = parsed.externalId

        user_metadata = request.get("methodDetails", {}).get("metadata")
        resolved_metadata = {**_build_analytics(credential), **(user_metadata or {})}

        if self._client is not None:
            pi = await self._create_with_client(
                client=self._client,
                challenge_id=challenge.id,
                request=request,
                spt=spt,
                metadata=resolved_metadata,
            )
        else:
            pi = await self._create_with_secret_key(
                secret_key=self._secret_key,  # type: ignore[arg-type]
                challenge_id=challenge.id,
                request=request,
                spt=spt,
                metadata=resolved_metadata,
            )

        if pi["status"] == "requires_action":
            raise PaymentActionRequiredError("Stripe PaymentIntent requires action")
        if pi["status"] != "succeeded":
            raise VerificationFailedError(f"Stripe PaymentIntent status: {pi['status']}")

        return Receipt.success(
            reference=pi["id"],
            method="stripe",
            external_id=credential_external_id,
        )

    async def _create_with_client(
        self,
        client: Any,
        challenge_id: str,
        request: dict[str, Any],
        spt: str,
        metadata: dict[str, str],
    ) -> dict[str, str]:
        """Create a PaymentIntent using the Stripe SDK client."""
        try:
            payment_intents = _resolve_payment_intents(client)
            result = payment_intents.create(
                {
                    "amount": int(request["amount"]),
                    "automatic_payment_methods": {
                        "allow_redirects": "never",
                        "enabled": True,
                    },
                    "confirm": True,
                    "currency": request["currency"],
                    "metadata": metadata,
                    "shared_payment_granted_token": spt,
                },
                options={"idempotency_key": f"mppx_{challenge_id}_{spt}"},
            )
            return {"id": result.id, "status": result.status}
        except (VerificationFailedError, TypeError):
            raise
        except Exception as err:
            raise VerificationFailedError("Stripe PaymentIntent failed") from err

    async def _create_with_secret_key(
        self,
        secret_key: str,
        challenge_id: str,
        request: dict[str, Any],
        spt: str,
        metadata: dict[str, str],
    ) -> dict[str, str]:
        """Create a PaymentIntent using raw HTTP with a secret key."""
        http_client = await self._get_http_client()

        auth_value = base64.b64encode(f"{secret_key}:".encode()).decode()

        body: dict[str, str] = {
            "amount": str(request["amount"]),
            "automatic_payment_methods[allow_redirects]": "never",
            "automatic_payment_methods[enabled]": "true",
            "confirm": "true",
            "currency": str(request["currency"]),
            "shared_payment_granted_token": spt,
        }
        for key, value in metadata.items():
            body[f"metadata[{key}]"] = value

        response = await http_client.post(
            f"{STRIPE_API_BASE}/payment_intents",
            headers={
                "Authorization": f"Basic {auth_value}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": f"mppx_{challenge_id}_{spt}",
            },
            data=body,
        )

        if not response.is_success:
            detail = None
            try:
                err = response.json().get("error", {})
                detail = err.get("message") or err.get("code")
            except Exception:
                detail = response.text[:200] if response.text else None
            raise VerificationFailedError(
                detail or f"Stripe PaymentIntent failed (HTTP {response.status_code})"
            )

        result = response.json()
        return {"id": result["id"], "status": result["status"]}
