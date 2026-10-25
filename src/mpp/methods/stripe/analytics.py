"""Shared Stripe analytics and backward-compatible metadata merging."""

from collections.abc import Mapping
from importlib.metadata import version

from mpp import Credential
from mpp.methods.stripe.payment_intent_options import validate_metadata


def build_analytics(credential: Credential) -> dict[str, str]:
    challenge = credential.challenge
    metadata = {
        "machine_payment": "true",
        "mpp_sdk": f"pympp/{version('pympp')}",
        "mpp_challenge_id": challenge.id,
        "mpp_intent": challenge.intent,
    }
    return {key: value[:500] for key, value in metadata.items()}


def merge_metadata(
    credential: Credential,
    configured: Mapping[str, str] | None,
    options: dict,
) -> dict[str, str]:
    return validate_metadata(
        {
            **build_analytics(credential),
            **(configured or {}),
            **options.get("metadata", {}),
        }
    )
