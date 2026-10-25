"""Stripe metadata identifying and describing MPP payments."""

from functools import cache
from importlib.metadata import PackageNotFoundError, version

from mpp.challenge import Challenge
from mpp.stripe._internal.constants import MACHINE_PAYMENT_METADATA

_MAX_VALUE_LENGTH = 500


@cache
def sdk_identifier() -> str:
    """Canonical SDK identifier (``pympp/<version>``) reported in Stripe metadata."""
    try:
        return f"pympp/{version('pympp')}"
    except PackageNotFoundError:
        return "pympp/0.0.0"


def build_analytics(
    *, challenge: Challenge | None = None, intent: str | None = None
) -> dict[str, str]:
    """Builds Stripe metadata used to identify and analyze MPP payments.

    Values are truncated to Stripe's 500-character metadata limit.
    """
    intent = intent if intent is not None else (challenge.intent if challenge else None)
    metadata = {**MACHINE_PAYMENT_METADATA, "mpp_sdk": sdk_identifier()}
    if intent:
        metadata["mpp_intent"] = intent
    if challenge is not None:
        metadata["mpp_challenge_id"] = challenge.id
    return {key: value[:_MAX_VALUE_LENGTH] for key, value in metadata.items()}
