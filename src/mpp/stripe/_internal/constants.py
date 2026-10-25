"""Stripe API constants."""

from types import MappingProxyType
from typing import Final

STRIPE_PREVIEW_VERSION: Final = "2026-07-29.preview"
"""Stripe API version with the ``.preview`` suffix.

Required for ``shared_payment_granted_token`` (SPTs are in private preview). Bump this when
upgrading to a newer Stripe API version.
"""

STRIPE_API_URL: Final = "https://api.stripe.com"
"""Stripe REST API base URL."""

MACHINE_PAYMENT_METADATA: Final = MappingProxyType({"machine_payment": "true"})
"""Metadata identifying a Stripe PaymentIntent as a machine payment."""
