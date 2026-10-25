"""Route binding checks: the challenge fields that must stay stable between issuance and use.

The HMAC (``Challenge.verify``) is the primary gate; these comparisons are the secondary safety
net for request hooks that produce credential-dependent output (e.g. ``feePayer``), ensuring the
economically significant subset and the route metadata (``opaque``) did not drift.
"""

import secrets
from collections.abc import Callable, Mapping
from typing import Any

from mpp import payment_request
from mpp.challenge import Challenge
from mpp.credential import Credential

NONCE_KEY = "_mppx_nonce"
"""Reserved metadata key for HMAC-bound, per-issuance challenge randomness."""

SCOPE_KEY = "_mppx_scope"
"""Reserved metadata key for route/resource scope binding."""

CORE_FIELDS = ("amount", "currency", "recipient")
METHOD_FIELDS = ("chainId", "memo", "sessionProtocol", "splits", "unitType")

type StableBinding = Callable[[dict[str, Any]], dict[str, Any]]


def with_nonce(meta: Mapping[str, str] | None) -> dict[str, str]:
    """Adds fresh issuance randomness while preserving application and route metadata."""
    return {**(meta or {}), NONCE_KEY: "0x" + secrets.token_hex(32)}


def route_meta(meta: Mapping[str, str] | None) -> dict[str, str] | None:
    """Removes issuance-only metadata when comparing stable route requirements."""
    rest = {key: value for key, value in (meta or {}).items() if key != NONCE_KEY}
    return rest or None


def read_scope(meta: Mapping[str, str] | None) -> str | None:
    return (meta or {}).get(SCOPE_KEY)


def merge_scope(meta: Mapping[str, str] | None, scope: str | None) -> dict[str, str] | None:
    """Merges the public ``scope`` option into challenge metadata.

    Raises:
        ValueError: When ``scope`` conflicts with ``meta["_mppx_scope"]``.
    """
    meta_scope = read_scope(meta)
    if scope is not None and meta_scope is not None and meta_scope != scope:
        raise ValueError(
            f"Conflicting scope values: `scope` ({scope}) does not match "
            f"`meta.{SCOPE_KEY}` ({meta_scope})."
        )
    if scope is None or meta_scope == scope:
        return dict(meta) if meta is not None else None
    return {**(meta or {}), SCOPE_KEY: scope}


def hydrate_meta(credential: Credential[Any]) -> Credential[Any]:
    """Parses ``challenge.opaque`` into ``challenge.meta`` (server-side, authoritative)."""
    challenge = credential.challenge
    if challenge.opaque is None:
        return credential
    meta = payment_request.deserialize(challenge.opaque)
    return credential.with_challenge(_replace_meta(challenge, meta))


def _replace_meta(challenge: Challenge, meta: Any) -> Challenge:
    from dataclasses import replace

    return replace(challenge, meta=meta)


def strict_equal(left: Any, right: Any) -> bool:
    """Deep equality with JavaScript ``isDeepStrictEqual`` semantics for JSON values."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, int | float) and isinstance(right, int | float):
        return left == right
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return left.keys() == right.keys() and all(strict_equal(left[k], right[k]) for k in left)
    if isinstance(left, list | tuple) and isinstance(right, list | tuple):
        return len(left) == len(right) and all(
            strict_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return type(left) is type(right) and left == right


def _scalar(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _hex(value: Any) -> str | None:
    text = _scalar(value)
    if text is None:
        return None
    return text.lower() if text.startswith("0x") else text


def normalize_comparable(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list | tuple):
        return [normalize_comparable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): normalize_comparable(item) for key, item in sorted(value.items())}
    return _hex(value) if isinstance(value, str) else value


def pinned_binding(request: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns the (core, method) pinned binding fields of a wire request."""
    details = request.get("methodDetails")
    details = details if isinstance(details, Mapping) else {}

    def pick(key: str) -> Any:
        value = request.get(key)
        return details.get(key) if value is None else value

    core = {
        "amount": _scalar(pick("amount")),
        "currency": _scalar(pick("currency")),
        "recipient": _scalar(pick("recipient")),
    }
    method = {
        "chainId": _scalar(pick("chainId")),
        "memo": _hex(details.get("memo")),
        "sessionProtocol": _scalar(details.get("sessionProtocol")),
        "splits": normalize_comparable(details.get("splits")),
        "unitType": _scalar(pick("unitType")),
    }
    return (
        {k: v for k, v in core.items() if v is not None},
        {k: v for k, v in method.items() if v is not None},
    )


def pinned_request_mismatch(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> str | None:
    expected_core, expected_method = pinned_binding(expected)
    actual_core, actual_method = pinned_binding(actual)
    for field in CORE_FIELDS:
        if not strict_equal(expected_core.get(field), actual_core.get(field)):
            return field
    for field in METHOD_FIELDS:
        if not strict_equal(expected_method.get(field), actual_method.get(field)):
            return field
    return None


def configured_request_mismatch(
    configured: Mapping[str, Any], actual: Mapping[str, Any]
) -> str | None:
    """Compares a credential with a composed handler's configured request when dispatching.

    Only method fields the configured request defines are compared (the request hook may add
    others later); the selected handler still checks every pinned field.
    """
    expected_core, expected_method = pinned_binding(configured)
    actual_core, actual_method = pinned_binding(actual)
    for field in CORE_FIELDS:
        if not strict_equal(expected_core.get(field), actual_core.get(field)):
            return field
    for field in METHOD_FIELDS:
        if field in expected_method and not strict_equal(
            expected_method[field], actual_method.get(field)
        ):
            return field
    return None


def stable_mismatch(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> str | None:
    fields = [*expected.keys(), *(key for key in actual if key not in expected)]
    for field in fields:
        if not strict_equal(
            normalize_comparable(expected.get(field)), normalize_comparable(actual.get(field))
        ):
            return field
    return None


def opaque_matches(expected: Mapping[str, str] | None, actual: Mapping[str, str] | None) -> bool:
    # The echoed nonce is HMAC-authenticated but not a stable route requirement.
    return strict_equal(route_meta(expected), route_meta(actual))


def challenge_mismatch(
    expected: Challenge, actual: Challenge, stable_binding: StableBinding | None = None
) -> str | None:
    """Returns the first drifted field between the route challenge and the echoed challenge."""
    for field in ("method", "intent", "realm"):
        if getattr(actual, field) != getattr(expected, field):
            return field
    if not opaque_matches(expected.meta, actual.meta):
        return "opaque"
    if stable_binding is None:
        return pinned_request_mismatch(expected.request, actual.request)
    return stable_mismatch(stable_binding(expected.request), stable_binding(actual.request))


def offer_matches(
    *,
    canonical_request: Mapping[str, Any],
    meta: Mapping[str, str] | None,
    stable_binding: StableBinding | None,
    credential: Credential[Any],
) -> bool:
    """Whether a credential targets a configured offer (compose dispatch narrowing)."""
    try:
        echoed = credential.challenge.request
        if stable_binding is not None:
            mismatch = stable_mismatch(
                stable_binding(dict(canonical_request)), stable_binding(dict(echoed))
            )
        else:
            mismatch = configured_request_mismatch(canonical_request, echoed)
        return mismatch is None and opaque_matches(meta, credential.challenge.meta)
    except Exception:
        return False
