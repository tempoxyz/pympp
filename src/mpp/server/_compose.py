"""Composition of several configured offers into one route handler."""

import base64
import copy
import json
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from mpp import _accept_payment
from mpp.challenge import Challenge
from mpp.constants import Header
from mpp.credential import Credential, extract_payment_scheme
from mpp.method import CanOfferContext, resolve
from mpp.server import _binding
from mpp.server._http import Request, Response
from mpp.server._mpp import (
    ComposedHandler,
    ConfiguredHandler,
    Handler,
    OfferInfo,
    PaymentRequired,
    PaymentResult,
)
from mpp.server._transport import McpTransport, Transport

X402_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"


def is_mcp(transport: Transport[Any, Any, Any, Any]) -> bool:
    return isinstance(transport, McpTransport)


def offers_of(handler: Any) -> tuple[OfferInfo, ...]:
    """Configured offers behind a handler (``()`` for custom callables)."""
    return tuple(getattr(handler, "offers", ()))


def compose(*handlers: Handler) -> ComposedHandler:
    """Combines configured HTTP handlers into one route handler.

    Without a credential every handler is evaluated (in order) and their challenges are merged
    into one 402 with several ``WWW-Authenticate`` values (negotiated with ``Accept-Payment``).
    With a credential the request is dispatched to the handler whose offer it targets.
    """
    return compose_handlers(list(handlers))


def compose_handlers(handlers: Sequence[Handler]) -> ComposedHandler:
    flat: list[Handler] = []
    for handler in handlers:
        if isinstance(handler, ComposedHandler):
            flat.extend(handler.handlers)
        else:
            flat.append(handler)
    if not flat:
        raise ValueError("compose() requires at least one handler")

    has_offer_policy = any(
        isinstance(handler, ConfiguredHandler) and handler.method.can_offer is not None
        for handler in flat
    )

    async def composed(input: Request) -> PaymentResult:
        # Gate dispatch on the Payment scheme only; other auth schemes fall through so that all
        # offers are presented.
        credential_headers = dict.fromkeys(
            header
            for handler in flat
            for offer in offers_of(handler)
            for header in offer.credential_headers
        )
        payment_header = next(
            (
                scheme
                for header in credential_headers
                if (value := input.headers.get(header)) is not None
                and (scheme := extract_payment_scheme(value)) is not None
            ),
            None,
        )
        if payment_header is not None:
            credential: Credential[Any] | None
            try:
                credential = _binding.hydrate_meta(Credential.deserialize(payment_header))
            except Exception:
                credential = None
            if credential is not None:
                name, intent = credential.challenge.method, credential.challenge.intent
                candidates = [
                    handler
                    for handler in flat
                    if any(
                        offer.name == name
                        and offer.intent == intent
                        and _binding.offer_matches(
                            canonical_request=offer.request,
                            meta=offer.meta,
                            stable_binding=offer.method.stable_binding,
                            credential=credential,
                        )
                        for offer in offers_of(handler)
                    )
                ]
                match = (
                    candidates[0]
                    if candidates
                    else next(
                        (
                            handler
                            for handler in flat
                            if any(
                                o.name == name and o.intent == intent for o in offers_of(handler)
                            )
                        ),
                        None,
                    )
                )
                if match is not None:
                    return await match(input)
            # Unrecognized or malformed credentials use the eligible offer set below; the first
            # handler issues the rejection challenge.

        selected = await _eligible_handlers(flat, input) if has_offer_policy else list(flat)

        transport_results: dict[int, PaymentResult] = {}
        for handler in selected:
            for offer in offers_of(handler):
                if not offer.transport.has_native_credentials:
                    continue
                try:
                    if await offer.transport.match_credential(input=input, request=offer.request):
                        result = await handler(input)
                        transport_results[id(handler)] = result
                        if result.status == 200:
                            return result
                        break
                except Exception:
                    pass

        authorization = Header.AUTHORIZATION.lower()
        for handler in selected:
            for offer in offers_of(handler):
                for header in offer.credential_headers:
                    value = input.headers.get(header)
                    if (
                        header.lower() != authorization
                        and value is not None
                        and extract_payment_scheme(value) is None
                    ):
                        return await handler(input)

        # No credential: evaluate sequentially so authorize()/renewal hooks can claim the request
        # without racing each other.
        results: list[tuple[Handler, PaymentRequired[Any]]] = []
        for handler in selected:
            result = transport_results.get(id(handler)) or await handler(input)
            if result.status == 200:
                return result
            if not isinstance(result.challenge, Response) or result.challenge.status != 402:
                return result
            results.append((handler, result))

        challenge_entries: list[tuple[Handler, Challenge, Response]] = []
        for handler, result in results:
            www = result.challenge.headers.get(Header.WWW_AUTHENTICATE)
            if www:
                challenge_entries.append((handler, Challenge.deserialize(www), result.challenge))
        accept_payment = input.headers.get(Header.ACCEPT_PAYMENT)
        if accept_payment:
            try:
                ranked = _accept_payment.rank(
                    [challenge for _, challenge, _ in challenge_entries],
                    _accept_payment.parse(accept_payment),
                )
                if ranked:
                    by_id = {
                        challenge.id: entry
                        for entry in challenge_entries
                        for challenge in [entry[1]]
                    }
                    challenge_entries = [by_id[challenge.id] for challenge in ranked]
            except ValueError:
                pass

        challenge_responses = [result.challenge for _, result in results]
        unnegotiated_x402 = (
            []
            if accept_payment is not None or not challenge_entries
            else [
                response
                for response in challenge_responses
                if X402_PAYMENT_REQUIRED_HEADER in response.headers
                and Header.WWW_AUTHENTICATE not in response.headers
            ]
        )
        negotiated = (
            [response for _, _, response in challenge_entries] + unnegotiated_x402
            if challenge_entries
            else challenge_responses
        )

        headers: list[tuple[str, str]] = [("Cache-Control", "no-store")]
        for _, _, response in challenge_entries:
            for value in response.headers.get_list(Header.WWW_AUTHENTICATE):
                headers.append((Header.WWW_AUTHENTICATE, value))
        x402_values = [
            value
            for response in negotiated
            for value in response.headers.get_list(X402_PAYMENT_REQUIRED_HEADER)
        ]
        for value in merge_x402_payment_required(x402_values):
            headers.append((X402_PAYMENT_REQUIRED_HEADER, value))

        # The first Payment-auth body, else the first transport 402 body.
        body_responses = (
            [response for _, _, response in challenge_entries]
            if challenge_entries
            else challenge_responses
        )
        body_bytes: bytes | None = None
        for response in body_responses:
            content_type = response.headers.get("Content-Type")
            if content_type:
                headers.append(("Content-Type", content_type))
            body_bytes = await response.read()
            break
        return PaymentRequired(Response(status=402, headers=headers, body=body_bytes or None))

    offers = tuple(offer for handler in flat for offer in offers_of(handler))
    return ComposedHandler(composed, offers=offers, handlers=tuple(flat))


def compose_mcp_handlers(
    handlers: Sequence[Handler], transport: Transport[Any, Any, Any, Any]
) -> ComposedHandler:
    """Dispatches one MCP credential, or gathers unsigned offers in configured order."""
    assert isinstance(transport, McpTransport)
    mcp_transport: McpTransport[Any, Any, Any, Any] = transport
    flat = list(handlers)

    async def composed(input: Any) -> PaymentResult:
        try:
            parsed = mcp_transport.get_credential(input)
            credential = _binding.hydrate_meta(parsed) if parsed is not None else None
        except Exception:
            # Let the method emit the normal malformed-credential error and retry challenge.
            return await flat[0](input)
        if credential is not None:
            name, intent = credential.challenge.method, credential.challenge.intent
            candidates = [
                handler
                for handler in flat
                if any(o.name == name and o.intent == intent for o in offers_of(handler))
            ]
            match = next(
                (
                    handler
                    for handler in candidates
                    if any(
                        _binding.offer_matches(
                            canonical_request=offer.request,
                            meta=offer.meta,
                            stable_binding=offer.method.stable_binding,
                            credential=credential,
                        )
                        for offer in offers_of(handler)
                    )
                ),
                None,
            )
            # Verification and settlement belong to exactly one handler, including failures.
            return await (match or (candidates[0] if candidates else flat[0]))(input)

        challenges: list[Any] = []
        first: Any = None
        for handler in flat:
            result = await handler(input)
            if result.status == 200:
                return result
            found = mcp_transport.payment_required_challenges(result.challenge)
            # Request-hook and configuration failures retain their original error semantics.
            if not found:
                return result
            if first is None:
                first = result.challenge
            challenges.extend(found)
        if first is None:
            raise ValueError("compose() requires at least one handler")
        return PaymentRequired(mcp_transport.with_challenges(first, challenges))

    return ComposedHandler(
        composed, offers=tuple(o for h in flat for o in offers_of(h)), handlers=tuple(flat)
    )


async def _eligible_handlers(handlers: Sequence[Handler], input: Request) -> list[Handler]:
    eligible: list[Handler] = []
    for handler in handlers:
        if isinstance(handler, ConfiguredHandler) and handler.method.can_offer is not None:
            approved = await resolve(
                handler.method.can_offer(
                    CanOfferContext(
                        input=input, request=freeze(copy.deepcopy(handler.offer.request))
                    )
                )
            )
            if not isinstance(approved, bool):
                raise TypeError("can_offer() must return a boolean")
            if not approved:
                continue
        eligible.append(handler)
    if not eligible:
        raise ValueError("No payment offers are available for this request")
    return eligible


def freeze(value: Any) -> Any:
    """Recursively converts dicts/lists into read-only mappings/tuples."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze(item) for item in value)
    return value


def merge_x402_payment_required(values: Sequence[str]) -> list[str]:
    """Merges x402 ``PAYMENT-REQUIRED`` headers (base64 JSON) into one."""
    if not values:
        return []
    decoded = [json.loads(base64.b64decode(value + "=" * (-len(value) % 4))) for value in values]
    first, rest = decoded[0], decoded[1:]

    def encode(value: Mapping[str, Any]) -> str:
        return base64.b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()

    def errors(items: Sequence[Mapping[str, Any]]) -> list[str]:
        return [
            item["error"] for item in items if isinstance(item.get("error"), str) and item["error"]
        ]

    if any(
        item.get("resource") != first.get("resource")
        or item.get("extensions") != first.get("extensions")
        for item in rest
    ):
        message = "; ".join(
            [*errors([first]), "Cannot merge x402 payment requirements with different resources."]
        )
        return [encode({**first, "error": message})]
    merged: dict[str, Any] = {
        **first,
        "accepts": [accept for item in decoded for accept in item.get("accepts", [])],
    }
    error = "; ".join(errors(decoded))
    if error:
        merged["error"] = error
    return [encode(merged)]
