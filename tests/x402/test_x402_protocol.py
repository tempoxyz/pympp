import base64
import json
from typing import Any

import httpx
import pytest

from mpp import Challenge
from mpp.x402 import (
    PAYMENT_SIGNATURE_HEADER,
    InvalidJsonHeaderError,
    collect_challenges,
    encode_payment_required,
    is_x402_challenge,
    protocol,
)

ACCEPT = {
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "maxTimeoutSeconds": 60,
    "network": "eip155:84532",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "scheme": "exact",
}
PAYMENT_REQUIRED = {
    "accepts": [ACCEPT],
    "resource": {"url": "https://api.example.com/x402"},
    "x402Version": 2,
}
SOLANA = {
    "amount": "10000",
    "asset": "USDC",
    "maxTimeoutSeconds": 60,
    "network": "solana:mainnet",
    "payTo": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWdYqPxfowV5n2kg",
    "scheme": "exact",
}
NATIVE = Challenge(
    id="native",
    realm="api.example.com",
    method="tempo",
    intent="charge",
    request={"amount": "1"},
)


def raw(value: object) -> str:
    return base64.b64encode(json.dumps(value).encode()).decode()


def response(headers: dict[str, str], status: int = 402) -> httpx.Response:
    return httpx.Response(status, headers=headers)


async def challenges(headers: dict[str, str], status: int = 402) -> list[Challenge]:
    return await protocol().get_challenges(response(headers, status))


@pytest.mark.parametrize(
    ("headers", "expected_ids"),
    [
        ({"PAYMENT-REQUIRED": encode_payment_required(PAYMENT_REQUIRED)}, ["x402:0"]),
        (
            {
                "PAYMENT-REQUIRED": encode_payment_required(
                    {**PAYMENT_REQUIRED, "accepts": [ACCEPT, {**ACCEPT, "amount": "20000"}]}
                )
            },
            ["x402:0", "x402:1"],
        ),
        ({"PAYMENT-REQUIRED": raw({**PAYMENT_REQUIRED, "accepts": [ACCEPT, SOLANA]})}, ["x402:0"]),
        (
            {
                "PAYMENT-REQUIRED": raw(
                    {**PAYMENT_REQUIRED, "accepts": [ACCEPT, {**ACCEPT, "scheme": "upto"}]}
                )
            },
            ["x402:0"],
        ),
        ({"PAYMENT-REQUIRED": raw({**PAYMENT_REQUIRED, "accepts": [SOLANA]})}, []),
    ],
)
async def test_synthesizes_branded_challenges(
    headers: dict[str, str], expected_ids: list[str]
) -> None:
    result = await challenges(headers)
    assert [challenge.id for challenge in result] == expected_ids
    assert all(challenge.method == "evm" and challenge.intent == "charge" for challenge in result)
    assert all(is_x402_challenge(challenge) for challenge in result)


async def test_challenge_request_carries_resource_and_extensions() -> None:
    extensions = {"bazaar": {"info": {"a": 1}, "schema": {"type": "object"}}}
    [challenge] = await challenges(
        {
            "PAYMENT-REQUIRED": encode_payment_required(
                {**PAYMENT_REQUIRED, "extensions": extensions}
            )
        }
    )
    assert challenge.realm == "api.example.com"
    assert challenge.request == {
        **ACCEPT,
        "extensions": extensions,
        "resource": {"url": "https://api.example.com/x402"},
    }


@pytest.mark.parametrize(
    ("url", "realm"),
    [
        ("https://api.example.com/x402?summary=hello#details", "api.example.com"),
        ("https://api.example.com:8443/x402", "api.example.com:8443"),
        ("https://api.example.com:443/x402", "api.example.com"),
    ],
)
async def test_realm_is_resource_host(url: str, realm: str) -> None:
    resource = {"url": url}
    [challenge] = await challenges(
        {"PAYMENT-REQUIRED": encode_payment_required({**PAYMENT_REQUIRED, "resource": resource})}
    )
    assert challenge.realm == realm
    assert challenge.request["resource"] == resource


async def test_ignores_non_402_and_missing_header() -> None:
    header = {"PAYMENT-REQUIRED": encode_payment_required(PAYMENT_REQUIRED)}
    assert await challenges(header, status=200) == []
    assert await challenges({}) == []


async def test_raises_on_malformed_envelope() -> None:
    with pytest.raises(InvalidJsonHeaderError):
        await challenges({"PAYMENT-REQUIRED": "garbage!"})


def test_protocol_name() -> None:
    assert protocol().name == "x402"


def headers_for(*, x402: Any = None, native: bool = False) -> dict[str, str]:
    result: dict[str, str] = {}
    if x402 is not None:
        result["PAYMENT-REQUIRED"] = x402
    if native:
        result["WWW-Authenticate"] = NATIVE.serialize()
    return result


def test_collects_native_then_x402_in_auto_mode() -> None:
    both = response(headers_for(x402=encode_payment_required(PAYMENT_REQUIRED), native=True))
    assert [c.id for c in collect_challenges(both)] == ["native", "x402:0"]
    assert [c.id for c in collect_challenges(both, "mpp")] == ["native"]
    assert [c.id for c in collect_challenges(both, "x402")] == ["x402:0"]


def test_auto_mode_tolerates_malformed_offer_of_other_protocol() -> None:
    malformed_x402 = response(headers_for(x402="garbage!", native=True))
    assert [c.id for c in collect_challenges(malformed_x402)] == ["native"]
    with pytest.raises(InvalidJsonHeaderError):
        collect_challenges(malformed_x402, "x402")
    malformed_mpp = response(
        {
            "PAYMENT-REQUIRED": encode_payment_required(PAYMENT_REQUIRED),
            "WWW-Authenticate": "Payment garbage",
        }
    )
    assert [c.id for c in collect_challenges(malformed_mpp)] == ["x402:0"]


def test_auto_mode_raises_when_nothing_parses() -> None:
    with pytest.raises(ValueError, match="Invalid base64 JSON header"):
        collect_challenges(response(headers_for(x402="garbage!")))
    assert collect_challenges(response({})) == []


async def test_sets_payment_signature_and_purges_stale_credentials() -> None:
    pytest.importorskip("mpp.client")
    request = httpx.Request(
        "GET",
        "https://api.example.com/x402",
        headers={"Authorization": "Payment stale", "PAYMENT-SIGNATURE": "old"},
    )
    updated = protocol().set_credential(request, "fresh", None)
    assert updated.headers[PAYMENT_SIGNATURE_HEADER] == "fresh"
    assert "authorization" not in updated.headers
    bearer = httpx.Request("GET", "https://a.example", headers={"Authorization": "Bearer t"})
    assert protocol().set_credential(bearer, "x", None).headers["authorization"] == "Bearer t"


async def test_relative_resource_urls_yield_no_offer() -> None:
    header = encode_payment_required({**PAYMENT_REQUIRED, "resource": {"url": "/relative"}})
    with pytest.raises(ValueError, match="Invalid URL"):
        await challenges({"PAYMENT-REQUIRED": header})
    # Under auto selection the unusable x402 offer is ignored in favor of native challenges.
    both = response({"PAYMENT-REQUIRED": header, "WWW-Authenticate": NATIVE.serialize()})
    assert [c.id for c in collect_challenges(both)] == ["native"]


@pytest.mark.parametrize(
    ("url", "realm"),
    [("http://[::1]:8080/a", "[::1]:8080"), ("https://[::1]/a", "[::1]")],
)
async def test_ipv6_realms_keep_brackets(url: str, realm: str) -> None:
    header = encode_payment_required(
        {**PAYMENT_REQUIRED, "accepts": [ACCEPT, ACCEPT], "resource": {"url": url}}
    )
    assert {c.realm for c in await challenges({"PAYMENT-REQUIRED": header})} == {realm}
