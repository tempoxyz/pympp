"""Unit tests for the x402 wire format, facilitator client and server helpers."""

from __future__ import annotations

import asyncio
import base64
import gzip
import json
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import anyio
import httpx
import pytest
from pytest_httpx import HTTPXMock

from mpp import ChallengeEcho, Credential, Receipt
from mpp._canonical import canonical_b64url
from mpp.server import PaymentVerified
from mpp.server.decorator import get_request_url, x402_input
from mpp.x402 import (
    PAYMENT_SIGNATURE_HEADER,
    FacilitatorError,
    HttpFacilitator,
    InvalidHeaderError,
    decode_payment_required,
    decode_payment_response,
    decode_payment_signature,
    encode_payment_required,
    encode_payment_response,
    encode_payment_signature,
    is_x402_credential,
    pay_to,
    payment_required_header,
    payment_response_header,
    resolve_facilitator,
)
from mpp.x402._header import MAX_HEADER_SIZE
from mpp.x402._server import (
    ROUTE_BINDING_SCHEMA,
    challenges_payment_required_header,
    route_extensions,
    route_nonce,
    route_requires_binding,
)
from mpp.x402._types import X402FormatError, parse_eip3009_payload, requirements_match

ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PAY_TO = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
PAYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
NONCE = "0x" + "11" * 32
SIGNATURE = "0x" + "22" * 65


def requirements(**overrides: Any) -> dict[str, Any]:
    return {
        "scheme": "exact",
        "network": "eip155:84532",
        "amount": "10000",
        "asset": ASSET,
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 300,
        "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        **overrides,
    }


def payment(**overrides: Any) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "accepted": requirements(),
        "payload": {
            "authorization": {
                "from": PAYER,
                "to": PAY_TO,
                "value": "10000",
                "validAfter": "0",
                "validBefore": "9999999999",
                "nonce": NONCE,
            },
            "signature": SIGNATURE,
        },
        "resource": {"url": "https://api.example.com/paid"},
        **overrides,
    }


def b64(value: Any) -> str:
    return base64.b64encode(json.dumps(value).encode()).decode()


class TestHeaders:
    def test_payment_required_round_trips(self) -> None:
        value = {
            "x402Version": 2,
            "accepts": [requirements()],
            "resource": {"url": "https://api.example.com/paid"},
            "error": "PAYMENT-SIGNATURE header is required",
        }
        encoded = encode_payment_required(value)  # type: ignore[arg-type]
        # Standard base64 over compact JSON, as x402 clients expect.
        assert json.loads(base64.b64decode(encoded)) == value
        assert decode_payment_required(encoded) == value

    def test_payment_signature_round_trips(self) -> None:
        value = payment()
        assert decode_payment_signature(encode_payment_signature(value)) == value  # type: ignore[arg-type]

    def test_payment_response_round_trips(self) -> None:
        value = {"success": True, "transaction": "0xabc", "network": "eip155:8453", "payer": PAYER}
        assert decode_payment_response(encode_payment_response(value)) == value  # type: ignore[arg-type]

    def test_decodes_unpadded_base64(self) -> None:
        encoded = b64(payment()).rstrip("=")
        assert decode_payment_signature(encoded)["x402Version"] == 2

    def test_keeps_unicode(self) -> None:
        value = {
            "x402Version": 2,
            "accepts": [requirements()],
            "resource": {"url": "https://api.example.com/€", "description": "café"},
        }
        assert decode_payment_required(encode_payment_required(value)) == value  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "value",
        [
            "not-base64!",
            base64.b64encode(b"not json").decode(),
            base64.b64encode(b"\xff\xfe").decode(),
            b64([1, 2]),
            b64(payment(x402Version=1)),
            b64(payment(x402Version=True)),
            b64(payment(accepted=requirements(scheme="upto"))),
            b64(payment(accepted=requirements(network="solana:mainnet"))),
            b64(payment(accepted=requirements(amount="1.5"))),
            b64(payment(accepted=requirements(amount=10000))),
            b64(payment(accepted=requirements(amount="1" * 79))),
            b64(payment(accepted=requirements(maxTimeoutSeconds=0))),
            b64(payment(accepted=requirements(maxTimeoutSeconds=True))),
            b64(payment(accepted=requirements(extra="eip3009"))),
            b64(payment(payload="0x")),
            b64(payment(resource={"description": "no url"})),
            b64(payment(extensions={"mppx": {"info": {}}})),
        ],
    )
    def test_rejects_invalid_payment_signatures(self, value: str) -> None:
        with pytest.raises(InvalidHeaderError):
            decode_payment_signature(value)

    def test_rejects_lone_surrogates(self) -> None:
        value = payment(extensions={"\ud800": {"info": {}, "schema": {}}})
        encoded = base64.b64encode(json.dumps(value).encode()).decode()
        with pytest.raises(InvalidHeaderError):
            decode_payment_signature(encoded)

    def test_rejects_values_rfc8785_cannot_canonicalize(self) -> None:
        value = payment(extensions={"extra": {"info": {"value": 2**100}, "schema": {}}})
        with pytest.raises(InvalidHeaderError):
            decode_payment_signature(b64(value))

    def test_rejects_deeply_nested_json(self) -> None:
        encoded = base64.b64encode(b"[" * 30_000 + b"]" * 30_000).decode()
        with pytest.raises(InvalidHeaderError):
            decode_payment_signature(encoded)

    def test_rejects_oversized_headers(self) -> None:
        with pytest.raises(InvalidHeaderError, match="too large"):
            decode_payment_signature("A" * (MAX_HEADER_SIZE + 1))

    def test_rejects_payment_required_without_accepts(self) -> None:
        value = {"x402Version": 2, "accepts": [], "resource": {"url": "https://a.example"}}
        with pytest.raises(InvalidHeaderError, match="accepts"):
            decode_payment_required(b64(value))

    def test_encoding_validates(self) -> None:
        with pytest.raises(X402FormatError):
            encode_payment_response({"success": "yes"})  # type: ignore[arg-type]

    def test_rejects_malformed_settle_responses(self) -> None:
        with pytest.raises(InvalidHeaderError):
            decode_payment_response(
                b64({"success": True, "transaction": "0x", "network": "x", "amount": "1.0"})
            )

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("from", "0x1234"),
            ("to", PAY_TO + "00"),
            ("nonce", "0x11"),
            ("value", "-1"),
            ("validBefore", "soon"),
        ],
    )
    def test_eip3009_payload_fields_are_checked(self, key: str, value: str) -> None:
        body = payment()["payload"]
        body["authorization"][key] = value
        with pytest.raises(X402FormatError):
            parse_eip3009_payload(body)

    def test_eip3009_signature_must_be_hex(self) -> None:
        body = payment()["payload"]
        body["signature"] = "0xzz"
        with pytest.raises(X402FormatError):
            parse_eip3009_payload(body)


class TestRequirementsMatch:
    def test_identical(self) -> None:
        assert requirements_match(requirements(), requirements())

    def test_addresses_compare_case_insensitively(self) -> None:
        assert requirements_match(
            requirements(asset=ASSET.lower(), payTo=PAY_TO.upper().replace("0X", "0x")),
            requirements(),
        )

    def test_missing_and_null_extra_are_equal(self) -> None:
        without = requirements()
        del without["extra"]
        assert requirements_match(requirements(extra=None), without)

    @pytest.mark.parametrize(
        "changed",
        [
            requirements(amount="10001"),
            requirements(network="eip155:8453"),
            requirements(maxTimeoutSeconds=60),
            requirements(extra={"assetTransferMethod": "permit2", "name": "USDC", "version": "2"}),
            requirements(payTo="0x" + "00" * 20),
            {**requirements(), "unexpected": True},
        ],
    )
    def test_any_other_difference_does_not_match(self, changed: dict[str, Any]) -> None:
        assert not requirements_match(changed, requirements())

    def test_booleans_never_equal_numbers(self) -> None:
        assert not requirements_match(requirements(maxTimeoutSeconds=True), requirements())
        assert not requirements_match(
            requirements(extra={"flag": 1}), requirements(extra={"flag": True})
        )

    def test_numbers_compare_by_value(self) -> None:
        assert requirements_match(requirements(maxTimeoutSeconds=300.0), requirements())

    def test_nested_lists_compare_in_order(self) -> None:
        assert requirements_match(
            requirements(extra={"tags": ["a", "b"]}), requirements(extra={"tags": ["a", "b"]})
        )
        assert not requirements_match(
            requirements(extra={"tags": ["a", "b"]}), requirements(extra={"tags": ["b", "a"]})
        )


class TestHttpFacilitator:
    async def test_verify_posts_the_v2_body(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://facilitator.example/verify", json={"isValid": True, "payer": PAYER}
        )
        facilitator = HttpFacilitator("https://facilitator.example/")

        result = await facilitator.verify(payment(), requirements())  # type: ignore[arg-type]

        assert result == {"isValid": True, "payer": PAYER}
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.content) == {
            "paymentPayload": payment(),
            "paymentRequirements": requirements(),
            "x402Version": 2,
        }

    async def test_settle_parses_the_response(self, httpx_mock: HTTPXMock) -> None:
        settled = {"success": True, "transaction": "0xabc", "network": "eip155:84532"}
        httpx_mock.add_response(url="https://facilitator.example/settle", json=settled)
        facilitator = HttpFacilitator("https://facilitator.example")
        assert await facilitator.settle(payment(), requirements()) == settled  # type: ignore[arg-type]

    async def test_reads_json_error_bodies(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=400, json={"isValid": False, "invalidReason": "invalid_signature"}
        )
        result = await HttpFacilitator("https://f.example").verify(payment(), requirements())  # type: ignore[arg-type]
        assert result.get("invalidReason") == "invalid_signature"

    async def test_sends_static_headers(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"isValid": True})
        facilitator = HttpFacilitator("https://f.example", headers={"Authorization": "Bearer t"})
        await facilitator.verify(payment(), requirements())  # type: ignore[arg-type]
        request = httpx_mock.get_request()
        assert request is not None and request.headers["authorization"] == "Bearer t"

    async def test_resolves_async_headers_per_request(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"isValid": True}, is_reusable=True)
        tokens = iter(["one", "two"])

        async def headers() -> dict[str, str]:
            return {"Authorization": f"Bearer {next(tokens)}"}

        facilitator = HttpFacilitator("https://f.example", headers=headers)
        await facilitator.verify(payment(), requirements())  # type: ignore[arg-type]
        await facilitator.verify(payment(), requirements())  # type: ignore[arg-type]
        assert [r.headers["authorization"] for r in httpx_mock.get_requests()] == [
            "Bearer one",
            "Bearer two",
        ]

    async def test_create_auth_headers_sends_each_endpoint_its_own(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url="https://f.example/verify", json={"isValid": True})
        httpx_mock.add_response(
            url="https://f.example/settle",
            json={"success": True, "transaction": "0xabc", "network": "eip155:8453"},
        )
        calls = 0

        async def create() -> dict[str, dict[str, str]]:
            nonlocal calls
            calls += 1
            return {
                "verify": {"Authorization": f"Bearer verify-{calls}"},
                "settle": {"Authorization": f"Bearer settle-{calls}"},
            }

        facilitator = HttpFacilitator(
            "https://f.example", headers={"X-Static": "1"}, create_auth_headers=create
        )
        await facilitator.verify(payment(), requirements())  # type: ignore[arg-type]
        await facilitator.settle(payment(), requirements())  # type: ignore[arg-type]
        verify, settle = httpx_mock.get_requests()
        assert verify.headers["authorization"] == "Bearer verify-1"
        assert settle.headers["authorization"] == "Bearer settle-2"
        assert verify.headers["x-static"] == settle.headers["x-static"] == "1"

    async def test_create_auth_headers_must_be_keyed_by_endpoint(self) -> None:
        facilitator = HttpFacilitator(
            "https://f.example",
            create_auth_headers=lambda: {"Authorization": "Bearer t"},  # pyright: ignore[reportArgumentType]
        )
        with pytest.raises(FacilitatorError, match="keyed by facilitator endpoint"):
            await facilitator.verify(payment(), requirements())  # type: ignore[arg-type]

    async def test_create_auth_headers_failure_raises_facilitator_error(self) -> None:
        def create() -> dict[str, dict[str, str]]:
            raise RuntimeError("key store down")

        facilitator = HttpFacilitator("https://f.example", create_auth_headers=create)
        with pytest.raises(FacilitatorError, match="auth headers failed: key store down"):
            await facilitator.settle(payment(), requirements())  # type: ignore[arg-type]

    async def test_uses_a_provided_client(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"isValid": True})
        async with httpx.AsyncClient(headers={"X-Client": "mine"}) as client:
            await HttpFacilitator("https://f.example", client=client).verify(
                payment(),  # type: ignore[arg-type]
                requirements(),  # type: ignore[arg-type]
            )
        request = httpx_mock.get_request()
        assert request is not None and request.headers["x-client"] == "mine"

    async def test_network_errors_raise_facilitator_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        with pytest.raises(FacilitatorError, match="/settle request failed"):
            await HttpFacilitator("https://f.example").settle(payment(), requirements())  # type: ignore[arg-type]

    async def test_non_json_bodies_raise_facilitator_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=502, text="bad gateway")
        with pytest.raises(FacilitatorError, match="HTTP 502"):
            await HttpFacilitator("https://f.example").verify(payment(), requirements())  # type: ignore[arg-type]

    async def test_malformed_bodies_raise_facilitator_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"isValid": "yes"}, is_reusable=True)
        with pytest.raises(FacilitatorError, match="isValid"):
            await HttpFacilitator("https://f.example").verify(payment(), requirements())  # type: ignore[arg-type]
        with pytest.raises(FacilitatorError, match="success"):
            await HttpFacilitator("https://f.example").settle(payment(), requirements())  # type: ignore[arg-type]

    def test_requires_a_url(self) -> None:
        with pytest.raises(ValueError):
            HttpFacilitator(" ")

    def test_resolve_facilitator(self) -> None:
        resolved = resolve_facilitator("https://f.example")
        assert isinstance(resolved, HttpFacilitator)
        assert resolve_facilitator(resolved) is resolved
        with pytest.raises(TypeError):
            resolve_facilitator(42)  # type: ignore[arg-type]


def x402_credential(request: dict[str, Any]) -> Credential:
    echo = ChallengeEcho(
        id="x402:abc", realm="r", method="evm", intent="charge", request=canonical_b64url(request)
    )
    return Credential(challenge=echo, payload={"from": PAYER})


class TestServerHelpers:
    def test_payment_required_header_dedupes_and_sets_defaults(self) -> None:
        accepts: list[Any] = [
            requirements(),
            requirements(asset=ASSET.lower()),
            requirements(amount="1"),
        ]
        value = payment_required_header(
            accepts,
            "https://api.example.com/paid",
        )
        assert value is not None
        decoded = decode_payment_required(value)
        assert [a["amount"] for a in decoded["accepts"]] == ["10000", "1"]
        assert decoded.get("error") == f"{PAYMENT_SIGNATURE_HEADER} header is required"

    def test_payment_required_header_without_offers(self) -> None:
        assert payment_required_header([], "https://api.example.com/paid") is None

    def test_payment_required_header_omits_offers_over_the_size_limit(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        accepts: list[Any] = [
            {**requirements(amount=str(n)), "extra": {"blob": "a" * 8000}} for n in range(1, 10)
        ]
        assert payment_required_header(accepts, "https://api.example.com/paid") is None
        assert "omitting x402 offers" in caplog.text

    def test_payment_response_header(self) -> None:
        credential = x402_credential({"methodDetails": {"chainId": 8453}})
        receipt = Receipt.success("0xabc", method="evm")
        value = payment_response_header(credential, receipt)
        assert value is not None
        assert decode_payment_response(value) == {
            "success": True,
            "transaction": "0xabc",
            "network": "eip155:8453",
            "payer": PAYER,
        }

    def test_payment_response_prefers_the_verified_payer(self) -> None:
        credential = x402_credential({"methodDetails": {"chainId": 8453}})
        receipt = Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference="0xabc",
            method="evm",
            payer=PAY_TO,
        )
        value = payment_response_header(credential, receipt)
        assert value is not None
        assert decode_payment_response(value).get("payer") == PAY_TO

    def test_no_payment_response_for_native_credentials(self) -> None:
        echo = ChallengeEcho(id="hmac-id", realm="r", method="evm", intent="charge", request="e30")
        credential = Credential(challenge=echo, payload={})
        assert not is_x402_credential(credential)
        assert payment_response_header(credential, Receipt.success("0xabc")) is None

    def test_get_request_url(self) -> None:
        class Starletteish:
            url = "https://api.example.com/paid?x=1"

        class Djangoish:
            def build_absolute_uri(self) -> str:
                return "https://api.example.com/django"

        class Broken:
            url = "/relative"

            def build_absolute_uri(self) -> str:
                raise RuntimeError("no host")

        assert get_request_url(Starletteish()) == "https://api.example.com/paid?x=1"
        assert get_request_url(Djangoish()) == "https://api.example.com/django"
        assert get_request_url(Broken()) is None
        assert get_request_url(object()) is None

    def test_x402_input_reads_the_payment_signature(self) -> None:
        class Request:
            url = "https://api.example.com/paid"
            headers = {"payment-signature": "abc"}

        value = x402_input(Request())
        assert value is not None
        assert value.resource_url == "https://api.example.com/paid"
        assert value.payment_signature == "abc"
        assert x402_input(None) is None

    def test_set_response_header(self) -> None:
        class Response:
            def __init__(self) -> None:
                self.headers: dict[str, str] = {}

        echo = ChallengeEcho(
            id="hmac-id", realm="r", method="tempo", intent="charge", request="e30"
        )
        verified = PaymentVerified(
            credential=Credential(challenge=echo, payload={}),
            receipt=Receipt.success("0xabc", method="tempo"),
        )
        response = Response()
        response.headers["Payment-Receipt"] = "value"
        verified.with_receipt(response)
        assert response.headers["Payment-Receipt"] == "value"
        assert response.headers["Cache-Control"] == "private"

        # Plain data and read-only headers are left alone.
        data = {"payer": PAYER}
        assert verified.with_receipt(data) == {"payer": PAYER}
        assert data == {"payer": PAYER}

        class ReadOnly:
            headers = ("a", "b")

        verified.with_receipt(ReadOnly())


class TestRouteBinding:
    def test_route_nonce_matches_mppx(self) -> None:
        # From mppx's RouteBinding.nonce with ox 0.14 (Json.canonicalize, base64url, sha256).
        extensions = {
            "mppx": {
                "info": {"method": "POST", "digest": "sha-256=:abc=:", "nonce": "ab" * 32},
                "schema": ROUTE_BINDING_SCHEMA,
            }
        }
        assert (
            route_nonce(
                accepted=requirements(),
                resource={"url": "https://api.example.com/paid?q=\u00e9"},
                extensions=extensions,
            )
            == "0x5bbc4bff9a4850f9faf5568b7937943ecf1db1992919cb2786343a0aa89f5f0e"
        )

    def test_route_extensions(self) -> None:
        extensions = route_extensions(
            http_method="post",
            scope={"route": "/paid", "http_method": "POST"},
            digest="sha-256=:abc=:",
            meta={"account": "acct_1", "_mpp_nonce": "issuance"},
        )
        info = extensions["mppx"]["info"]
        assert info == {
            "method": "POST",
            "_mppx_scope": canonical_b64url({"route": "/paid", "http_method": "POST"}),
            "digest": "sha-256=:abc=:",
            "opaque": canonical_b64url({"account": "acct_1"}),
        }
        assert extensions["mppx"]["schema"] == ROUTE_BINDING_SCHEMA
        assert route_extensions(http_method="GET")["mppx"]["info"] == {"method": "GET"}

    def test_route_requires_binding(self) -> None:
        assert not route_requires_binding()
        assert not route_requires_binding(meta={"_mpp_nonce": "issuance"})
        assert route_requires_binding(scope={"route": "/paid"})
        assert route_requires_binding(digest="sha-256=:abc=:")
        assert route_requires_binding(meta={"account": "acct_1"})

    def test_mismatched_route_bindings_keep_the_first(self) -> None:
        from mpp import Challenge

        first = Challenge(id="a", method="evm", intent="charge", request={"_mppx_scope": {"r": 1}})
        second = Challenge(id="b", method="evm", intent="charge", request={"_mppx_scope": {"r": 2}})
        offer: Any = requirements()
        value = challenges_payment_required_header(
            [first, second],
            lambda c: offer,
            "https://api.example.com/paid",
            "GET",
        )
        assert value is not None
        decoded = decode_payment_required(value)
        assert len(decoded["accepts"]) == 1
        assert "different routes" in decoded.get("error", "")


class TestFacilitatorSupported:
    async def test_http_facilitator_reads_get_supported(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://facilitator.example/supported",
            method="GET",
            json={
                "kinds": [
                    {
                        "x402Version": 2,
                        "scheme": "exact",
                        "network": "eip155:8453",
                        "extra": {"payTo": PAY_TO},
                    }
                ]
            },
        )
        supported = await HttpFacilitator("https://facilitator.example/").supported()
        assert supported["kinds"][0].get("extra", {})["payTo"] == PAY_TO
        request = httpx_mock.get_request()
        assert request is not None and request.method == "GET"

    async def test_supported_rejects_a_malformed_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"kinds": "nope"})
        with pytest.raises(FacilitatorError, match="kinds"):
            await HttpFacilitator("https://f.example").supported()

    async def test_supported_sends_only_a_configured_content_type(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(json={"kinds": []})
        httpx_mock.add_response(json={"kinds": []})
        await HttpFacilitator("https://f.example").supported()
        await HttpFacilitator(
            "https://f.example", headers={"Content-Type": "application/x-custom"}
        ).supported()
        first, second = httpx_mock.get_requests()
        assert "content-type" not in first.headers
        assert second.headers["content-type"] == "application/x-custom"

    async def test_supported_escapes_signer_keys_in_errors(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"kinds": [], "signers": {"a\nforged": "x"}})
        with pytest.raises(FacilitatorError) as error:
            await HttpFacilitator("https://f.example").supported()
        assert "\n" not in str(error.value)

    async def test_supported_raises_on_http_errors(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=500, json={})
        with pytest.raises(FacilitatorError, match="500"):
            await HttpFacilitator("https://f.example").supported()

    async def test_supported_raises_on_transport_errors(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("down"))
        with pytest.raises(FacilitatorError, match="request failed"):
            await HttpFacilitator("https://f.example").supported()

    async def test_supported_raises_when_auth_headers_fail(self) -> None:
        async def create_auth_headers() -> Any:
            raise RuntimeError("no key")

        facilitator = HttpFacilitator("https://f.example", create_auth_headers=create_auth_headers)
        with pytest.raises(FacilitatorError, match="auth headers failed"):
            await facilitator.supported()

    async def test_supported_uses_the_given_client(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="https://f.example/supported", json={"kinds": []})
        async with httpx.AsyncClient() as client:
            supported = await HttpFacilitator("https://f.example", client=client).supported()
        assert supported == {"kinds": []}

    async def test_supported_sends_one_field_per_header_name(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"kinds": []})
        facilitator = HttpFacilitator(
            "https://f.example",
            headers={"Authorization": "Bearer generic"},
            create_auth_headers=lambda: {"supported": {"authorization": "Bearer endpoint"}},
        )
        await facilitator.supported()
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers.get_list("authorization") == ["Bearer endpoint"]

    async def test_supported_has_a_total_deadline(self) -> None:
        class Trickle(httpx.AsyncByteStream):
            async def __aiter__(self) -> AsyncIterator[bytes]:
                while True:
                    yield b" "
                    await asyncio.sleep(0.01)

        class Slow(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, stream=Trickle())

        async with httpx.AsyncClient(transport=Slow()) as client:
            facilitator = HttpFacilitator("https://f.example", timeout=0.2, client=client)
            with pytest.raises(FacilitatorError, match="did not answer within"):
                await facilitator.supported()

    async def test_supported_caps_the_body_size(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(content=b" " * (1024 * 1024 + 1))
        with pytest.raises(FacilitatorError, match="more than 1048576 bytes"):
            await HttpFacilitator("https://f.example").supported()

    async def test_supported_refuses_a_compressed_body(self, httpx_mock: HTTPXMock) -> None:
        # 1 MiB of spaces gzips to about 1 KiB: the cap must count wire bytes.
        httpx_mock.add_response(
            content=gzip.compress(b" " * (1024 * 1024 + 1)), headers={"content-encoding": "gzip"}
        )
        with pytest.raises(FacilitatorError, match="compressed body"):
            await HttpFacilitator("https://f.example").supported()
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers.get_list("accept-encoding") == ["identity"]

    def test_supported_runs_under_trio(self) -> None:
        def answer(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"kinds": []})

        async def run() -> Any:
            async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
                return await HttpFacilitator("https://f.example", client=client).supported()

        assert anyio.run(run, backend="trio") == {"kinds": []}

    async def test_supported_errors_omit_httpx_messages(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.LocalProtocolError("Illegal header value b'secret\\n'"))
        with pytest.raises(FacilitatorError) as error:
            await HttpFacilitator("https://f.example").supported()
        assert "secret" not in str(error.value)
        assert error.value.__cause__ is None and error.value.__suppress_context__

    async def test_supported_does_not_follow_redirects(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://f.example/supported",
            status_code=302,
            headers={"location": "http://downgrade.example/supported"},
        )
        async with httpx.AsyncClient(follow_redirects=True) as client:
            with pytest.raises(FacilitatorError, match="302"):
                await pay_to(
                    HttpFacilitator("https://f.example", client=client), network="eip155:8453"
                )
        assert len(httpx_mock.get_requests()) == 1

    @pytest.mark.parametrize(
        ("url", "trust_env"), [("http://127.0.0.1:4021", False), ("https://f.example", True)]
    )
    async def test_supported_ignores_environment_proxies_for_cleartext(
        self, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch, url: str, trust_env: bool
    ) -> None:
        created: list[bool] = []
        real = httpx.AsyncClient

        class Recording(real):  # type: ignore[misc, valid-type]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                created.append(kwargs.get("trust_env", True))
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", Recording)
        httpx_mock.add_response(json={"kinds": []})
        await HttpFacilitator(url).supported()
        assert created == [trust_env]

    async def test_supported_rejects_deeply_nested_json(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            content=b"[" * 100_000 + b"]" * 100_000, headers={"content-type": "application/json"}
        )
        with pytest.raises(FacilitatorError, match="/supported returned"):
            await HttpFacilitator("https://f.example").supported()

    @pytest.mark.parametrize(
        "body",
        [
            {"kinds": [{"x402Version": "2", "scheme": "exact", "network": "eip155:8453"}]},
            {"kinds": [], "extensions": [1]},
            {"kinds": [], "signers": {"eip155:*": "0xabc"}},
            {"kinds": [{"x402Version": 2.5, "scheme": "exact", "network": "eip155:8453"}]},
            {"kinds": [{"x402Version": 2, "scheme": "exact", "network": "n", "extra": None}]},
            {"kinds": [], "extensions": None},
            {"kinds": [], "signers": None},
        ],
    )
    async def test_supported_validates_its_fields(
        self, httpx_mock: HTTPXMock, body: dict[str, Any]
    ) -> None:
        httpx_mock.add_response(json=body)
        with pytest.raises(FacilitatorError, match="supportedResponse"):
            await HttpFacilitator("https://f.example").supported()

    async def test_pay_to_rejects_a_malformed_supported_response(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                return {"kinds": "nope"}

        with pytest.raises(FacilitatorError, match="/supported returned"):
            await pay_to(Stub(), network="eip155:8453")  # type: ignore[arg-type]

    async def test_pay_to_picks_the_v2_kind_for_the_scheme_and_network(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                return {
                    "kinds": [
                        {
                            "x402Version": 1,
                            "scheme": "exact",
                            "network": "eip155:8453",
                            "extra": {"payTo": "0x" + "11" * 20},
                        },
                        {
                            "x402Version": 2,
                            "scheme": "upto",
                            "network": "eip155:8453",
                            "extra": {"payTo": "0x" + "22" * 20},
                        },
                        {
                            "x402Version": 2,
                            "scheme": "exact",
                            "network": "eip155:8453",
                            "extra": {"payTo": PAY_TO.lower()},
                        },
                    ]
                }

        assert await pay_to(Stub(), network="eip155:8453") == PAY_TO  # type: ignore[arg-type]
        assert await pay_to(Stub(), network="eip155:8453", scheme="upto") == "0x" + "22" * 20  # type: ignore[arg-type]

    async def test_pay_to_accepts_a_facilitator_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url="https://facilitator.example/supported",
            json={
                "kinds": [
                    {
                        "x402Version": 2,
                        "scheme": "exact",
                        "network": "eip155:8453",
                        "extra": {"payTo": PAY_TO},
                    }
                ]
            },
        )
        assert await pay_to("https://facilitator.example", network="eip155:8453") == PAY_TO

    @pytest.mark.parametrize(
        "url", ["http://facilitator.example", "http://10.0.0.1:8080", "ftp://facilitator.example"]
    )
    async def test_pay_to_refuses_cleartext_facilitators(self, url: str) -> None:
        with pytest.raises(FacilitatorError, match="needs an https:// facilitator URL"):
            await pay_to(url, network="eip155:8453")

    @pytest.mark.parametrize(
        "url", ["https:", "https://", "https:/facilitator.example", "https:facilitator.example"]
    )
    async def test_pay_to_refuses_hostless_https_urls(
        self, httpx_mock: HTTPXMock, url: str
    ) -> None:
        # An injected client would resolve the path against its own base URL, here cleartext.
        async with httpx.AsyncClient(base_url="http://facilitator.example") as client:
            facilitator = HttpFacilitator(url, client=client)
            with pytest.raises(FacilitatorError, match="needs an https:// facilitator URL"):
                await pay_to(facilitator, network="eip155:8453")
        assert httpx_mock.get_requests() == []

    @pytest.mark.parametrize(
        "url", ["http://localhost:4021", "http://127.0.0.1:4021", "http://[::1]:4021"]
    )
    async def test_pay_to_allows_loopback_http(self, httpx_mock: HTTPXMock, url: str) -> None:
        kind = {"x402Version": 2, "scheme": "exact", "network": "eip155:8453"}
        httpx_mock.add_response(json={"kinds": [{**kind, "extra": {"payTo": PAY_TO}}]})
        assert await pay_to(url, network="eip155:8453") == PAY_TO

    async def test_pay_to_accepts_a_synchronous_supported(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...

            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...

            def supported(self) -> Any:
                kind = {"x402Version": 2, "scheme": "exact", "network": "eip155:8453"}
                return {"kinds": [{**kind, "extra": {"payTo": PAY_TO}}]}

        assert await pay_to(Stub(), network="eip155:8453") == PAY_TO  # type: ignore[arg-type]

    async def test_pay_to_needs_supported(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...

        with pytest.raises(FacilitatorError, match="does not implement"):
            await pay_to(Stub(), network="eip155:8453")  # type: ignore[arg-type]

    async def test_pay_to_fails_on_a_missing_kind_or_bad_address(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                return {
                    "kinds": [
                        {
                            "x402Version": 2,
                            "scheme": "exact",
                            "network": "eip155:8453",
                            "extra": {"payTo": "nope"},
                        }
                    ]
                }

        with pytest.raises(FacilitatorError, match="publishes no payTo"):
            await pay_to(Stub(), network="eip155:8453")  # type: ignore[arg-type]

    async def test_pay_to_names_the_evm_extra_before_discovery(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                raise AssertionError("discovery must not run without the evm extra")

        monkeypatch.setitem(sys.modules, "eth_utils.address", None)
        with pytest.raises(ImportError, match=r"pympp\[evm\]"):
            await pay_to(Stub(), network="eip155:8453")  # type: ignore[arg-type]

    async def test_pay_to_skips_matching_kinds_without_a_valid_pay_to(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                kind = {"x402Version": 2, "scheme": "exact", "network": "eip155:8453"}
                return {
                    "kinds": [
                        kind,
                        {**kind, "extra": {"payTo": "nope"}},
                        {**kind, "extra": {"payTo": PAY_TO.lower()}},
                    ]
                }

        assert await pay_to(Stub(), network="eip155:8453") == PAY_TO  # type: ignore[arg-type]
        with pytest.raises(FacilitatorError, match="publishes no payTo"):
            await pay_to(Stub(), network="eip155:1")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("published", "message"),
        [
            (["0x" + "00" * 20], "publishes no payTo"),
            ([PAY_TO, "0x" + "33" * 20], "2 different payTo addresses"),
        ],
    )
    async def test_pay_to_rejects_unpayable_or_ambiguous_addresses(
        self, published: list[str], message: str
    ) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                kind = {"x402Version": 2, "scheme": "exact", "network": "eip155:8453"}
                return {"kinds": [{**kind, "extra": {"payTo": a}} for a in published]}

        with pytest.raises(FacilitatorError, match=message):
            await pay_to(Stub(), network="eip155:8453")  # type: ignore[arg-type]

    async def test_pay_to_accepts_duplicates_of_one_address(self) -> None:
        class Stub:
            async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any: ...
            async def supported(self) -> Any:
                kind = {"x402Version": 2, "scheme": "exact", "network": "eip155:8453"}
                return {
                    "kinds": [
                        {**kind, "extra": {"payTo": PAY_TO}},
                        {**kind, "extra": {"payTo": PAY_TO.lower()}},
                    ]
                }

        assert await pay_to(Stub(), network="eip155:8453") == PAY_TO  # type: ignore[arg-type]
