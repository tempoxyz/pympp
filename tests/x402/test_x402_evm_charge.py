"""Ports mppx ``x402/server/EvmCharge.test.ts`` (route binding of x402 credentials)."""

import base64
import json
import time
from typing import Any

import pytest
from eth_account import Account

from mpp import evm
from mpp.evm import assets
from mpp.evm import server as evm_server
from mpp.server import Mpp, Request, Response
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_RESPONSE_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    Extension,
    PaymentRequired,
    PaymentRequirements,
    ResourceInfo,
    decode_payment_required,
    encode_payment_signature,
    route_binding_nonce,
)
from mpp.x402._evm_charge import requirements_match

SECRET_KEY = "test-secret-key-test-secret-key-32"
TRANSACTION = "0x" + "1" * 64
account = Account.from_key("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
recipient = Account.from_key("0x" + "42" * 32).address
URL = "https://example.com/paid-scoped"
SCOPE = "GET /paid-scoped"


class Facilitator:
    def __init__(self) -> None:
        self.reached: list[str] = []

    async def verify(self, payload: Any, requirements: Any) -> dict[str, Any]:
        self.reached.append("verify")
        return {"isValid": True}

    async def settle(self, payload: Any, requirements: PaymentRequirements) -> dict[str, Any]:
        self.reached.append("settle")
        return {"network": requirements.network, "success": True, "transaction": TRANSACTION}


def create_mppx(
    route_binding: evm_server.RouteBindingMode | None = None,
) -> tuple[Mpp, Facilitator]:
    facilitator = Facilitator()
    options = (
        evm_server.X402Options(facilitator=facilitator, route_binding=route_binding)
        if route_binding
        else evm_server.X402Options(facilitator=facilitator)
    )
    mppx = Mpp(
        methods=[
            evm_server.charge(currency=assets.BASE_SEPOLIA_USDC, recipient=recipient, x402=options)
        ],
        secret_key=SECRET_KEY,
    )
    return mppx, facilitator


def read_challenge(response: Response) -> PaymentRequired:
    return decode_payment_required(response.headers[PAYMENT_REQUIRED_HEADER])


def third_party_credential(
    *,
    accepted: PaymentRequirements,
    extensions: dict[str, Extension] | None = None,
    nonce: str | None = None,
    resource: ResourceInfo | None = None,
    valid_before: int | None = None,
) -> str:
    """The credential a spec-compliant third-party x402 wallet produces."""
    now = int(time.time())
    authorization = {
        "from": account.address,
        "nonce": nonce or "0x" + "ab" * 32,
        "to": accepted.pay_to,
        "validAfter": str(now - 600),
        "validBefore": str(valid_before or now + int(accepted.max_timeout_seconds)),
        "value": accepted.amount,
    }
    extra = accepted.extra or {}
    signed = account.sign_typed_data(
        full_message=evm.authorization_typed_data(
            authorization=evm.AuthorizationConfig(name=extra["name"], version=extra["version"]),
            chain_id=int(accepted.network.removeprefix("eip155:")),
            currency=accepted.asset,
            from_=authorization["from"],
            to=authorization["to"],
            value=authorization["value"],
            valid_after=authorization["validAfter"],
            valid_before=authorization["validBefore"],
            nonce=authorization["nonce"],
        )
    )
    value: dict[str, Any] = {
        "accepted": accepted.to_dict(),
        "payload": {
            "authorization": authorization,
            "signature": "0x" + bytes(signed.signature).hex(),
        },
        "x402Version": 2,
    }
    if extensions:
        value["extensions"] = {key: ext.to_dict() for key, ext in extensions.items()}
    if resource:
        value["resource"] = resource.to_dict()
    return encode_payment_signature(value)


def route_bound_extensions(
    extensions: dict[str, Extension], info: dict[str, Any] | None = None
) -> dict[str, Extension]:
    mppx = extensions["mppx"]
    return {
        **extensions,
        "mppx": Extension(
            info={**mppx.info, "nonce": "client-salt", **(info or {})}, schema=mppx.schema_
        ),
    }


def route_bound_credential(
    *, accepted: PaymentRequirements, extensions: dict[str, Extension], resource: ResourceInfo
) -> str:
    return third_party_credential(
        accepted=accepted,
        extensions=extensions,
        resource=resource,
        nonce=route_binding_nonce(accepted=accepted, extensions=extensions, resource=resource),
    )


def request(url: str, credential: str | None = None) -> Request:
    return Request("GET", url, headers={PAYMENT_SIGNATURE_HEADER: credential} if credential else {})


async def challenged(route: Any, url: str = URL) -> PaymentRequired:
    result = await route(request(url))
    assert result.status == 402
    return read_challenge(result.challenge)


async def test_scoped_charge_requires_route_bound_nonce_by_default() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.extensions is not None
    info = challenge.extensions["mppx"].info
    assert info["_mppx_scope"] == SCOPE
    assert info["method"] == "GET"
    assert "nonce" not in info

    result = await route(
        request(
            URL,
            third_party_credential(
                accepted=challenge.accepts[0],
                extensions=challenge.extensions,
                resource=challenge.resource,
            ),
        )
    )
    assert result.status == 402
    assert (
        read_challenge(result.challenge).error
        == "Payment verification failed: x402 payment payload does not bind required route metadata."
    )
    assert facilitator.reached == []


async def test_resource_mode_requires_the_resource_to_be_echoed() -> None:
    mppx, facilitator = create_mppx("resource")
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    result = await route(request(URL, third_party_credential(accepted=challenge.accepts[0])))
    assert result.status == 402
    assert (
        read_challenge(result.challenge).error
        == "Payment verification failed: x402 payment payload resource does not match route resource."
    )
    assert facilitator.reached == []


async def test_resource_mode_accepts_an_enriched_resource() -> None:
    mppx, facilitator = create_mppx("resource")
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    enriched = challenge.resource.model_copy(update={"description": "A paid route."})
    result = await route(
        request(URL, third_party_credential(accepted=challenge.accepts[0], resource=enriched))
    )
    assert result.status == 200
    assert facilitator.reached == ["verify", "settle"]


async def test_scoped_charge_rejects_credential_for_another_route() -> None:
    mppx, facilitator = create_mppx("resource")
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    other = mppx.evm.charge(amount="0.25", scope="GET /other")
    challenge = await challenged(other, "https://example.com/other")
    result = await route(
        request(
            URL,
            third_party_credential(
                accepted=challenge.accepts[0],
                extensions=challenge.extensions,
                resource=challenge.resource,
            ),
        )
    )
    assert result.status == 402
    assert facilitator.reached == []


async def test_scoped_charge_rejects_altered_requirements() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    altered = challenge.accepts[0].model_copy(update={"amount": "1"})
    result = await route(
        request(URL, third_party_credential(accepted=altered, resource=challenge.resource))
    )
    assert result.status == 402
    assert facilitator.reached == []


async def test_unscoped_charge_is_payable_by_third_party_clients() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25")
    url = "https://example.com/paid"
    challenge = await challenged(route, url)
    result = await route(
        request(
            url,
            third_party_credential(accepted=challenge.accepts[0], resource=challenge.resource),
        )
    )
    assert result.status == 200
    response = result.with_receipt(Response.json({"ok": True}))  # type: ignore[attr-defined]
    assert PAYMENT_RESPONSE_HEADER in response.headers
    assert facilitator.reached == ["verify", "settle"]


async def test_unscoped_charge_rejects_unrelated_resource() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25")
    url = "https://example.com/paid"
    challenge = await challenged(route, url)
    other = challenge.resource.model_copy(update={"url": "https://example.com/other"})
    result = await route(
        request(url, third_party_credential(accepted=challenge.accepts[0], resource=other))
    )
    assert result.status == 402
    assert facilitator.reached == []


async def test_claimed_mppx_binding_is_verified_in_full() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.extensions is not None
    result = await route(
        request(
            URL,
            third_party_credential(
                accepted=challenge.accepts[0],
                extensions=route_bound_extensions(challenge.extensions),
                resource=challenge.resource,
            ),
        )
    )
    assert result.status == 402
    assert facilitator.reached == []


@pytest.mark.parametrize("mode", [None, "required"])
async def test_valid_mppx_bound_credential_is_payable(mode: Any) -> None:
    mppx, facilitator = create_mppx(mode)
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.extensions is not None
    credential = route_bound_credential(
        accepted=challenge.accepts[0],
        extensions=route_bound_extensions(challenge.extensions),
        resource=challenge.resource,
    )
    result = await route(request(URL, credential))
    assert result.status == 200
    assert facilitator.reached == ["verify", "settle"]


async def test_bound_credential_rejects_mismatched_resource() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.extensions is not None
    credential = route_bound_credential(
        accepted=challenge.accepts[0],
        extensions=route_bound_extensions(challenge.extensions),
        resource=challenge.resource.model_copy(update={"url": "https://example.com/other"}),
    )
    assert (await route(request(URL, credential))).status == 402
    assert facilitator.reached == []


async def test_bound_credential_rejects_altered_extensions() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.extensions is not None
    credential = route_bound_credential(
        accepted=challenge.accepts[0],
        extensions=route_bound_extensions(challenge.extensions, {"_mppx_scope": "GET /other"}),
        resource=challenge.resource,
    )
    assert (await route(request(URL, credential))).status == 402
    assert facilitator.reached == []


async def test_required_mode_keeps_scoped_charges_mppx_only() -> None:
    mppx, facilitator = create_mppx("required")
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    result = await route(
        request(
            URL, third_party_credential(accepted=challenge.accepts[0], resource=challenge.resource)
        )
    )
    assert result.status == 402
    assert facilitator.reached == []


async def test_required_mode_leaves_unscoped_charges_payable() -> None:
    mppx, facilitator = create_mppx("required")
    route = mppx.evm.charge(amount="0.25")
    url = "https://example.com/paid"
    challenge = await challenged(route, url)
    result = await route(
        request(
            url, third_party_credential(accepted=challenge.accepts[0], resource=challenge.resource)
        )
    )
    assert result.status == 200
    assert facilitator.reached == ["verify", "settle"]


async def test_payment_required_header_shape() -> None:
    mppx, _ = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.error == "Payment is required."
    assert challenge.resource == ResourceInfo(url=URL)
    assert challenge.accepts[0].to_dict() == {
        "amount": "250000",
        "asset": assets.BASE_SEPOLIA_USDC.address,
        "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        "maxTimeoutSeconds": 300,
        "network": "eip155:84532",
        "payTo": recipient,
        "scheme": "exact",
    }
    assert challenge.extensions is not None
    mppx_extension = challenge.extensions["mppx"].to_dict()
    assert mppx_extension["schema"] == {
        "additionalProperties": False,
        "properties": {
            "_mppx_scope": {"type": "string"},
            "digest": {"type": "string"},
            "method": {"type": "string"},
            "nonce": {"type": "string"},
            "opaque": {"type": "string"},
        },
        "required": ["method"],
        "type": "object",
    }
    assert set(mppx_extension["info"]) == {"method", "_mppx_scope", "opaque"}


# -- pympp#320 hardening -----------------------------------------------------------------------


def problem(result: Any) -> dict[str, Any]:
    return json.loads(result.challenge.body)


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (
            base64.b64encode(json.dumps({"x402Version": 1}).encode()).decode(),
            "x402Version must be 2",
        ),
        ("A" * 70_000, "header is too large"),
        ("not base64 json", "not base64 JSON"),
    ],
    ids=["v1", "oversized", "garbage"],
)
async def test_malformed_payment_signature(header: str, reason: str) -> None:
    mppx, facilitator = create_mppx()
    result = await mppx.evm.charge(amount="0.25")(request(URL, header))
    assert result.status == 402
    detail = f"Credential is malformed: invalid PAYMENT-SIGNATURE header: {reason}."
    assert problem(result)["detail"] == detail
    assert read_challenge(result.challenge).error == detail
    assert facilitator.reached == []


async def test_composed_server_reports_a_malformed_payment() -> None:
    mppx, _ = create_mppx()
    v1 = base64.b64encode(json.dumps({"x402Version": 1}).encode()).decode()
    result = await mppx.compose((mppx.evm.charge, {"amount": "0.25"}))(request(URL, v1))
    assert result.status == 402
    assert problem(result)["type"].endswith("/malformed-credential")


async def test_addresses_compare_case_insensitively() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25")
    url = "https://example.com/paid"
    challenge = await challenged(route, url)
    accepted = challenge.accepts[0]
    lowered = accepted.model_copy(
        update={"asset": accepted.asset.lower(), "pay_to": accepted.pay_to.lower()}
    )
    result = await route(
        request(url, third_party_credential(accepted=lowered, resource=challenge.resource))
    )
    assert result.status == 200
    assert facilitator.reached == ["verify", "settle"]


def test_booleans_never_equal_numbers() -> None:
    accepted = PaymentRequirements.model_validate(
        {
            "amount": "1",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "extra": {"flag": True},
            "maxTimeoutSeconds": 60,
            "network": "eip155:84532",
            "payTo": recipient,
            "scheme": "exact",
        }
    )
    numeric = accepted.model_copy(update={"extra": {"flag": 1}})
    assert requirements_match(accepted, accepted)
    assert not requirements_match(accepted, numeric)


async def test_rejects_x402_authorizations_valid_for_too_long() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25")
    url = "https://example.com/paid"
    challenge = await challenged(route, url)
    credential = third_party_credential(
        accepted=challenge.accepts[0],
        resource=challenge.resource,
        valid_before=int(time.time()) + 30 * 86_400,
    )
    result = await route(request(url, credential))
    assert result.status == 402
    assert read_challenge(result.challenge).error == (
        "Payment verification failed: EVM authorization is valid for too long."
    )
    assert facilitator.reached == []


async def test_route_bound_nonce_compares_case_insensitively() -> None:
    mppx, facilitator = create_mppx()
    route = mppx.evm.charge(amount="0.25", scope=SCOPE)
    challenge = await challenged(route)
    assert challenge.extensions is not None
    extensions = route_bound_extensions(challenge.extensions)
    nonce = route_binding_nonce(
        accepted=challenge.accepts[0], extensions=extensions, resource=challenge.resource
    )
    credential = third_party_credential(
        accepted=challenge.accepts[0],
        extensions=extensions,
        resource=challenge.resource,
        nonce="0x" + nonce[2:].upper(),
    )
    assert (await route(request(URL, credential))).status == 200
    assert facilitator.reached == ["verify", "settle"]
