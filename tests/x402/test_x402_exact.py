import re
from collections.abc import Callable
from typing import Any

import pytest

from mpp import Challenge
from mpp.evm import chains, tokens
from mpp.x402 import _exact, assets, decode_payment_signature, route_binding_nonce
from mpp.x402.assets import Eip3009Transfer

USDC = assets.define(
    address="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    decimals=6,
    network="eip155:84532",
    transfer=Eip3009Transfer(name="USDC", version="2"),
)
MPPX_EXTENSIONS = {
    "mppx": {
        "info": {"method": "GET"},
        "schema": {
            "additionalProperties": False,
            "properties": {"method": {"type": "string"}, "nonce": {"type": "string"}},
            "required": ["method"],
            "type": "object",
        },
    }
}
_UNSET: Any = object()


def challenge(**overrides: Any) -> Challenge:
    request: dict[str, Any] = {
        "amount": "10000",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        "maxTimeoutSeconds": 60,
        "network": "eip155:84532",
        "payTo": "0x2222222222222222222222222222222222222222",
        "scheme": "exact",
        "extensions": MPPX_EXTENSIONS,
        "resource": {"url": "https://example.com/paid"},
    }
    for key, value in overrides.items():
        if value is None:
            request.pop(key, None)
        else:
            request[key] = value
    return Challenge(
        id="x402-test", intent="charge", method="evm", realm="example.com", request=request
    )


def policy(signer: Any, **overrides: Any) -> _exact.Policy:
    values: dict[str, Any] = {
        "account": signer,
        "currencies": (USDC,),
        "max_amount": "0.01",
        "networks": (chains.BASE_SEPOLIA,),
    }
    values.update(overrides)
    return _exact.Policy(**values)


async def test_enforces_amount_network_and_currency_policy(signer: Any) -> None:
    config = policy(signer)
    with pytest.raises(ValueError, match=r"x402 exact amount exceeds maxAmount\."):
        await _exact.create_credential(challenge(amount="10001"), config)
    with pytest.raises(ValueError, match=r"x402 exact chain ID is not allowed: 8453\."):
        await _exact.create_credential(challenge(network="eip155:8453"), config)
    with pytest.raises(
        ValueError,
        match=r"x402 exact currency is not allowed: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913\.",
    ):
        await _exact.create_credential(
            challenge(asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), config
        )
    assert signer.calls == []


async def test_requires_network_policy_for_raw_currencies(signer: Any) -> None:
    with pytest.raises(ValueError, match=r"x402 exact raw currency allowlists require networks\."):
        await _exact.create_credential(
            challenge(), policy(signer, currencies=(USDC.address,), networks=None)
        )


async def test_uses_known_asset_metadata_for_policy(signer: Any) -> None:
    credential = await _exact.create_credential(
        challenge(), policy(signer, currencies=(assets.BASE_SEPOLIA_USDC,), networks=None)
    )
    assert len(signer.calls) == 1
    assert decode_payment_signature(credential).accepted.asset == assets.BASE_SEPOLIA_USDC.address


async def test_pins_known_asset_policy_to_its_network(signer: Any) -> None:
    with pytest.raises(
        ValueError,
        match=r"x402 exact currency is not allowed: 0x036CbD53842c5426634e7929541eC2318f3dCF7e\.",
    ):
        await _exact.create_credential(
            challenge(network="eip155:8453"),
            policy(signer, currencies=(assets.BASE_SEPOLIA_USDC,), networks=None),
        )
    assert signer.calls == []


async def test_accepts_token_sets_for_policy_and_decimals(signer: Any) -> None:
    config = policy(signer, currencies=tokens.POPULAR, networks=None, max_amount="1")
    credential = await _exact.create_credential(challenge(amount="1000000"), config)
    assert len(signer.calls) == 1
    assert decode_payment_signature(credential).accepted.asset == assets.BASE_SEPOLIA_USDC.address
    with pytest.raises(ValueError, match=r"x402 exact amount exceeds maxAmount\."):
        await _exact.create_credential(challenge(amount="1000001"), config)
    assert len(signer.calls) == 1


async def test_pins_token_policy_to_available_networks(signer: Any) -> None:
    with pytest.raises(
        ValueError,
        match=r"x402 exact currency is not allowed: 0x036CbD53842c5426634e7929541eC2318f3dCF7e\.",
    ):
        await _exact.create_credential(
            challenge(network="eip155:999999"),
            policy(signer, currencies=tokens.POPULAR, networks=None, max_amount="1"),
        )
    assert signer.calls == []


async def test_signs_mppx_bound_payloads(signer: Any) -> None:
    payload = decode_payment_signature(await _exact.create_credential(challenge(), policy(signer)))
    assert len(signer.calls) == 1
    assert payload.x402_version == 2
    assert payload.accepted.scheme == "exact"
    assert payload.extensions is not None
    info = payload.extensions["mppx"].info
    assert info["method"] == "GET"
    assert re.fullmatch(r"[0-9a-f]{64}", info["nonce"])
    assert payload.resource is not None
    assert payload.payload.authorization.nonce == route_binding_nonce(  # type: ignore[union-attr]
        accepted=payload.accepted, extensions=payload.extensions, resource=payload.resource
    )
    assert payload.payload.signature == "0x1234"


async def test_signs_the_eip3009_typed_data(signer: Any) -> None:
    payload = decode_payment_signature(await _exact.create_credential(challenge(), policy(signer)))
    authorization = payload.payload.authorization  # type: ignore[union-attr]
    [typed_data] = signer.calls
    assert typed_data["primaryType"] == "TransferWithAuthorization"
    assert typed_data["domain"] == {
        "chainId": 84532,
        "name": "USDC",
        "verifyingContract": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "version": "2",
    }
    assert typed_data["message"] == {
        "from": "0x1111111111111111111111111111111111111111",
        "nonce": authorization.nonce,
        "to": "0x2222222222222222222222222222222222222222",
        "validAfter": int(authorization.valid_after),
        "validBefore": int(authorization.valid_before),
        "value": 10000,
    }
    assert int(authorization.valid_before) - int(authorization.valid_after) == 660


async def test_uses_fresh_route_bound_nonces(signer: Any) -> None:
    first = decode_payment_signature(await _exact.create_credential(challenge(), policy(signer)))
    second = decode_payment_signature(await _exact.create_credential(challenge(), policy(signer)))
    assert first.extensions
    assert second.extensions
    assert first.extensions["mppx"].info["nonce"] != second.extensions["mppx"].info["nonce"]
    assert first.payload.authorization.nonce != second.payload.authorization.nonce  # type: ignore[union-attr]


async def test_signs_standard_payloads_with_random_nonces(signer: Any) -> None:
    first = decode_payment_signature(
        await _exact.create_credential(challenge(extensions=None), policy(signer))
    )
    second = decode_payment_signature(
        await _exact.create_credential(challenge(extensions=None), policy(signer))
    )
    assert len(signer.calls) == 2
    assert first.extensions is None
    assert first.resource is not None
    assert first.resource.url == "https://example.com/paid"
    nonce = first.payload.authorization.nonce  # type: ignore[union-attr]
    assert re.fullmatch(r"0x[0-9a-f]{64}", nonce)
    assert nonce != second.payload.authorization.nonce  # type: ignore[union-attr]


async def test_preserves_non_mppx_extensions(signer: Any) -> None:
    extensions = {"bazaar": {"info": {"catalog": "cdp"}, "schema": {"type": "object"}}}
    payload = decode_payment_signature(
        await _exact.create_credential(challenge(extensions=extensions), policy(signer))
    )
    assert payload.extensions is not None
    assert {key: value.to_dict() for key, value in payload.extensions.items()} == extensions
    assert re.fullmatch(r"0x[0-9a-f]{64}", payload.payload.authorization.nonce)  # type: ignore[union-attr]


async def test_rejects_challenges_without_resource(signer: Any) -> None:
    with pytest.raises(ValueError, match=r"x402 exact EIP-3009 requires resource information\."):
        await _exact.create_credential(challenge(extensions=None, resource=None), policy(signer))
    assert signer.calls == []


async def test_requires_a_signer() -> None:
    with pytest.raises(ValueError, match=r"x402 exact requires a typed-data signer\."):
        await _exact.create_credential(challenge(), _exact.Policy())


async def test_context_account_takes_precedence(
    signer: Any, make_signer: Callable[..., Any]
) -> None:
    other = make_signer(address="0x3333333333333333333333333333333333333333")
    payload = decode_payment_signature(
        await _exact.create_credential(challenge(), policy(signer), account=other)
    )
    assert payload.payload.authorization.from_ == other.address  # type: ignore[union-attr]
    assert signer.calls == []


async def test_rejects_permit2_and_missing_token_metadata(signer: Any) -> None:
    with pytest.raises(ValueError, match=r"x402 exact permit2 signing is not implemented yet\."):
        await _exact.create_credential(
            challenge(extra={"assetTransferMethod": "permit2", "name": "USDC", "version": "2"}),
            policy(signer),
        )
    with pytest.raises(ValueError, match=r"x402 exact EIP-3009 requires token name and version\."):
        await _exact.create_credential(challenge(extra={"version": "2"}), policy(signer))


def test_recognizes_bound_and_standard_challenges(signer: Any) -> None:
    assert _exact.can_handle_challenge(challenge(), policy(signer))
    assert _exact.can_handle_challenge(challenge(extensions=None), policy(signer))


@pytest.mark.parametrize(
    "overrides",
    [
        {"resource": None},
        {"extra": {"assetTransferMethod": "permit2", "name": "USDC", "version": "2"}},
        {"extra": {"assetTransferMethod": "eip3009", "version": "2"}},
        {"extra": {"assetTransferMethod": "eip3009", "name": "USDC"}},
        {"network": "eip155:8453"},
        {"amount": "10001"},
    ],
    ids=["missing-resource", "permit2", "missing-name", "missing-version", "network", "amount"],
)
def test_does_not_claim_unsupported_challenges(signer: Any, overrides: dict[str, Any]) -> None:
    assert not _exact.can_handle_challenge(challenge(**overrides), policy(signer))
