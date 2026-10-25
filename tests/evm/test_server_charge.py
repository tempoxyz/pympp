import httpx
import pytest
from eth_account import Account

from mpp import Challenge, Credential, Receipt, evm
from mpp.client import Mpp as ClientMppx
from mpp.evm import assets, tokens
from mpp.evm import client as evm_client
from mpp.evm import server as evm_server
from mpp.server import Mpp, Request
from mpp.x402 import (
    PAYMENT_REQUIRED_HEADER,
    PAYMENT_SIGNATURE_HEADER,
    PaymentPayload,
    decode_payment_required,
)

from ._helpers import PRIVATE_KEY, SECRET_KEY, TRANSACTION, Facilitator, to_httpx

CURRENCY = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
RECIPIENT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
account = Account.from_key(PRIVATE_KEY)


async def settle(_: evm_server.SettleParams) -> evm_server.SettleResult:
    return evm_server.SettleResult(reference=TRANSACTION)


async def test_resolves_token_currency_config() -> None:
    mppx = Mpp(
        methods=[
            evm_server.charge(
                authorization=evm.AuthorizationConfig(name="USD Coin", version="2"),
                chain_id=84532,
                currency=tokens.USDC,
                recipient=RECIPIENT,
                x402=evm_server.X402Options(facilitator=Facilitator()),
            )
        ],
        secret_key=SECRET_KEY,
    )
    first = await mppx.evm.charge(amount="0.25")(Request("GET", "https://example.com/paid"))
    assert first.status == 402
    challenge = Challenge.from_headers(first.challenge.headers)  # type: ignore[attr-defined]
    assert challenge.request == {
        "amount": "250000",
        "currency": CURRENCY,
        "methodDetails": {"chainId": 84532, "credentialTypes": ["authorization"], "decimals": 6},
        "recipient": RECIPIENT,
    }


@pytest.mark.parametrize(
    ("config", "error"),
    [
        (
            {
                "authorization": evm.AuthorizationConfig(name="USD Coin", version="2"),
                "currency": tokens.USDC,
            },
            "EVM authorization requires `chainId`.",
        ),
        (
            {
                "authorization": evm.AuthorizationConfig(name="USD Coin", version="2"),
                "chain_id": 999_999,
                "currency": tokens.USDC,
            },
            "EVM currency is not available on chain ID 999999.",
        ),
        (
            {"chain_id": 84532, "currency": tokens.USDC},
            "EVM authorization requires `authorization` metadata.",
        ),
        (
            {"chain_id": 8453, "currency": assets.BASE_SEPOLIA_USDC},
            "EVM currency is not available on chain ID 8453.",
        ),
        (
            {
                "currency": assets.define(
                    address=CURRENCY,
                    decimals=6,
                    network="eip155:84532",
                    transfer=assets.Permit2Transfer(),
                )
            },
            "EVM authorization requires `authorization` metadata.",
        ),
        (
            {
                "currency": CURRENCY,
                "authorization": evm.AuthorizationConfig(name="X", version="1"),
            },
            "EVM authorization requires `chainId`.",
        ),
        (
            {
                "currency": CURRENCY,
                "chain_id": 1,
                "authorization": evm.AuthorizationConfig(name="X", version="1"),
            },
            "EVM authorization requires `decimals`.",
        ),
    ],
)
def test_rejects_invalid_configuration(config: dict[str, object], error: str) -> None:
    with pytest.raises(ValueError, match=error.replace(".", r"\.")):
        evm_server.charge(recipient=RECIPIENT, settle=settle, **config)  # type: ignore[arg-type]


def test_requires_settle_or_facilitator() -> None:
    with pytest.raises(ValueError, match=r"requires `settle` or `x402\.facilitator`"):
        evm_server.charge(currency=assets.BASE_USDC, recipient=RECIPIENT)


async def test_infers_defaults_from_known_assets() -> None:
    mppx = Mpp(
        methods=[evm_server.charge(currency=assets.BASE_USDC, recipient=RECIPIENT, settle=settle)],
        secret_key=SECRET_KEY,
    )
    response = await mppx.evm.charge(amount="0.25")(Request("GET", "https://example.com/paid"))
    assert response.status == 402
    challenge = Challenge.from_headers(response.challenge.headers)  # type: ignore[attr-defined]
    assert challenge.request == {
        "amount": "250000",
        "currency": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "methodDetails": {"chainId": 8453, "credentialTypes": ["authorization"], "decimals": 6},
        "recipient": RECIPIENT,
    }


async def test_settles_native_authorization_credentials() -> None:
    facilitator = Facilitator()
    mppx = Mpp(
        methods=[
            evm_server.charge(
                currency=assets.BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                x402=evm_server.X402Options(facilitator=facilitator),
            )
        ],
        secret_key=SECRET_KEY,
    )
    client = ClientMppx(
        methods=[
            evm_client.evm(
                account=account, currencies=[assets.BASE_SEPOLIA_USDC], max_amount="0.25"
            )
        ],
    )
    route = mppx.evm.charge(amount="0.25")

    first = await route(Request("GET", "https://example.com/paid"))
    assert first.status == 402
    challenge_response = first.challenge  # type: ignore[attr-defined]
    challenge = Challenge.from_headers(challenge_response.headers)
    assert (challenge.method, challenge.intent) == ("evm", "charge")
    assert challenge.request == {
        "amount": "250000",
        "currency": CURRENCY,
        "methodDetails": {"chainId": 84532, "credentialTypes": ["authorization"], "decimals": 6},
        "recipient": RECIPIENT,
    }

    authorization = await client.create_credential(to_httpx(challenge_response))
    credential = Credential.deserialize(authorization)
    assert credential.payload["type"] == "authorization"
    assert credential.payload["nonce"] == evm.challenge_hash(id=challenge.id, realm=challenge.realm)
    assert credential.payload["to"] == RECIPIENT
    assert credential.payload["value"] == "250000"

    result = await route(
        Request("GET", "https://example.com/paid", headers={"Authorization": authorization})
    )
    assert result.status == 200
    from mpp.server import Response

    response = result.with_receipt(Response.json({"ok": True}))  # type: ignore[attr-defined]
    receipt = Receipt.from_headers(response.headers)
    assert (receipt.method, receipt.reference, receipt.status) == ("evm", TRANSACTION, "success")
    payload, requirements = facilitator.settlements[0]
    assert requirements.to_dict() == {
        "amount": "250000",
        "asset": CURRENCY,
        "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        "maxTimeoutSeconds": 300,
        "network": "eip155:84532",
        "payTo": RECIPIENT,
        "scheme": "exact",
    }
    assert payload.to_dict()["payload"] == {
        "authorization": {
            key: credential.payload[key]
            for key in ("from", "nonce", "to", "validAfter", "validBefore", "value")
        },
        "signature": credential.payload["signature"],
    }
    assert "resource" not in payload.to_dict()

    # A re-signed authorization with a different nonce is not bound to the challenge.
    forged_payload = {**credential.payload, "nonce": "0x" + "2" * 64}
    signed = account.sign_typed_data(
        full_message=evm.authorization_typed_data(
            authorization=evm.AuthorizationConfig(name="USDC", version="2"),
            chain_id=84532,
            currency=CURRENCY,
            from_=forged_payload["from"],
            to=forged_payload["to"],
            value=forged_payload["value"],
            valid_after=forged_payload["validAfter"],
            valid_before=forged_payload["validBefore"],
            nonce=forged_payload["nonce"],
        )
    )
    forged_payload["signature"] = "0x" + bytes(signed.signature).hex()
    forged = Credential(
        challenge=challenge, payload=forged_payload, source=credential.source
    ).serialize()
    forged_result = await route(
        Request(
            "GET",
            "https://example.com/paid",
            headers={"Authorization": forged, PAYMENT_SIGNATURE_HEADER: "ignored-for-native"},
        )
    )
    assert forged_result.status == 402

    # An x402 payment payload smuggled in Authorization is rejected.
    payment_required = decode_payment_required(challenge_response.headers[PAYMENT_REQUIRED_HEADER])
    x402_payload = PaymentPayload.model_validate(
        {
            "accepted": payment_required.accepts[0].to_dict(),
            "payload": {
                "authorization": {
                    "from": account.address,
                    "nonce": "0x" + "3" * 64,
                    "to": RECIPIENT,
                    "validAfter": "0",
                    "validBefore": "9999999999",
                    "value": payment_required.accepts[0].amount,
                },
                "signature": "0x" + "4" * 130,
            },
            "resource": payment_required.resource.to_dict(),
            "x402Version": 2,
        }
    ).to_dict()
    smuggled = Credential(challenge=challenge, payload=x402_payload).serialize()
    smuggled_result = await route(
        Request("GET", "https://example.com/paid", headers={"Authorization": smuggled})
    )
    assert smuggled_result.status == 402
    assert len(facilitator.settlements) == 1


async def test_x402_signature_header_is_paid_through_the_same_route() -> None:
    facilitator = Facilitator()
    mppx = Mpp(
        methods=[
            evm_server.charge(
                currency=assets.BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                x402=evm_server.X402Options(facilitator=facilitator),
            )
        ],
        secret_key=SECRET_KEY,
    )
    route = mppx.evm.charge(amount="0.25")
    first = await route(Request("GET", "https://example.com/paid"))
    x402_only = httpx.Response(
        402,
        headers={PAYMENT_REQUIRED_HEADER: first.challenge.headers[PAYMENT_REQUIRED_HEADER]},  # type: ignore[attr-defined]
        request=httpx.Request("GET", "https://example.com/paid"),
    )
    client = ClientMppx(
        methods=[evm_client.charge(account=account, currencies=[assets.BASE_SEPOLIA_USDC])]
    )
    prepared = await client.prepare_payment(x402_only)
    assert prepared.challenge.protocol == "x402"
    signature = await prepared.create_credential()
    paid = await route(
        Request("GET", "https://example.com/paid", headers={PAYMENT_SIGNATURE_HEADER: signature})
    )
    assert paid.status == 200
    from mpp.server import Response
    from mpp.x402 import PAYMENT_RESPONSE_HEADER, decode_payment_response

    response = paid.with_receipt(Response.json({"ok": True}))  # type: ignore[attr-defined]
    settled = decode_payment_response(response.headers[PAYMENT_RESPONSE_HEADER])
    assert settled.to_dict() == {
        "network": "eip155:84532",
        "payer": account.address,
        "success": True,
        "transaction": TRANSACTION,
    }
    assert "payment-receipt" in response.headers
    assert facilitator.reached == ["verify", "settle"]
