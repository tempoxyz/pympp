from typing import Any

import pytest

from mpp import Challenge, Credential, evm
from mpp.evm import assets, chains, tokens
from mpp.evm import client as evm_client
from mpp.method import CredentialParams

from .conftest import RecordingSigner

USDC = assets.BASE_SEPOLIA_USDC.address
RECIPIENT = "0x2222222222222222222222222222222222222222"


def native(
    amount: str = "1000000", chain_id: int = 84532, decimals: int = 18, **extra: Any
) -> Challenge:
    return Challenge(
        id="native",
        intent="charge",
        method="evm",
        realm="api.example.com",
        request={
            "amount": amount,
            "currency": USDC,
            "methodDetails": {
                "chainId": chain_id,
                "credentialTypes": ["authorization"],
                "decimals": decimals,
                **extra,
            },
            "recipient": RECIPIENT,
        },
    )


async def create(method: Any, challenge: Challenge, context: Any = None) -> str:
    parsed = method.context.model_validate(context) if context is not None else None
    return await method.create_credential(CredentialParams(challenge=challenge, context=parsed))


async def test_does_not_sign_x402_payloads_from_unbranded_challenges(
    signer: RecordingSigner,
) -> None:
    method = evm_client.charge(
        account=signer,
        currencies=[assets.BASE_SEPOLIA_USDC],
        max_amount="0.01",
        networks=[chains.BASE_SEPOLIA],
    )
    challenge = Challenge(
        id="attacker-controlled",
        intent="charge",
        method="evm",
        realm="api.example.com",
        request={
            "amount": "10000",
            "asset": USDC,
            "maxTimeoutSeconds": 60,
            "network": "eip155:84532",
            "payTo": RECIPIENT,
            "scheme": "exact",
        },
    )
    with pytest.raises(KeyError):
        await create(method, challenge)
    assert signer.calls == []


async def test_does_not_use_server_supplied_decimals_for_max_amount(
    signer: RecordingSigner,
) -> None:
    method = evm_client.charge(account=signer, max_amount="1")
    with pytest.raises(ValueError, match=r"EVM charge maxAmount requires currency decimals\."):
        await create(method, native(amount="1000000000000000000"))


async def test_requires_network_policy_for_raw_currencies(signer: RecordingSigner) -> None:
    method = evm_client.charge(account=signer, currencies=[USDC], max_amount="1")
    with pytest.raises(ValueError, match=r"EVM raw currency allowlists require networks\."):
        await create(method, native(decimals=6))


async def test_accepts_token_sets_for_policy_and_decimals(signer: RecordingSigner) -> None:
    method = evm_client.charge(
        account=signer,
        authorization=evm.AuthorizationConfig(name="USD Coin", version="2"),
        currencies=tokens.POPULAR,
        max_amount="1",
    )
    await create(method, native())
    [typed_data] = signer.calls
    assert typed_data["domain"]["name"] == "USD Coin"
    assert typed_data["domain"]["version"] == "2"
    assert typed_data["domain"]["verifyingContract"] == USDC
    with pytest.raises(ValueError, match=r"EVM charge amount exceeds maxAmount\."):
        await create(method, native(amount="1000001"))
    assert len(signer.calls) == 1


async def test_requires_authorization_metadata_for_token_currencies(
    signer: RecordingSigner,
) -> None:
    method = evm_client.charge(account=signer, currencies=tokens.POPULAR, max_amount="1")
    with pytest.raises(ValueError, match=r"EVM authorization requires token name and version\."):
        await create(method, native())
    assert signer.calls == []


async def test_uses_known_asset_metadata_for_policy_and_domain(signer: RecordingSigner) -> None:
    method = evm_client.charge(
        account=signer, currencies=[assets.BASE_SEPOLIA_USDC], max_amount="0.01"
    )
    await create(method, native(amount="10000"))
    [typed_data] = signer.calls
    assert typed_data["domain"]["name"] == "USDC"
    assert typed_data["domain"]["version"] == "2"
    with pytest.raises(ValueError, match=r"EVM charge amount exceeds maxAmount\."):
        await create(method, native(amount="10001"))
    assert len(signer.calls) == 1


async def test_pins_known_asset_policy_to_its_network(signer: RecordingSigner) -> None:
    method = evm_client.charge(
        account=signer, currencies=[assets.BASE_SEPOLIA_USDC], max_amount="0.01"
    )
    with pytest.raises(
        ValueError,
        match=r"EVM currency is not allowed: 0x036CbD53842c5426634e7929541eC2318f3dCF7e\.",
    ):
        await create(method, native(amount="10000", chain_id=8453, decimals=6))
    assert signer.calls == []


async def test_signs_challenge_bound_authorizations(signer: RecordingSigner) -> None:
    method = evm_client.charge(account=signer, currencies=[assets.BASE_SEPOLIA_USDC])
    challenge = native(amount="10000")
    challenge = Challenge(**{**challenge.to_dict(), "expires": "2030-01-01T00:00:00.000Z"})
    credential = Credential.deserialize(await create(method, challenge))
    assert credential.source == f"did:pkh:eip155:84532:{signer.address}"
    assert credential.payload == {
        "from": signer.address,
        "nonce": evm.challenge_hash(id="native", realm="api.example.com"),
        "signature": "0x1234",
        "to": RECIPIENT,
        "type": "authorization",
        "validAfter": "0",
        "validBefore": "1893456000",
        "value": "10000",
    }
    [typed_data] = signer.calls
    assert typed_data["message"]["validBefore"] == 1893456000
    assert typed_data["message"]["value"] == 10000


async def test_rejects_unaccepted_or_split_challenges(signer: RecordingSigner) -> None:
    method = evm_client.charge(
        account=signer, authorization=evm.AuthorizationConfig(name="X", version="1")
    )
    unaccepted = native()
    unaccepted.request["methodDetails"]["credentialTypes"] = ["permit2"]
    with pytest.raises(ValueError, match=r"EVM authorization is not accepted by this challenge\."):
        await create(method, unaccepted)
    split = native(splits=[{"amount": "1", "recipient": RECIPIENT}])
    with pytest.raises(ValueError, match=r"EVM authorization does not support payment splits\."):
        await create(method, split)


async def test_reports_missing_signer_only_when_creating(signer: RecordingSigner) -> None:
    method = evm_client.charge(currencies=[assets.BASE_SEPOLIA_USDC])
    with pytest.raises(ValueError, match=r"requires a typed-data signer\."):
        await create(method, native(amount="1"))
    credential = Credential.deserialize(
        await create(method, native(amount="1"), {"account": signer})
    )
    assert credential.payload["from"] == signer.address


def test_evm_group_returns_charge() -> None:
    [method] = evm_client.evm(max_amount="1")
    assert method.key == "evm/charge"


async def test_signs_with_eth_account() -> None:
    from eth_account import Account
    from eth_account.messages import encode_typed_data

    account = Account.from_key("0x" + "11" * 32)
    method = evm_client.charge(account=account, currencies=[assets.BASE_SEPOLIA_USDC])
    credential = Credential.deserialize(await create(method, native(amount="1")))
    payload = credential.payload
    typed_data = evm.authorization_typed_data(
        authorization=evm.AuthorizationConfig(name="USDC", version="2"),
        chain_id=84532,
        currency=USDC,
        from_=payload["from"],
        to=payload["to"],
        value=payload["value"],
        valid_after=payload["validAfter"],
        valid_before=payload["validBefore"],
        nonce=payload["nonce"],
    )
    recovered = Account.recover_message(
        encode_typed_data(full_message=typed_data), signature=payload["signature"]
    )
    assert recovered == account.address


async def test_refuses_zero_amount_charges(signer: RecordingSigner) -> None:
    method = evm_client.charge(account=signer, currencies=[assets.BASE_SEPOLIA_USDC])
    with pytest.raises(ValueError, match=r"EVM client does not sign zero-amount charges\."):
        await create(method, native(amount="0"))
    assert signer.calls == []
