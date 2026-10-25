import pytest
from pydantic import ValidationError

from mpp import evm


def test_challenge_hash_frames_id_and_realm() -> None:
    assert evm.challenge_hash(id="ab", realm="c") != evm.challenge_hash(id="a", realm="bc")


def test_challenge_hash_vector() -> None:
    assert (
        evm.challenge_hash(id="challenge", realm="example.com")
        == "0xaf46a6d4bdf4f9796c81e5d99101e1393b95168c0273f9387b3e45526b09614c"
    )


def test_network_and_source() -> None:
    assert evm.network_of(84532) == "eip155:84532"
    assert evm.to_source(address="0xabc", chain_id=8453) == "did:pkh:eip155:8453:0xabc"


def test_request_transform_matches_mppx() -> None:
    wire = evm.charge.normalize_request(
        {
            "amount": "0.25",
            "chainId": 84532,
            "currency": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
            "decimals": 6,
            "recipient": "0x209693bc6afc0c5328ba36faf03c514ef312287c",
            "externalId": "order-1",
            "permit2Address": "0x000000000022d473030f116ddee9f6b43ac78ba3",
            "splits": [{"amount": "1", "recipient": "0x1111111111111111111111111111111111111111"}],
        }
    )
    assert wire == {
        "externalId": "order-1",
        "amount": "250000",
        "currency": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "methodDetails": {
            "chainId": 84532,
            "credentialTypes": ["authorization"],
            "decimals": 6,
            "permit2Address": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            "splits": [{"amount": "1", "recipient": "0x1111111111111111111111111111111111111111"}],
        },
        "recipient": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"amount": "1e3"},
        {"currency": "0x1234"},
        {"credentialTypes": []},
        {"credentialTypes": ["permit2"]},
        {"chainId": "84532"},
    ],
)
def test_request_validation(overrides: dict[str, object]) -> None:
    base = {
        "amount": "1",
        "chainId": 1,
        "currency": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "decimals": 6,
        "recipient": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    }
    with pytest.raises(ValidationError):
        evm.charge.normalize_request({**base, **overrides})


def test_payload_schema() -> None:
    payload = {
        "from": "0x1111111111111111111111111111111111111111",
        "nonce": "0x" + "ab" * 32,
        "signature": "0x1234",
        "to": "0x2222222222222222222222222222222222222222",
        "type": "authorization",
        "validAfter": "0",
        "validBefore": "10",
        "value": "1",
    }
    assert evm.charge.parse_payload(payload).to_dict() == payload
    with pytest.raises(ValidationError):
        evm.charge.parse_payload({**payload, "type": "permit2"})
    with pytest.raises(ValidationError):
        evm.charge.parse_payload({**payload, "nonce": "0x12"})
