"""Zero-amount proof credentials and supportedModes in Tempo charge verification.

Mirrors mppx ``tempo/server/Charge.ts``: a zero-amount challenge is paid only with an
EIP-712 proof signed by the source account or by one of its active access keys (bare
or in a Keychain V1/V2 envelope), and ``methodDetails.supportedModes`` limits which
settlement modes a challenge accepts.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from eth_hash.auto import keccak

from mpp import Challenge, Credential
from mpp.errors import CredentialReplayedError, VerificationError
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo._proof import ACCOUNT_KEYCHAIN_ADDRESS
from mpp.methods.tempo.intents import ChargeIntent
from mpp.methods.tempo.session._proof import proof_digest, proof_source, sign_proof
from mpp.store import MemoryStore
from tests import TEST_REALM, make_credential

CHAIN_ID = 4217
CHALLENGE_ID = "zero-amount-challenge"
SOURCE = TempoAccount.from_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
ACCESS_KEY = TempoAccount.from_key(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
OTHER = TempoAccount.from_key("0x" + "11" * 32)


def _expires() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")


def _request(amount: str = "0", modes: list[str] | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {"chainId": CHAIN_ID}
    if modes is not None:
        details["supportedModes"] = modes
    return {
        "amount": amount,
        "currency": "0x20c0000000000000000000000000000000000000",
        "recipient": "0x742d35cc6634c0532925a3b844bc9e7595f8fe00",
        "methodDetails": details,
    }


def _credential(payload: dict[str, Any], source: str | None = None) -> Credential:
    return make_credential(
        payload=payload,
        challenge_id=CHALLENGE_ID,
        expires=_expires(),
        source=source if source is not None else proof_source(SOURCE.address, CHAIN_ID),
    )


def _digest() -> bytes:
    digest = proof_digest(
        account=SOURCE.address, chain_id=CHAIN_ID, challenge_id=CHALLENGE_ID, realm=TEST_REALM
    )
    return bytes.fromhex(digest.removeprefix("0x"))


def _keychain(version: int, signer: TempoAccount = ACCESS_KEY, user: str | None = None) -> str:
    user_bytes = bytes.fromhex((user or SOURCE.address).removeprefix("0x"))
    payload = keccak(bytes([version]) + _digest() + user_bytes) if version == 4 else _digest()
    return "0x" + (bytes([version]) + user_bytes + signer.sign_hash(payload)).hex()


class FakeKeychainRpc:
    """Serves eth_chainId and AccountKeychain.getKey from ``keys`` (unknown keys read as zeros)."""

    def __init__(self, keys: dict[str, tuple[int, bool]] | None = None) -> None:
        self.keys = {key.lower(): value for key, value in (keys or {}).items()}
        self.calls: list[str] = []

    async def post(self, url: str, json: dict[str, Any]) -> httpx.Response:
        method = json["method"]
        self.calls.append(method)
        if method == "eth_chainId":
            result: Any = hex(CHAIN_ID)
        elif method == "eth_call":
            call = json["params"][0]
            assert call["to"] == ACCOUNT_KEYCHAIN_ADDRESS
            data = call["data"].removeprefix("0x")
            assert data.startswith("bc298553")
            assert data[8 + 24 : 8 + 64] == SOURCE.address.lower().removeprefix("0x")
            key_id = "0x" + data[8 + 64 + 24 :]
            expiry, revoked = self.keys.get(key_id, (0, False))
            words = [0, int(key_id, 16) if key_id in self.keys else 0, expiry, 0, int(revoked)]
            result = "0x" + "".join(f"{word:064x}" for word in words)
        else:
            raise AssertionError(f"unexpected RPC method {method}")
        body = {"jsonrpc": "2.0", "id": json["id"], "result": result}
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))


def _intent(rpc: FakeKeychainRpc | None = None, store: MemoryStore | None = None) -> ChargeIntent:
    client: Any = rpc or FakeKeychainRpc()
    return ChargeIntent(rpc_url="https://rpc.test", http_client=client, store=store)


ACTIVE = {ACCESS_KEY.address: (int(time.time()) + 3600, False)}


def _eoa_proof() -> dict[str, Any]:
    signature = sign_proof(SOURCE, chain_id=CHAIN_ID, challenge_id=CHALLENGE_ID, realm=TEST_REALM)
    return {"type": "proof", "signature": signature}


async def test_eoa_proof_accepted_without_rpc() -> None:
    rpc = FakeKeychainRpc()
    receipt = await _intent(rpc).verify(_credential(_eoa_proof()), _request())
    assert (receipt.status, receipt.reference) == ("success", CHALLENGE_ID)
    assert receipt.payer == SOURCE.address.lower()
    assert rpc.calls == []


async def test_validate_reports_proof_mode() -> None:
    validation = await _intent().validate(_credential(_eoa_proof()), _request())
    assert validation.details == {"mode": "proof", "sender": SOURCE.address.lower()}
    assert validation.payer == SOURCE.address.lower()


@pytest.mark.parametrize(
    "signature",
    [
        pytest.param(lambda: _keychain(3), id="keychain-v1"),
        pytest.param(lambda: _keychain(4), id="keychain-v2"),
        pytest.param(lambda: "0x" + ACCESS_KEY.sign_hash(_digest()).hex(), id="bare-access-key"),
    ],
)
async def test_active_access_key_proof_accepted(signature: Any) -> None:
    credential = _credential({"type": "proof", "signature": signature()})
    receipt = await _intent(FakeKeychainRpc(ACTIVE)).verify(credential, _request())
    assert receipt.reference == CHALLENGE_ID


@pytest.mark.parametrize(
    ("keys", "signature"),
    [
        pytest.param({}, lambda: _keychain(4), id="unknown-key"),
        pytest.param(
            {ACCESS_KEY.address: (int(time.time()) + 3600, True)},
            lambda: _keychain(4),
            id="revoked-key",
        ),
        pytest.param(
            {ACCESS_KEY.address: (int(time.time()) - 1, False)}, lambda: _keychain(4), id="expired"
        ),
        pytest.param(ACTIVE, lambda: _keychain(4, user=OTHER.address), id="other-account"),
        pytest.param(ACTIVE, lambda: _keychain(4)[:-2] + "00", id="tampered"),
    ],
)
async def test_unauthorized_access_key_proof_rejected(keys: Any, signature: Any) -> None:
    credential = _credential({"type": "proof", "signature": signature()})
    with pytest.raises(VerificationError, match="does not match source"):
        await _intent(FakeKeychainRpc(keys)).verify(credential, _request())


async def test_proof_signed_by_other_account_rejected() -> None:
    signature = sign_proof(OTHER, chain_id=CHAIN_ID, challenge_id=CHALLENGE_ID, realm=TEST_REALM)
    with pytest.raises(VerificationError, match="does not match source"):
        await _intent().verify(_credential({"type": "proof", "signature": signature}), _request())


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (proof_source(SOURCE.address, 1), "source is invalid"),
        ("not-a-did", "source is invalid"),
    ],
)
async def test_proof_source_rejected(source: str, message: str) -> None:
    with pytest.raises(VerificationError, match=message):
        await _intent().verify(_credential(_eoa_proof(), source=source), _request())


async def test_proof_on_nonzero_amount_rejected() -> None:
    with pytest.raises(VerificationError, match="only valid for zero-amount"):
        await _intent().verify(_credential(_eoa_proof()), _request(amount="1"))


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "hash", "hash": "0x" + "11" * 32},
        {"type": "transaction", "signature": "0x76"},
    ],
)
async def test_zero_amount_requires_proof(payload: dict[str, Any]) -> None:
    rpc = FakeKeychainRpc()
    with pytest.raises(VerificationError, match="require a proof credential"):
        await _intent(rpc).verify(_credential(payload), _request(amount="000"))
    assert rpc.calls == []


async def test_proof_single_use_with_configured_store() -> None:
    intent = _intent(store=MemoryStore())
    credential = _credential(_eoa_proof())
    await intent.verify(credential, _request())
    with pytest.raises(CredentialReplayedError):
        await intent.verify(credential, _request())


async def test_proof_reusable_without_configured_store() -> None:
    intent = _intent()
    credential = _credential(_eoa_proof())
    await intent.verify(credential, _request())
    await intent.verify(credential, _request())


async def test_pull_only_rejects_hash() -> None:
    credential = _credential({"type": "hash", "hash": "0x" + "11" * 32})
    with pytest.raises(VerificationError, match="Hash credentials are not supported"):
        await _intent().verify(credential, _request(amount="1000", modes=["pull"]))


async def test_push_only_rejects_transaction() -> None:
    credential = _credential({"type": "transaction", "signature": "0x76"})
    with pytest.raises(VerificationError, match="Transaction credentials are not supported"):
        await _intent().verify(credential, _request(amount="1000", modes=["push"]))


async def test_zero_amount_with_splits_rejected() -> None:
    request = _request()
    request["methodDetails"]["splits"] = [
        {"amount": "1", "recipient": "0x9999999999999999999999999999999999999999"}
    ]
    with pytest.raises(VerificationError, match="cannot have splits"):
        await _intent().verify(_credential(_eoa_proof()), request)


async def test_validate_rejects_consumed_proof() -> None:
    intent = _intent(store=MemoryStore())
    credential = _credential(_eoa_proof())
    await intent.verify(credential, _request())
    with pytest.raises(CredentialReplayedError):
        await intent.validate(credential, _request())


def _challenge(amount: str = "0", modes: list[str] | None = None) -> Challenge:
    return Challenge(
        id=CHALLENGE_ID,
        method="tempo",
        intent="charge",
        request=_request(amount, modes),
        realm=TEST_REALM,
        expires=_expires(),
    )


@pytest.mark.parametrize("root", [None, SOURCE.address], ids=["eoa", "access-key"])
async def test_client_pays_zero_amount_with_proof(root: str | None) -> None:
    signer = SOURCE if root is None else ACCESS_KEY
    method = tempo_client.TempoMethod(account=signer, root_account=root, chain_id=CHAIN_ID)
    challenge = _challenge()
    credential = await method.create_credential(challenge)
    assert credential.payload["type"] == "proof"
    assert credential.source == proof_source(SOURCE.address, CHAIN_ID)
    server_credential = Credential(
        challenge=credential.challenge,
        payload=credential.payload,
        source=credential.source,
    )
    receipt = await _intent(FakeKeychainRpc(ACTIVE)).verify(server_credential, challenge.request)
    assert receipt.payer == SOURCE.address.lower()


def test_client_skips_push_only_offers() -> None:
    method = tempo_client.TempoMethod(account=SOURCE, chain_id=CHAIN_ID)
    assert method.can_handle_challenge(_challenge("1000", ["pull", "push"]))
    assert not method.can_handle_challenge(_challenge("1000", ["push"]))
