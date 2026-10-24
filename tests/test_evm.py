"""Unit tests for the EVM payment method and its charge intent."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from eth_account import Account

from mpp import Challenge, ChallengeEcho, Credential
from mpp._canonical import canonical_b64url
from mpp.errors import (
    CredentialReplayedError,
    InternalPaymentError,
    InvalidPayloadError,
    VerificationFailedError,
)
from mpp.methods.evm import (
    BASE_SEPOLIA_USDC,
    BASE_USDC,
    CELO_USDT,
    Authorization,
    ChargeIntent,
    EvmAsset,
    challenge_hash,
    evm,
)
from mpp.methods.evm._eip3009 import authorization_domain, sign_authorization, to_source
from mpp.server import Mpp
from mpp.store import MemoryStore
from mpp.x402 import FacilitatorError, PaymentPayload, PaymentRequirements

PAYER = Account.from_key("0x" + "11" * 32)
OTHER = Account.from_key("0x" + "22" * 32)
RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
REALM = "api.example.com"


class FakeFacilitator:
    """Records calls and answers with configurable responses."""

    def __init__(
        self,
        *,
        verify: dict[str, Any] | Exception | None = None,
        settle: dict[str, Any] | Exception | None = None,
    ) -> None:
        self.verify_response = verify or {"isValid": True}
        self.settle_response = settle or {
            "success": True,
            "transaction": "0x" + "ab" * 32,
            "network": "eip155:84532",
        }
        self.verified: list[tuple[PaymentPayload, PaymentRequirements]] = []
        self.settled: list[tuple[PaymentPayload, PaymentRequirements]] = []

    async def verify(self, payment_payload: Any, payment_requirements: Any) -> Any:
        self.verified.append((payment_payload, payment_requirements))
        if isinstance(self.verify_response, Exception):
            raise self.verify_response
        return self.verify_response

    async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any:
        self.settled.append((payment_payload, payment_requirements))
        if isinstance(self.settle_response, Exception):
            raise self.settle_response
        return self.settle_response


def server_method(facilitator: Any = None, **kwargs: Any):
    return evm(
        currency=BASE_SEPOLIA_USDC,
        recipient=RECIPIENT,
        facilitator=facilitator or FakeFacilitator(),
        **kwargs,
    )


def request(method: Any = None, amount: str = "10000") -> dict[str, Any]:
    method = method or server_method()
    return method.transform_request(
        {"amount": amount, "currency": method.currency, "recipient": RECIPIENT}, None
    )


def native_credential(
    req: dict[str, Any],
    *,
    challenge_id: str = "challenge-1",
    signer: Any = PAYER,
    source: str | None = "default",
    **overrides: Any,
) -> Credential:
    """Sign a native evm/charge credential, optionally altering the payload."""
    now = int(time.time())
    payload = {
        "type": "authorization",
        "from": PAYER.address,
        "to": req["recipient"],
        "value": req["amount"],
        "validAfter": "0",
        "validBefore": str(now + 300),
        "nonce": challenge_hash(challenge_id, REALM),
    }
    payload.update({k: v for k, v in overrides.items() if k != "signature"})
    domain = authorization_domain(
        name="USDC", version="2", chain_id=req["methodDetails"]["chainId"], currency=req["currency"]
    )
    payload["signature"] = overrides.get("signature") or sign_authorization(
        signer, domain=domain, payload=payload
    )
    echo = ChallengeEcho(
        id=challenge_id,
        realm=REALM,
        method="evm",
        intent="charge",
        request=canonical_b64url(req),
    )
    if source == "default":
        source = to_source(address=PAYER.address, chain_id=84532)
    return Credential(challenge=echo, payload=payload, source=source)


def x402_echo(credential: Credential) -> Credential:
    echo = ChallengeEcho(
        id="x402:" + "00" * 32,
        realm=REALM,
        method="evm",
        intent="charge",
        request=credential.challenge.request,
    )
    return Credential(challenge=echo, payload=credential.payload, source=credential.source)


class TestConfiguration:
    def test_known_asset(self) -> None:
        method = server_method()
        assert method.name == "evm"
        assert method.currency == BASE_SEPOLIA_USDC.address
        assert (method.chain_id, method.decimals) == (84532, 6)
        assert (method.domain_name, method.domain_version) == ("USDC", "2")
        assert isinstance(method.intents["charge"], ChargeIntent)

    def test_known_assets_carry_their_domains(self) -> None:
        assert (BASE_USDC.name, BASE_USDC.network) == ("USD Coin", "eip155:8453")
        assert (CELO_USDT.name, CELO_USDT.version) == ("Tether USD", "1")

    def test_raw_address_needs_chain_decimals_and_domain(self) -> None:
        address = "0x" + "aa" * 20
        for missing in ("chain_id", "decimals", "authorization"):
            options: dict[str, Any] = {
                "chain_id": 31337,
                "decimals": 6,
                "authorization": {"name": "USDC", "version": "2"},
            }
            del options[missing]
            with pytest.raises(ValueError, match=missing.replace("_", "_")):
                evm(currency=address, recipient=RECIPIENT, settle=lambda a: "0x1", **options)
        method = evm(
            currency=address,
            recipient=RECIPIENT,
            settle=lambda a: "0x1",
            chain_id=31337,
            decimals=18,
            authorization={"name": "Token", "version": "1"},
        )
        assert (method.chain_id, method.decimals, method.domain_name) == (31337, 18, "Token")

    def test_rejects_a_chain_id_the_asset_is_not_on(self) -> None:
        with pytest.raises(ValueError, match="chain ID 84532"):
            server_method(chain_id=8453)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"currency": "USDC", "recipient": RECIPIENT, "settle": lambda a: "0x1"},
            {"currency": BASE_USDC, "recipient": "alice", "settle": lambda a: "0x1"},
            {"currency": BASE_USDC, "facilitator": "https://f.example"},
            {"currency": BASE_USDC},
            {
                "currency": BASE_USDC,
                "recipient": RECIPIENT,
                "settle": lambda a: "0x1",
                "authorization": {"name": "", "version": "2"},
            },
        ],
    )
    def test_rejects_invalid_configuration(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            evm(**kwargs)

    def test_server_needs_a_settlement_path(self) -> None:
        with pytest.raises(ValueError, match="facilitator or a settle hook"):
            ChargeIntent(name="USDC", version="2")
        with pytest.raises(ValueError, match="max_timeout_seconds"):
            ChargeIntent(name="USDC", version="2", settle=lambda a: "0x1", max_timeout_seconds=0)

    def test_invalid_assets(self) -> None:
        with pytest.raises(ValueError):
            EvmAsset(address="0x12", decimals=6, chain_id=1, name="A", version="1")
        with pytest.raises(ValueError):
            EvmAsset(address="0x" + "aa" * 20, decimals=99, chain_id=1, name="A", version="1")
        with pytest.raises(ValueError):
            EvmAsset(address="0x" + "aa" * 20, decimals=6, chain_id=0, name="A", version="1")
        with pytest.raises(ValueError):
            EvmAsset(address="0x" + "aa" * 20, decimals=6, chain_id=1, name="", version="1")

    def test_mpp_wires_its_store(self) -> None:
        store = MemoryStore()
        method = server_method()
        Mpp.create(method=method, realm=REALM, secret_key="k", store=store)
        assert method.intents["charge"]._store is store  # type: ignore[attr-defined]


class TestRequestShape:
    def test_matches_mppx_evm_charge_requests(self) -> None:
        method = server_method()
        assert method.transform_request(
            {
                "amount": "10000",
                "currency": method.currency.lower(),
                "recipient": RECIPIENT.lower(),
                "methodDetails": {"chainId": 84532},
            },
            None,
        ) == {
            "amount": "10000",
            "currency": BASE_SEPOLIA_USDC.address,
            "recipient": RECIPIENT,
            "methodDetails": {
                "chainId": 84532,
                "credentialTypes": ["authorization"],
                "decimals": 6,
            },
        }

    def test_is_idempotent(self) -> None:
        method = server_method()
        once = request(method)
        assert method.transform_request(once, None) == once

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"currency": "0x" + "bb" * 20}, "currency"),
            ({"recipient": "bob"}, "recipient"),
            ({"methodDetails": {"chainId": 1}}, "chain_id"),
            ({"methodDetails": {"splits": [{"amount": "1", "recipient": RECIPIENT}]}}, "splits"),
            ({"methodDetails": {"feePayer": True}}, "fee_payer"),
            ({"methodDetails": "x"}, "methodDetails"),
        ],
    )
    def test_rejects_requests_evm_cannot_pay(self, change: dict[str, Any], message: str) -> None:
        method = server_method()
        base = {"amount": "1", "currency": method.currency, "recipient": RECIPIENT, **change}
        with pytest.raises(ValueError, match=message):
            method.transform_request(base, None)

    async def test_mpp_rejects_splits_and_fee_payer(self) -> None:
        server = Mpp.create(method=server_method(), realm=REALM, secret_key="k")
        with pytest.raises(ValueError, match="fee_payer"):
            await server.charge(None, "0.01", fee_payer=True)

    def test_x402_requirements(self) -> None:
        intent = server_method(max_timeout_seconds=60).intents["charge"]
        assert isinstance(intent, ChargeIntent)
        assert intent.x402_requirements(request()) == {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "10000",
            "asset": BASE_SEPOLIA_USDC.address,
            "payTo": RECIPIENT,
            "maxTimeoutSeconds": 60,
            "extra": {"assetTransferMethod": "eip3009", "name": "USDC", "version": "2"},
        }


class TestChallengeHash:
    def test_matches_keccak_of_the_json_pair(self) -> None:
        # cast keccak '["abc","api.example.com"]'
        assert (
            challenge_hash("abc", "api.example.com")
            == "0x5fc7620ab10ee4cbef955fe0902682f5688d24749a3a0322452c6728cd3d1425"
        )
        # Non-ASCII stays unescaped, like JSON.stringify: cast keccak '["é","r"]'
        assert (
            challenge_hash("é", "r")
            == "0x69f34659b96a92d90dce7863fee2fe01dc6372af8b8a42e2b9ff14f73522e1c7"
        )


class TestValidate:
    async def test_accepts_a_valid_authorization(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        req = request(method)
        validation = await method.intents["charge"].validate(native_credential(req), req)  # type: ignore[union-attr]
        assert validation.payer == PAYER.address
        assert validation.intent == "charge"
        [(payment, requirements)] = facilitator.verified
        assert payment["accepted"] == requirements
        assert payment["payload"]["authorization"]["from"] == PAYER.address

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"value": "9999"}, "amount mismatch"),
            ({"to": OTHER.address}, "recipient mismatch"),
            ({"nonce": "0x" + "00" * 32}, "challenge hash mismatch"),
            ({"validAfter": str(int(time.time()) + 600)}, "not valid yet"),
            ({"validBefore": str(int(time.time()) - 1)}, "has expired"),
            ({"from": OTHER.address}, "signature mismatch"),
            ({"signature": "0x" + "00" * 65}, "signature is invalid"),
        ],
    )
    async def test_rejects(self, overrides: dict[str, Any], message: str) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        req = request(method)
        with pytest.raises(VerificationFailedError, match=message):
            await method.intents["charge"].validate(  # type: ignore[union-attr]
                native_credential(req, **overrides), req
            )
        assert facilitator.verified == []

    async def test_rejects_signatures_by_another_key(self) -> None:
        method = server_method()
        req = request(method)
        with pytest.raises(VerificationFailedError, match="signature mismatch"):
            await method.intents["charge"].validate(  # type: ignore[union-attr]
                native_credential(req, signer=OTHER), req
            )

    async def test_x402_credentials_are_not_bound_to_a_challenge_hash(self) -> None:
        method = server_method()
        req = request(method)
        credential = x402_echo(native_credential(req, nonce="0x" + "42" * 32))
        validation = await method.intents["charge"].validate(credential, req)  # type: ignore[union-attr]
        assert validation.payer == PAYER.address

    @pytest.mark.parametrize(
        "source",
        [
            to_source(address=OTHER.address, chain_id=84532),
            to_source(address=PAYER.address, chain_id=8453),
            "did:key:z6Mk",
        ],
    )
    async def test_rejects_a_mismatched_source(self, source: str) -> None:
        method = server_method()
        req = request(method)
        with pytest.raises(VerificationFailedError, match="source mismatch"):
            await method.intents["charge"].validate(  # type: ignore[union-attr]
                native_credential(req, source=source), req
            )

    async def test_source_is_optional(self) -> None:
        method = server_method()
        req = request(method)
        await method.intents["charge"].validate(native_credential(req, source=None), req)  # type: ignore[union-attr]

    @pytest.mark.parametrize(
        "payload",
        [
            "nope",
            {"type": "transaction"},
            {"type": "authorization", "from": "0x12"},
        ],
    )
    async def test_rejects_malformed_payloads(self, payload: Any) -> None:
        method = server_method()
        req = request(method)
        credential = native_credential(req)
        bad = Credential(challenge=credential.challenge, payload=payload)
        with pytest.raises(InvalidPayloadError):
            await method.intents["charge"].validate(bad, req)  # type: ignore[union-attr]

    async def test_rejects_out_of_range_values(self) -> None:
        method = server_method()
        req = request(method)
        credential = native_credential(req, validBefore=str(2**256), signature="0x" + "00" * 65)
        with pytest.raises(InvalidPayloadError, match="out of range"):
            await method.intents["charge"].validate(credential, req)  # type: ignore[union-attr]

    async def test_rejects_requests_without_authorization_credentials(self) -> None:
        method = server_method()
        req = request(method)
        credential = native_credential(req)
        stripped = {**req, "methodDetails": {"chainId": 84532}}
        with pytest.raises(VerificationFailedError, match="not supported"):
            await method.intents["charge"].validate(credential, stripped)  # type: ignore[union-attr]
        with pytest.raises(VerificationFailedError, match="splits"):
            await method.intents["charge"].validate(  # type: ignore[union-attr]
                credential,
                {**req, "methodDetails": {**req["methodDetails"], "splits": [{"amount": "1"}]}},
            )
        with pytest.raises(VerificationFailedError, match="chainId"):
            await method.intents["charge"].validate(credential, {**req, "methodDetails": {}})  # type: ignore[union-attr]

    async def test_facilitator_rejection(self) -> None:
        facilitator = FakeFacilitator(
            verify={"isValid": False, "invalidReason": "insufficient_funds"}
        )
        method = server_method(facilitator)
        req = request(method)
        with pytest.raises(VerificationFailedError, match="insufficient_funds"):
            await method.intents["charge"].validate(native_credential(req), req)  # type: ignore[union-attr]

    async def test_facilitator_message_wins_over_reason(self) -> None:
        facilitator = FakeFacilitator(
            verify={"isValid": False, "invalidReason": "r", "invalidMessage": "human message"}
        )
        method = server_method(facilitator)
        req = request(method)
        with pytest.raises(VerificationFailedError, match="human message"):
            await method.intents["charge"].validate(native_credential(req), req)  # type: ignore[union-attr]

    async def test_facilitator_outage_is_an_internal_error(self) -> None:
        method = server_method(FakeFacilitator(verify=FacilitatorError("down")))
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await method.intents["charge"].validate(native_credential(req), req)  # type: ignore[union-attr]

    async def test_custom_settle_skips_the_facilitator(self) -> None:
        facilitator = FakeFacilitator()
        method = evm(
            currency=BASE_SEPOLIA_USDC,
            recipient=RECIPIENT,
            facilitator=facilitator,
            settle=lambda authorization: "0x1",
        )
        req = request(method)
        await method.intents["charge"].validate(native_credential(req), req)  # type: ignore[union-attr]
        assert facilitator.verified == []


class TestBroadcast:
    async def test_settles_through_the_facilitator(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        req = request(method)
        receipt = await method.intents["charge"].broadcast(native_credential(req), req)  # type: ignore[union-attr]
        assert receipt.reference == "0x" + "ab" * 32
        assert receipt.method == "evm"
        assert receipt.payer == PAYER.address
        [(payment, requirements)] = facilitator.settled
        assert payment["x402Version"] == 2
        assert requirements["amount"] == "10000"

    @pytest.mark.parametrize("is_async", [False, True])
    async def test_settles_through_a_hook(self, is_async: bool) -> None:
        seen: list[Authorization] = []

        def settle(authorization: Authorization) -> str:
            seen.append(authorization)
            return "0xhook"

        async def settle_async(authorization: Authorization) -> str:
            return settle(authorization)

        method = evm(
            currency=BASE_SEPOLIA_USDC,
            recipient=RECIPIENT,
            settle=settle_async if is_async else settle,
        )
        req = request(method)
        receipt = await method.intents["charge"].broadcast(native_credential(req), req)  # type: ignore[union-attr]
        assert receipt.reference == "0xhook"
        [authorization] = seen
        assert authorization.source == to_source(address=PAYER.address, chain_id=84532)
        assert authorization.request == req
        assert authorization.payload["from"] == PAYER.address

    async def test_hook_must_return_a_reference(self) -> None:
        method = evm(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=lambda a: "")
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await method.intents["charge"].broadcast(native_credential(req), req)  # type: ignore[union-attr]

    async def test_failed_settlement_releases_the_claim(self) -> None:
        store = MemoryStore()
        facilitator = FakeFacilitator(
            settle={
                "success": False,
                "errorMessage": "nonce used",
                "transaction": "",
                "network": "x",
            }
        )
        method = server_method(facilitator)
        intent = method.intents["charge"]
        intent._store = store  # type: ignore[union-attr]
        req = request(method)
        credential = native_credential(req)
        with pytest.raises(VerificationFailedError, match="nonce used"):
            await intent.broadcast(credential, req)  # type: ignore[union-attr]
        assert store._data == {}

        facilitator.settle_response = {
            "success": True,
            "transaction": "0xdone",
            "network": "eip155:84532",
        }
        receipt = await intent.broadcast(credential, req)  # type: ignore[union-attr]
        assert receipt.reference == "0xdone"
        assert list(store._data.values()) == ["0xdone"]

    async def test_unknown_settlement_outcome_keeps_the_claim(self) -> None:
        store = MemoryStore()
        method = server_method(FakeFacilitator(settle=FacilitatorError("timeout")))
        intent = method.intents["charge"]
        intent._store = store  # type: ignore[union-attr]
        req = request(method)
        credential = native_credential(req)
        with pytest.raises(InternalPaymentError):
            await intent.broadcast(credential, req)  # type: ignore[union-attr]
        with pytest.raises(CredentialReplayedError):
            await intent.broadcast(credential, req)  # type: ignore[union-attr]

    async def test_claims_each_authorization_once(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        intent = method.intents["charge"]
        intent._store = MemoryStore()  # type: ignore[union-attr]
        req = request(method)
        credential = native_credential(req)
        await intent.broadcast(credential, req)  # type: ignore[union-attr]
        with pytest.raises(CredentialReplayedError):
            await intent.broadcast(credential, req)  # type: ignore[union-attr]
        assert len(facilitator.settled) == 1

    async def test_success_without_a_transaction_is_an_internal_error(self) -> None:
        method = server_method(
            FakeFacilitator(settle={"success": True, "transaction": "", "network": "x"})
        )
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await method.intents["charge"].broadcast(native_credential(req), req)  # type: ignore[union-attr]


class TestX402Conversion:
    def payment(self, body: dict[str, Any]) -> PaymentPayload:
        intent = server_method().intents["charge"]
        assert isinstance(intent, ChargeIntent)
        return {"x402Version": 2, "accepted": intent.x402_requirements(request()), "payload": body}

    def test_converts_eip3009_payloads(self) -> None:
        intent = server_method().intents["charge"]
        assert isinstance(intent, ChargeIntent)
        authorization = {
            "from": PAYER.address,
            "to": RECIPIENT,
            "value": "10000",
            "validAfter": "0",
            "validBefore": "9999999999",
            "nonce": "0x" + "11" * 32,
        }
        payload, source = intent.x402_credential_payload(
            self.payment({"authorization": authorization, "signature": "0x" + "22" * 65}),
            request(),
        )
        assert payload == {"type": "authorization", **authorization, "signature": "0x" + "22" * 65}
        assert source == to_source(address=PAYER.address, chain_id=84532)

    def test_rejects_permit2_payloads(self) -> None:
        intent = server_method().intents["charge"]
        assert isinstance(intent, ChargeIntent)
        with pytest.raises(VerificationFailedError, match="EIP-3009"):
            intent.x402_credential_payload(
                self.payment({"permit2Authorization": {}, "signature": "0x00"}), request()
            )

    def test_rejects_malformed_eip3009_payloads(self) -> None:
        intent = server_method().intents["charge"]
        assert isinstance(intent, ChargeIntent)
        with pytest.raises(InvalidPayloadError):
            intent.x402_credential_payload(
                self.payment({"authorization": {"from": "0x1"}, "signature": "0x00"}), request()
            )


class TestClient:
    def challenge(self, **request_overrides: Any) -> Challenge:
        req = {**request(), **request_overrides}
        expires = (datetime.now(UTC) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        return Challenge.create(
            secret_key="k",
            realm=REALM,
            method="evm",
            intent="charge",
            request=req,
            expires=expires,
        )

    async def test_signs_a_credential_the_server_accepts(self) -> None:
        challenge = self.challenge()
        credential = await evm(currency=BASE_SEPOLIA_USDC, account=PAYER).create_credential(
            challenge
        )
        assert credential.payload["nonce"] == challenge_hash(challenge.id, REALM)
        assert credential.payload["validBefore"] == str(
            int(datetime.fromisoformat(challenge.expires.replace("Z", "+00:00")).timestamp())  # type: ignore[union-attr]
        )
        assert credential.source == to_source(address=PAYER.address, chain_id=84532)
        method = server_method()
        validation = await method.intents["charge"].validate(credential, challenge.request)  # type: ignore[union-attr]
        assert validation.payer == PAYER.address

    async def test_defaults_validity_without_expires(self) -> None:
        challenge = Challenge(id="c", method="evm", intent="charge", request=request(), realm=REALM)
        credential = await evm(currency=BASE_SEPOLIA_USDC, account=PAYER).create_credential(
            challenge
        )
        assert int(credential.payload["validBefore"]) >= int(time.time()) + 290

    @pytest.mark.parametrize(
        "overrides",
        [
            {"currency": BASE_USDC.address},
            {"methodDetails": {"chainId": 8453, "credentialTypes": ["authorization"]}},
            {"methodDetails": {"chainId": 84532}},
            {
                "methodDetails": {
                    "chainId": 84532,
                    "credentialTypes": ["authorization"],
                    "splits": [{"amount": "1"}],
                }
            },
            {"amount": "1.5"},
            {"recipient": "bob"},
            {"methodDetails": None},
            {"amount": "20001"},
        ],
    )
    async def test_refuses_challenges_it_cannot_pay(self, overrides: dict[str, Any]) -> None:
        method = evm(currency=BASE_SEPOLIA_USDC, account=PAYER, max_amount="0.02")
        challenge = self.challenge(**overrides)
        assert not method.can_handle_challenge(challenge)
        with pytest.raises(ValueError):
            await method.create_credential(challenge)

    async def test_requires_an_account(self) -> None:
        with pytest.raises(ValueError, match="No account"):
            await server_method().create_credential(self.challenge())

    def test_client_methods_match_evm_charge(self) -> None:
        method = evm(currency=BASE_SEPOLIA_USDC, account=PAYER)
        assert list(method.intents) == ["charge"]
        assert method.can_handle_challenge(self.challenge())
