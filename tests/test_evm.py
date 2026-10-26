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
from mpp.methods.evm import client as evm_client
from mpp.methods.evm import server as evm_server
from mpp.methods.evm._eip3009 import authorization_domain, sign_authorization, to_source
from mpp.runtime import ClientMethod, CredentialParams
from mpp.server import Mpp
from mpp.server.method import RequestContext, ServerMethod
from mpp.store import MemoryStore
from mpp.x402 import FacilitatorError, PaymentPayload, PaymentRequirements
from tests import http_request

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


def server_method(facilitator: Any = None, **kwargs: Any) -> ServerMethod:
    return evm_server.charge(
        currency=BASE_SEPOLIA_USDC,
        recipient=RECIPIENT,
        facilitator=facilitator or FakeFacilitator(),
        **kwargs,
    )


def charge_intent(method: ServerMethod) -> ChargeIntent:
    assert isinstance(method.x402, ChargeIntent)
    return method.x402


def resolve(method: ServerMethod, **options: Any) -> dict[str, Any]:
    """Resolve route options to the wire request a challenge carries."""
    assert method.resolve_request is not None
    resolved = method.resolve_request(RequestContext(request=options))
    assert isinstance(resolved, dict)
    return method.method.normalize_request(resolved)


def request(method: ServerMethod | None = None, amount: str = "0.01") -> dict[str, Any]:
    return resolve(method or server_method(), amount=amount)


async def sign(method: ClientMethod, challenge: Challenge) -> Credential:
    return Credential.from_authorization(
        await method.create_credential(CredentialParams(challenge=challenge))
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
        assert method.key == "evm/charge"
        req = request(method)
        assert req["currency"] == BASE_SEPOLIA_USDC.address
        assert (req["methodDetails"]["chainId"], req["methodDetails"]["decimals"]) == (84532, 6)
        intent = charge_intent(method)
        assert (intent.domain_name, intent.domain_version) == ("USDC", "2")

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
        details = request(method)["methodDetails"]
        assert (details["chainId"], details["decimals"]) == (31337, 18)
        assert charge_intent(method).domain_name == "Token"

    @pytest.mark.parametrize("decimals", [True, 1.5, -1, 37])
    def test_rejects_invalid_decimal_overrides(self, decimals: Any) -> None:
        with pytest.raises(ValueError, match="decimals"):
            server_method(decimals=decimals)
        with pytest.raises(ValueError, match="decimals"):
            evm(
                currency="0x" + "aa" * 20,
                recipient=RECIPIENT,
                settle=lambda a: "0x1",
                chain_id=31337,
                decimals=decimals,
                authorization={"name": "Token", "version": "1"},
            )

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
        with pytest.raises(ValueError, match="route_binding"):
            ChargeIntent(name="USDC", version="2", settle=lambda a: "0x1", route_binding="none")  # type: ignore[arg-type]
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

    def test_uses_its_store(self) -> None:
        store = MemoryStore()
        assert charge_intent(server_method(store=store))._store is store

    def test_mpp_wires_its_store(self) -> None:
        store = MemoryStore()
        method = server_method()
        Mpp(methods=method, realm=REALM, secret_key="k", store=store)
        assert charge_intent(method)._store is store

    def test_mpp_store_does_not_replace_its_own(self) -> None:
        own = MemoryStore()
        method = server_method(store=own)
        Mpp(methods=method, realm=REALM, secret_key="k", store=MemoryStore())
        assert charge_intent(method)._store is own

    def test_without_a_store_claims_stay_in_process(self) -> None:
        method = server_method()
        Mpp(methods=method, realm=REALM, secret_key="k")
        assert charge_intent(method)._store is None


class TestRequestShape:
    def test_matches_mppx_evm_charge_requests(self) -> None:
        method = server_method()
        assert resolve(
            method,
            amount="0.01",
            currency=BASE_SEPOLIA_USDC.address.lower(),
            recipient=RECIPIENT.lower(),
            chain_id=84532,
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

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"currency": "0x" + "bb" * 20}, "currency"),
            ({"recipient": "bob"}, "recipient"),
            ({"chain_id": 1}, "chain_id"),
            ({"splits": [{"amount": "1", "recipient": RECIPIENT}]}, "splits"),
            ({"fee_payer": True}, "fee_payer"),
            ({"amount": ""}, "amount"),
        ],
    )
    def test_rejects_requests_evm_cannot_pay(self, change: dict[str, Any], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            resolve(server_method(), **{"amount": "0.01", **change})

    def test_rejects_unknown_options(self) -> None:
        with pytest.raises(TypeError, match="unsupported option: nope"):
            resolve(server_method(), amount="0.01", nope=True)

    async def test_mpp_rejects_splits_and_fee_payer(self) -> None:
        server = Mpp(methods=server_method(), realm=REALM, secret_key="k")
        with pytest.raises(ValueError, match="fee_payer"):
            await server.charge(amount="0.01", fee_payer=True)(http_request())

    def test_x402_requirements(self) -> None:
        intent = charge_intent(server_method(max_timeout_seconds=60))
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
        validation = await charge_intent(method).validate(native_credential(req), req)
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
            await charge_intent(method).validate(native_credential(req, **overrides), req)
        assert facilitator.verified == []

    async def test_rejects_signatures_by_another_key(self) -> None:
        method = server_method()
        req = request(method)
        with pytest.raises(VerificationFailedError, match="signature mismatch"):
            await charge_intent(method).validate(native_credential(req, signer=OTHER), req)

    async def test_x402_credentials_are_not_bound_to_a_challenge_hash(self) -> None:
        method = server_method()
        req = request(method)
        credential = x402_echo(native_credential(req, nonce="0x" + "42" * 32))
        validation = await charge_intent(method).validate(credential, req)
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
            await charge_intent(method).validate(native_credential(req, source=source), req)

    async def test_source_is_optional(self) -> None:
        method = server_method()
        req = request(method)
        await charge_intent(method).validate(native_credential(req, source=None), req)

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
            await charge_intent(method).validate(bad, req)

    async def test_rejects_authorizations_valid_for_too_long(self) -> None:
        method = server_method()
        req = request(method)
        credential = x402_echo(native_credential(req, validBefore=str(int(time.time()) + 7200)))
        with pytest.raises(VerificationFailedError, match="valid for too long"):
            await charge_intent(method).validate(credential, req)
        longer = server_method(max_validity_seconds=86_400)
        await charge_intent(longer).validate(credential, req)
        with pytest.raises(ValueError, match="max_validity_seconds"):
            server_method(max_validity_seconds=10)

    async def test_native_credentials_may_run_to_challenge_expiry(self) -> None:
        method = server_method()
        req = request(method)
        valid_before = int(time.time()) + 7200
        signed = native_credential(req, validBefore=str(valid_before))
        expires = datetime.fromtimestamp(valid_before, UTC).isoformat().replace("+00:00", "Z")
        echo = ChallengeEcho(
            id=signed.challenge.id,
            realm=REALM,
            method="evm",
            intent="charge",
            request=signed.challenge.request,
            expires=expires,
        )
        credential = Credential(challenge=echo, payload=signed.payload, source=signed.source)
        await charge_intent(method).validate(credential, req)
        # Without a challenge expiry the one-hour cap still applies.
        with pytest.raises(VerificationFailedError, match="valid for too long"):
            await charge_intent(method).validate(signed, req)

    async def test_rejects_values_too_long_to_parse(self) -> None:
        method = server_method()
        req = request(method)
        credential = native_credential(req, value="9" * 5000, signature="0x" + "00" * 65)
        with pytest.raises(InvalidPayloadError, match="value is malformed"):
            await charge_intent(method).validate(credential, req)

    async def test_rejects_out_of_range_values(self) -> None:
        method = server_method()
        req = request(method)
        credential = native_credential(req, validBefore=str(2**256), signature="0x" + "00" * 65)
        with pytest.raises(InvalidPayloadError, match="out of range"):
            await charge_intent(method).validate(credential, req)

    async def test_rejects_requests_without_authorization_credentials(self) -> None:
        method = server_method()
        req = request(method)
        credential = native_credential(req)
        stripped = {**req, "methodDetails": {"chainId": 84532}}
        with pytest.raises(VerificationFailedError, match="not supported"):
            await charge_intent(method).validate(credential, stripped)
        with pytest.raises(VerificationFailedError, match="splits"):
            await charge_intent(method).validate(
                credential,
                {**req, "methodDetails": {**req["methodDetails"], "splits": [{"amount": "1"}]}},
            )
        with pytest.raises(VerificationFailedError, match="chainId"):
            await charge_intent(method).validate(credential, {**req, "methodDetails": {}})

    async def test_facilitator_rejection(self) -> None:
        facilitator = FakeFacilitator(
            verify={"isValid": False, "invalidReason": "insufficient_funds"}
        )
        method = server_method(facilitator)
        req = request(method)
        with pytest.raises(VerificationFailedError, match="insufficient_funds"):
            await charge_intent(method).validate(native_credential(req), req)

    async def test_facilitator_message_wins_over_reason(self) -> None:
        facilitator = FakeFacilitator(
            verify={"isValid": False, "invalidReason": "r", "invalidMessage": "human message"}
        )
        method = server_method(facilitator)
        req = request(method)
        with pytest.raises(VerificationFailedError, match="human message"):
            await charge_intent(method).validate(native_credential(req), req)

    async def test_facilitator_outage_is_an_internal_error(self) -> None:
        method = server_method(FakeFacilitator(verify=FacilitatorError("down")))
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await charge_intent(method).validate(native_credential(req), req)

    async def test_custom_settle_skips_the_facilitator(self) -> None:
        facilitator = FakeFacilitator()
        method = evm(
            currency=BASE_SEPOLIA_USDC,
            recipient=RECIPIENT,
            facilitator=facilitator,
            settle=lambda authorization: "0x1",
        )
        req = request(method)
        await charge_intent(method).validate(native_credential(req), req)
        assert facilitator.verified == []


class TestBroadcast:
    async def test_settles_through_the_facilitator(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        req = request(method)
        receipt = await charge_intent(method).broadcast(native_credential(req), req)
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
        receipt = await charge_intent(method).broadcast(native_credential(req), req)
        assert receipt.reference == "0xhook"
        [authorization] = seen
        assert authorization.source == to_source(address=PAYER.address, chain_id=84532)
        assert authorization.request == req
        assert authorization.payload["from"] == PAYER.address

    async def test_hook_must_return_a_reference(self) -> None:
        method = evm(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=lambda a: "")
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await charge_intent(method).broadcast(native_credential(req), req)

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
        intent = charge_intent(method)
        intent._store = store
        req = request(method)
        credential = native_credential(req)
        with pytest.raises(VerificationFailedError, match="nonce used"):
            await intent.broadcast(credential, req)
        assert store._data == {}

        facilitator.settle_response = {
            "success": True,
            "transaction": "0xdone",
            "network": "eip155:84532",
        }
        receipt = await intent.broadcast(credential, req)
        assert receipt.reference == "0xdone"
        assert list(store._data.values()) == ["0xdone"]

    async def test_unknown_settlement_outcome_keeps_the_claim(self) -> None:
        store = MemoryStore()
        method = server_method(FakeFacilitator(settle=FacilitatorError("timeout")))
        intent = charge_intent(method)
        intent._store = store
        req = request(method)
        credential = native_credential(req)
        with pytest.raises(InternalPaymentError):
            await intent.broadcast(credential, req)
        with pytest.raises(CredentialReplayedError):
            await intent.broadcast(credential, req)

    async def test_pending_settlement_keeps_the_claim(self) -> None:
        store = MemoryStore()
        method = server_method(
            FakeFacilitator(
                settle={
                    "success": False,
                    "errorReason": "settlement_pending",
                    "transaction": "0xpending",
                    "network": "eip155:84532",
                }
            )
        )
        intent = charge_intent(method)
        intent._store = store
        req = request(method)
        credential = native_credential(req)
        with pytest.raises(InternalPaymentError):
            await intent.broadcast(credential, req)
        assert list(store._data.values()) == ["pending"]
        with pytest.raises(CredentialReplayedError):
            await intent.validate(credential, req)

    async def test_validate_reports_claimed_authorizations_as_replays(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        intent = charge_intent(method)
        intent._store = MemoryStore()
        req = request(method)
        credential = native_credential(req)
        await intent.broadcast(credential, req)
        facilitator.verified.clear()
        with pytest.raises(CredentialReplayedError):
            await intent.validate(credential, req)
        # Reported before asking the facilitator.
        assert facilitator.verified == []

    async def test_claims_without_a_configured_store(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        intent = charge_intent(method)
        req = request(method)
        credential = native_credential(req)
        await intent.broadcast(credential, req)
        with pytest.raises(CredentialReplayedError):
            await intent.broadcast(credential, req)
        with pytest.raises(CredentialReplayedError):
            await intent.validate(credential, req)
        assert len(facilitator.settled) == 1

    async def test_fallback_claims_expire_with_their_authorization(self) -> None:
        from mpp.methods.evm.intents import _ClaimCache

        cache = _ClaimCache()
        assert await cache.put_if_absent("old", "pending")
        cache.claim_until("old", int(time.time()) - 120)
        assert await cache.put_if_absent("new", "pending")
        cache.claim_until("new", int(time.time()) + 300)
        # Writing prunes expired claims; live ones still block duplicates.
        assert await cache.put_if_absent("another", "pending")
        assert await cache.get("old") is None
        assert not await cache.put_if_absent("new", "pending")
        await cache.delete("new")
        assert await cache.put_if_absent("new", "pending")

    async def test_full_fallback_cache_refuses_without_evicting_live_claims(self) -> None:
        from mpp.methods.evm.intents import _ClaimCache

        cache = _ClaimCache(max_entries=2)
        now = int(time.time())
        for key in ("a", "b"):
            assert await cache.put_if_absent(key, "pending")
            cache.claim_until(key, now + 300)
        method = server_method()
        intent = charge_intent(method)
        intent._store = cache
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await intent.broadcast(native_credential(req), req)
        # Live claims are kept and still block duplicates.
        assert not await cache.put_if_absent("a", "pending")
        assert not await cache.put_if_absent("b", "pending")

    async def test_rolled_back_claims_do_not_grow_the_heap(self) -> None:
        from mpp.methods.evm.intents import _ClaimCache

        cache = _ClaimCache()
        now = int(time.time())
        for _ in range(5000):
            assert await cache.put_if_absent("k", "pending")
            cache.claim_until("k", now + 300)
            await cache.delete("k")
        assert len(cache._heap) <= 1025
        assert cache._data == {} and cache._expires == {}

    async def test_claims_each_authorization_once(self) -> None:
        facilitator = FakeFacilitator()
        method = server_method(facilitator)
        intent = charge_intent(method)
        intent._store = MemoryStore()
        req = request(method)
        credential = native_credential(req)
        await intent.broadcast(credential, req)
        with pytest.raises(CredentialReplayedError):
            await intent.broadcast(credential, req)
        assert len(facilitator.settled) == 1

    async def test_success_without_a_transaction_is_an_internal_error(self) -> None:
        method = server_method(
            FakeFacilitator(settle={"success": True, "transaction": "", "network": "x"})
        )
        req = request(method)
        with pytest.raises(InternalPaymentError):
            await charge_intent(method).broadcast(native_credential(req), req)


class TestX402Conversion:
    def payment(self, body: dict[str, Any]) -> PaymentPayload:
        intent = charge_intent(server_method())
        assert isinstance(intent, ChargeIntent)
        return {"x402Version": 2, "accepted": intent.x402_requirements(request()), "payload": body}

    def test_converts_eip3009_payloads(self) -> None:
        intent = charge_intent(server_method())
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
        intent = charge_intent(server_method())
        assert isinstance(intent, ChargeIntent)
        with pytest.raises(VerificationFailedError, match="EIP-3009"):
            intent.x402_credential_payload(
                self.payment({"permit2Authorization": {}, "signature": "0x00"}), request()
            )

    def test_rejects_malformed_eip3009_payloads(self) -> None:
        intent = charge_intent(server_method())
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

    def test_requires_an_account(self) -> None:
        with pytest.raises(ValueError, match="No account"):
            evm_client.charge(currency=BASE_SEPOLIA_USDC, account=None)  # type: ignore[arg-type]

    async def test_signs_a_credential_the_server_accepts(self) -> None:
        challenge = self.challenge()
        credential = await sign(
            evm_client.charge(currency=BASE_SEPOLIA_USDC, account=PAYER), challenge
        )
        assert credential.payload["nonce"] == challenge_hash(challenge.id, REALM)
        assert credential.payload["validBefore"] == str(
            int(datetime.fromisoformat(challenge.expires.replace("Z", "+00:00")).timestamp())  # type: ignore[union-attr]
        )
        assert credential.source == to_source(address=PAYER.address, chain_id=84532)
        method = server_method()
        validation = await charge_intent(method).validate(credential, challenge.request)
        assert validation.payer == PAYER.address

    async def test_defaults_validity_without_expires(self) -> None:
        challenge = Challenge(id="c", method="evm", intent="charge", request=request(), realm=REALM)
        credential = await sign(
            evm_client.charge(currency=BASE_SEPOLIA_USDC, account=PAYER), challenge
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
            {"amount": "0"},
        ],
    )
    async def test_refuses_challenges_it_cannot_pay(self, overrides: dict[str, Any]) -> None:
        method = evm_client.charge(currency=BASE_SEPOLIA_USDC, account=PAYER, max_amount="0.02")
        challenge = self.challenge(**overrides)
        assert method.can_handle_challenge is not None
        assert not method.can_handle_challenge(challenge)
        with pytest.raises(ValueError):
            await sign(method, challenge)

    def test_client_methods_match_evm_charge(self) -> None:
        method = evm_client.charge(currency=BASE_SEPOLIA_USDC, account=PAYER)
        assert method.key == "evm/charge"
        assert method.can_handle_challenge is not None
        assert method.can_handle_challenge(self.challenge())


def test_evm_shorthand_creates_either_side() -> None:
    assert isinstance(
        evm(currency=BASE_SEPOLIA_USDC, recipient=RECIPIENT, settle=lambda a: "0x1"), ServerMethod
    )
    assert isinstance(evm(currency=BASE_SEPOLIA_USDC, account=PAYER), ClientMethod)
