"""Settlement hardening of the EVM charge server (ports pympp#320 regression tests)."""

import json
import time
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from eth_account import Account

from mpp import Challenge, Credential, evm
from mpp import store as _store
from mpp.client import Mpp as ClientMppx
from mpp.errors import CredentialReplayedError, VerificationFailedError
from mpp.evm import assets
from mpp.evm import client as evm_client
from mpp.evm import server as evm_server
from mpp.evm.server import _claims
from mpp.server import Mpp, Request, Response
from mpp.x402 import PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER, facilitator

from ._helpers import PRIVATE_KEY, SECRET_KEY, TRANSACTION, Facilitator

RECIPIENT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
REALM = "example.test"
URL = "https://example.test/paid"
account = Account.from_key(PRIVATE_KEY)
other = Account.from_key("0x" + "42" * 32)


class Settler:
    """A custom settle hook returning queued outcomes (results or exceptions)."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    async def __call__(self, params: evm_server.SettleParams) -> evm_server.SettleResult:
        self.calls += 1
        outcome = self.outcomes.pop(0) if self.outcomes else TRANSACTION
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, str):
            return evm_server.SettleResult(reference=outcome)
        return outcome


class Settlements(Facilitator):
    """A facilitator double whose settle answers are queued (dicts or exceptions)."""

    def __init__(self, *answers: Any, verify: Any = None) -> None:
        super().__init__()
        self.answers = list(answers)
        self.verify_answer = verify

    async def verify(self, payment_payload: Any, payment_requirements: Any) -> dict[str, Any]:
        if isinstance(self.verify_answer, BaseException):
            self.reached.append("verify")
            raise self.verify_answer
        return await super().verify(payment_payload, payment_requirements)

    async def settle(self, payment_payload: Any, payment_requirements: Any) -> Any:
        if not self.answers:
            return await super().settle(payment_payload, payment_requirements)
        self.reached.append("settle")
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def server(
    *,
    settle: evm_server.SettleAuthorization | None = None,
    facilitator: Any = None,
    **options: Any,
) -> Mpp:
    x402 = evm_server.X402Options(facilitator=facilitator) if facilitator is not None else None
    return Mpp(
        methods=[
            evm_server.charge(
                currency=assets.BASE_SEPOLIA_USDC,
                recipient=RECIPIENT,
                settle=settle,
                x402=x402,
                **options,
            )
        ],
        realm=REALM,
        secret_key=SECRET_KEY,
    )


async def challenge_of(mppx: Mpp, **route: Any) -> Challenge:
    result = await mppx.evm.charge(amount="0.25", **route)(Request("GET", URL))
    assert result.status == 402
    return Challenge.from_headers(result.challenge.headers)  # type: ignore[attr-defined]


def sign(
    challenge: Challenge,
    *,
    signer: Any = account,
    source: str | None = "default",
    signature: str | None = None,
    **overrides: str,
) -> str:
    """Signs a native authorization credential for ``challenge`` (overrides are signed too)."""
    payload = {
        "from": account.address,
        "nonce": evm.challenge_hash(id=challenge.id, realm=challenge.realm),
        "to": challenge.request["recipient"],
        "type": "authorization",
        "validAfter": "0",
        "validBefore": str(int(time.time()) + 120),
        "value": challenge.request["amount"],
        **overrides,
    }
    if signature is None:
        signed = signer.sign_typed_data(
            full_message=evm.authorization_typed_data(
                authorization=evm.AuthorizationConfig(name="USDC", version="2"),
                chain_id=84532,
                currency=challenge.request["currency"],
                from_=payload["from"],
                to=payload["to"],
                value=payload["value"],
                valid_after=payload["validAfter"],
                valid_before=payload["validBefore"],
                nonce=payload["nonce"],
            )
        )
        signature = "0x" + bytes(signed.signature).hex()
    payload["signature"] = signature
    if source == "default":
        source = f"did:pkh:eip155:84532:{account.address}"
    return Credential(challenge=challenge, payload=payload, source=source).serialize()


async def pay(mppx: Mpp, credential: str, header: str = "Authorization") -> Any:
    return await mppx.evm.charge(amount="0.25")(Request("GET", URL, headers={header: credential}))


def problem(result: Any) -> dict[str, Any]:
    response = result.challenge
    assert isinstance(response, Response)
    assert isinstance(response.body, bytes)
    return json.loads(response.body)


def assert_no_challenge(result: Any, status: int) -> None:
    response = result.challenge
    assert response.status == status
    assert "www-authenticate" not in response.headers
    assert PAYMENT_REQUIRED_HEADER not in response.headers


async def x402_signature(mppx: Mpp) -> str:
    first = await mppx.evm.charge(amount="0.25")(Request("GET", URL))
    x402_only = httpx.Response(
        402,
        headers={PAYMENT_REQUIRED_HEADER: first.challenge.headers[PAYMENT_REQUIRED_HEADER]},  # type: ignore[attr-defined]
        request=httpx.Request("GET", URL),
    )
    client = ClientMppx(
        methods=[evm_client.charge(account=account, currencies=[assets.BASE_SEPOLIA_USDC])]
    )
    return await (await client.prepare_payment(x402_only)).create_credential()


# -- replay claims -----------------------------------------------------------------------------


async def test_claims_each_authorization_once() -> None:
    settle = Settler()
    mppx = server(settle=settle)
    credential = sign(await challenge_of(mppx))
    assert (await pay(mppx, credential)).status == 200
    replay = await pay(mppx, credential)
    assert_no_challenge(replay, 403)
    assert problem(replay)["detail"] == (
        "Payment verification failed: EVM authorization has already been used."
    )
    assert settle.calls == 1


async def test_replayed_payment() -> None:
    settlements = Settlements()
    mppx = server(facilitator=settlements)
    signature = await x402_signature(mppx)
    assert (await pay(mppx, signature, PAYMENT_SIGNATURE_HEADER)).status == 200
    replay = await pay(mppx, signature, PAYMENT_SIGNATURE_HEADER)
    assert_no_challenge(replay, 403)
    assert settlements.reached == ["verify", "settle"]


async def test_replay_with_a_store_is_a_403_without_a_challenge() -> None:
    store = _store.memory()
    settle = Settler()
    first, second = server(settle=settle, store=store), server(settle=settle, store=store)
    credential = sign(await challenge_of(first))
    assert (await pay(first, credential)).status == 200
    # Another instance sharing the store sees the claim.
    assert_no_challenge(await pay(second, credential), 403)
    assert settle.calls == 1


async def test_validate_reports_claimed_authorizations_as_replays() -> None:
    settlements = Settlements()
    mppx = server(facilitator=settlements)
    credential = sign(await challenge_of(mppx))
    assert (await pay(mppx, credential)).status == 200
    settlements.reached.clear()
    with pytest.raises(CredentialReplayedError):
        await mppx.validate_credential(credential, request={"amount": "0.25"}, realm=REALM)
    # Reported before asking the facilitator.
    assert settlements.reached == []


async def test_claims_without_a_configured_store() -> None:
    settle = Settler()
    mppx = server(settle=settle)
    credential = sign(await challenge_of(mppx))
    assert (await pay(mppx, credential)).status == 200
    with pytest.raises(CredentialReplayedError):
        await mppx.broadcast_credential(credential, request={"amount": "0.25"}, realm=REALM)
    assert settle.calls == 1


async def test_fallback_claims_expire_with_their_authorization() -> None:
    cache = _claims.ClaimCache()
    now = int(time.time())
    assert await _store.try_claim(cache, "old", _claims.claim_expires(now - 120))
    assert await _store.try_claim(cache, "new", _claims.claim_expires(now + 300))
    # Writing prunes expired claims; live ones still block duplicates.
    assert await _store.try_claim(cache, "another", _claims.claim_expires(now + 300))
    assert await cache.get("old") is None
    assert not await _store.try_claim(cache, "new", _claims.claim_expires(now + 300))
    await cache.delete("new")
    assert await _store.try_claim(cache, "new", _claims.claim_expires(now + 300))


async def test_full_fallback_cache_refuses_without_evicting_live_claims() -> None:
    cache = _claims.ClaimCache(max_entries=2)
    expires = _claims.claim_expires(int(time.time()) + 300)
    for key in ("a", "b"):
        assert await _store.try_claim(cache, key, expires)
    settle = Settler()
    mppx = server(settle=settle, store=cache)
    result = await pay(mppx, sign(await challenge_of(mppx)))
    assert_no_challenge(result, 500)
    assert settle.calls == 0
    # Live claims are kept and still block duplicates.
    assert not await _store.try_claim(cache, "a", expires)
    assert not await _store.try_claim(cache, "b", expires)


async def test_rolled_back_claims_do_not_grow_the_heap() -> None:
    cache = _claims.ClaimCache()
    expires = _claims.claim_expires(int(time.time()) + 300)
    for _ in range(5000):
        assert await _store.try_claim(cache, "k", expires)
        await cache.delete("k")
    assert len(cache._heap) <= 1025
    assert cache._data == {}


async def test_failed_settlement_releases_the_claim() -> None:
    settle = Settler(VerificationFailedError(reason="nonce used"))
    mppx = server(settle=settle)
    credential = sign(await challenge_of(mppx))
    failed = await pay(mppx, credential)
    assert failed.status == 402
    assert problem(failed)["detail"] == "Payment verification failed: nonce used."
    assert (await pay(mppx, credential)).status == 200
    assert settle.calls == 2


async def test_unknown_settlement_outcome_keeps_the_claim() -> None:
    settlements = Settlements(facilitator.FacilitatorError("timeout"))
    mppx = server(facilitator=settlements)
    credential = sign(await challenge_of(mppx))
    assert_no_challenge(await pay(mppx, credential), 500)
    assert_no_challenge(await pay(mppx, credential), 403)


async def test_pending_settlement_is_a_server_error_without_a_challenge() -> None:
    settlements = Settlements(
        {
            "errorReason": "settlement_pending",
            "network": "eip155:84532",
            "success": False,
            "transaction": "0xpending",
        }
    )
    mppx = server(facilitator=settlements)
    signature = await x402_signature(mppx)
    pending = await pay(mppx, signature, PAYMENT_SIGNATURE_HEADER)
    assert_no_challenge(pending, 500)
    assert problem(pending)["type"].endswith("/internal-payment-error")
    # The claim is kept.
    assert_no_challenge(await pay(mppx, signature, PAYMENT_SIGNATURE_HEADER), 403)


async def test_facilitator_outage_is_an_internal_error() -> None:
    settlements = Settlements(verify=facilitator.FacilitatorError("down"))
    mppx = server(facilitator=settlements)
    credential = sign(await challenge_of(mppx))
    assert_no_challenge(await pay(mppx, credential), 500)
    # Verification runs before the claim, so the payer can retry once the facilitator is back.
    settlements.verify_answer = None
    assert (await pay(mppx, credential)).status == 200


@pytest.mark.parametrize(
    "answer",
    [
        {"oops": True},
        facilitator.FacilitatorError("connection reset"),
    ],
)
async def test_unreadable_settlement_is_a_server_error(answer: Any) -> None:
    mppx = server(facilitator=Settlements(answer))
    signature = await x402_signature(mppx)
    assert_no_challenge(await pay(mppx, signature, PAYMENT_SIGNATURE_HEADER), 500)


async def test_success_without_a_transaction_is_an_internal_error() -> None:
    mppx = server(
        facilitator=Settlements({"network": "eip155:84532", "success": True, "transaction": ""})
    )
    assert_no_challenge(await pay(mppx, sign(await challenge_of(mppx))), 500)


async def test_hook_must_return_a_reference() -> None:
    mppx = server(settle=Settler(""))
    assert_no_challenge(await pay(mppx, sign(await challenge_of(mppx))), 500)


async def test_unexpected_settlement_errors_are_reported_without_a_challenge() -> None:
    settle = Settler(RuntimeError("boom"))
    mppx = server(settle=settle)
    failures: list[Any] = []
    mppx.on_payment_failed(failures.append)
    credential = sign(await challenge_of(mppx))
    assert_no_challenge(await pay(mppx, credential), 500)
    assert len(failures) == 1
    # The hook may have moved funds: the claim stays.
    assert_no_challenge(await pay(mppx, credential), 403)
    assert settle.calls == 1


# -- validity window ---------------------------------------------------------------------------


async def test_rejects_authorizations_valid_for_too_long() -> None:
    mppx = server(settle=Settler())
    challenge = await challenge_of(mppx)
    credential = sign(challenge, validBefore=str(int(time.time()) + 7200))
    rejected = await pay(mppx, credential)
    assert rejected.status == 402
    assert problem(rejected)["detail"] == (
        "Payment verification failed: EVM authorization is valid for too long."
    )
    longer = server(settle=Settler(), max_validity_seconds=86_400)
    assert (await pay(longer, credential)).status == 200
    with pytest.raises(ValueError, match="max_validity_seconds"):
        server(settle=Settler(), max_validity_seconds=10)


async def test_native_credentials_may_run_to_challenge_expiry() -> None:
    mppx = server(settle=Settler())
    valid_before = int(time.time()) + 7200
    expires = datetime.fromtimestamp(valid_before, UTC).isoformat().replace("+00:00", "Z")
    challenge = await challenge_of(mppx, expires=expires)
    assert (await pay(mppx, sign(challenge, validBefore=str(valid_before)))).status == 200


# -- payload checks ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "detail"),
    [
        (
            {"value": "9" * 5000},
            "Credential payload is invalid: EVM authorization value is malformed.",
        ),
        (
            {"validBefore": str(2**256)},
            "Credential payload is invalid: EVM authorization validBefore is out of range.",
        ),
    ],
)
async def test_rejects_values_too_long_to_parse(overrides: dict[str, str], detail: str) -> None:
    mppx = server(settle=Settler())
    challenge = await challenge_of(mppx)
    result = await pay(mppx, sign(challenge, signature="0x" + "00" * 65, **overrides))
    assert result.status == 402
    assert problem(result)["detail"] == detail


@pytest.mark.parametrize("signature", ["0x" + "00" * 65, "0x1234"])
async def test_rejects_unrecoverable_signatures(signature: str) -> None:
    mppx = server(settle=Settler())
    result = await pay(mppx, sign(await challenge_of(mppx), signature=signature))
    assert result.status == 402
    assert problem(result)["detail"] == (
        "Payment verification failed: EVM authorization signature is invalid."
    )


@pytest.mark.parametrize(
    "source",
    [
        f"did:pkh:eip155:84532:{other.address}",
        f"did:pkh:eip155:8453:{account.address}",
        "did:key:z6Mk",
    ],
)
async def test_rejects_a_mismatched_source(source: str) -> None:
    mppx = server(settle=Settler())
    result = await pay(mppx, sign(await challenge_of(mppx), source=source))
    assert result.status == 402
    assert (
        problem(result)["detail"]
        == "Payment verification failed: EVM authorization source mismatch."
    )


@pytest.mark.parametrize(
    "source", [None, f"did:pkh:eip155:84532:{account.address.lower()}"], ids=["none", "lowercase"]
)
async def test_source_is_optional(source: str | None) -> None:
    mppx = server(settle=Settler())
    assert (await pay(mppx, sign(await challenge_of(mppx), source=source))).status == 200


async def test_challenge_hash_nonce_compares_case_insensitively() -> None:
    mppx = server(settle=Settler())
    challenge = await challenge_of(mppx)
    nonce = "0x" + evm.challenge_hash(id=challenge.id, realm=challenge.realm)[2:].upper()
    assert (await pay(mppx, sign(challenge, nonce=nonce))).status == 200
