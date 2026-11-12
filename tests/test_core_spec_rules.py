"""Core spec rules every SDK server shares.

Problem types and check order for rejected credentials, credential fields, the
per-challenge nonce, the minimum HMAC secret, the method grammar and the client's
handling of an invalid-challenge answer to a paid retry.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, generate_challenge_id
from mpp._parsing import ParseError
from mpp.server import Mpp
from tests.test_behavior_contract import (
    PROBLEMS,
    REALM,
    SECRET,
    ContractMethod,
    app,
    authorization,
    engine_request,
    http,
    issue,
    make_server,
    offers,
    paying,
)


def _rebind(challenge: Challenge, **changes: Any) -> Challenge:
    """Return the challenge with the changes, re-signed with the server secret."""
    changed = replace(challenge, **changes)
    return replace(
        changed,
        id=generate_challenge_id(
            secret_key=SECRET,
            realm=changed.realm,
            method=changed.method,
            intent=changed.intent,
            request=changed.request,
            expires=changed.expires,
            digest=changed.digest,
            opaque=changed.opaque,
            header=changed.header,
        ),
    )


def _past() -> str:
    return (datetime.now(UTC) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")


class TestSecretKey:
    def test_challenge_ids_refuse_a_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 32 bytes"):
            generate_challenge_id(
                secret_key="short",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000000"},
            )

    def test_server_refuses_a_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 32 bytes"):
            Mpp(methods=ContractMethod().server[0], realm=REALM, secret_key="x" * 31)

    @pytest.mark.parametrize(
        ("header", "opaque", "expected"),
        [
            (None, None, "2S2NsFcCINq8QUKV8OZHdRm_JhhbJf5X8Cii4gZ_UyI"),
            ("Payment-Authorization", None, "CfIT3MTJbcDQ7kdEJD9GbLQPvlRZQLnEXyerMinsFMg"),
            (
                "Payment-Authorization",
                {"pi": "pi_123"},
                "fGVr3o_Ve1k0KQpddLKyEXRE7nk6chQOC5lN7Q54dR8",
            ),
        ],
    )
    def test_spec_hmac_vectors(
        self, header: str | None, opaque: dict[str, str] | None, expected: str
    ) -> None:
        assert (
            generate_challenge_id(
                secret_key="mpp-hmac-test-vector-secret-32by",
                realm="api.example.com",
                method="tempo",
                intent="charge",
                request={"amount": "1000000"},
                header=header,
                opaque=opaque,
            )
            == expected
        )


class TestNonce:
    async def test_challenges_carry_a_16_byte_nonce(self) -> None:
        issued = await issue(make_server(ContractMethod()).charge(amount="1"))
        assert issued.opaque is not None
        assert re.fullmatch(r"[A-Za-z0-9_-]{22}", issued.opaque["_mpp_nonce"])

    async def test_nonce_can_be_turned_off(self) -> None:
        server = make_server(ContractMethod(), unique_challenges=False)
        issued = await issue(server.charge(amount="1"))
        assert issued.opaque is None

    @pytest.mark.parametrize("key", ["_mpp_nonce", "_mppx_nonce"])
    async def test_route_meta_matching_ignores_nonces(self, key: str) -> None:
        method = ContractMethod()
        handler = make_server(method).charge(amount="1", meta={"plan": "pro"})
        issued = await issue(handler)
        echoed = _rebind(issued, opaque={"plan": "pro", key: "abc"})
        result = await handler(engine_request(authorization(echoed)))
        assert result.status == 200
        assert method.settled == ["ok"]


class TestCredentialFields:
    async def test_bare_payment_counts_as_absent(self) -> None:
        handler = make_server(ContractMethod()).charge(amount="1")
        async with http(app({"/paid": handler})) as c:
            response = await c.get("/paid", headers={"Authorization": "Payment"})
        assert response.status_code == 402
        assert response.json()["type"] == f"{PROBLEMS}/payment-required"

    async def test_credential_in_the_unselected_field_is_ignored(self) -> None:
        method = ContractMethod()
        handler = make_server(method, requires_auth=True).charge(amount="1")
        issued = await issue(handler)
        result = await handler(engine_request(authorization(issued)))
        assert result.status == 402
        assert offers(result)
        assert method.settled == []

    @pytest.mark.parametrize("where", ["comma-joined", "both-fields"])
    async def test_more_than_one_credential_is_a_bad_request(self, where: str) -> None:
        method = ContractMethod()
        handler = make_server(method).charge(amount="1")
        issued = await issue(handler)
        [value] = authorization(issued).values()
        headers = (
            {"Authorization": f"{value}, {value}"}
            if where == "comma-joined"
            else {"Authorization": value, "Payment-Authorization": value}
        )
        async with http(app({"/paid": handler})) as c:
            response = await c.get("/paid", headers=headers)
        assert response.status_code == 400
        assert response.json()["type"] == f"{PROBLEMS}/bad-request"
        assert "www-authenticate" not in response.headers
        assert method.settled == []


async def _rejected(handler: Any, challenge: Challenge) -> tuple[int, str, list[Challenge]]:
    result = await handler(engine_request(authorization(challenge)))
    body = json.loads(result.challenge.body)
    return result.status, body["type"], offers(result)


class TestProblemTypes:
    async def test_expired(self) -> None:
        handler = make_server(ContractMethod()).charge(amount="1")
        issued = await issue(handler)
        status, problem, retry = await _rejected(handler, _rebind(issued, expires=_past()))
        assert (status, problem) == (402, f"{PROBLEMS}/payment-expired")
        assert retry and retry[0].id != issued.id

    async def test_unknown_challenge(self) -> None:
        handler = make_server(ContractMethod()).charge(amount="1")
        issued = await issue(handler)
        status, problem, retry = await _rejected(handler, replace(issued, id="forged"))
        assert (status, problem) == (402, f"{PROBLEMS}/invalid-challenge")
        assert retry

    async def test_body_digest_mismatch(self) -> None:
        server = make_server(ContractMethod())
        issued = await issue(server.charge(amount="1", body=b"one"))
        status, problem, retry = await _rejected(server.charge(amount="1", body=b"two"), issued)
        assert (status, problem) == (402, f"{PROBLEMS}/invalid-challenge")
        assert retry

    async def test_binding_is_checked_before_expiry(self) -> None:
        handler = make_server(ContractMethod()).charge(amount="1")
        issued = await issue(handler)
        stale = _rebind(issued, realm="other.example.com", expires=_past())
        _, problem, _ = await _rejected(handler, stale)
        assert problem == f"{PROBLEMS}/invalid-challenge"


class TestMethodGrammar:
    @pytest.mark.parametrize("method", ["tempo2", "tempo-v2", "vendor:pay", "Tempo"])
    def test_parse_rejects_non_lowercase_alpha_methods(self, method: str) -> None:
        with pytest.raises(ParseError):
            Challenge.from_www_authenticate(
                f'Payment id="x", realm="r", method="{method}", intent="charge", '
                'request="eyJhbW91bnQiOiIxIn0"'
            )

    def test_format_rejects_non_lowercase_alpha_methods(self) -> None:
        challenge = Challenge(id="x", realm="r", method="tempo-v2", intent="charge", request={})
        with pytest.raises(ValueError, match="payment method"):
            challenge.to_www_authenticate("r")


async def test_client_does_not_pay_again_after_invalid_challenge() -> None:
    """A paid retry answered with invalid-challenge (such as a replay) is final."""
    created: list[Any] = []
    client, transport = paying(
        app({"/paid": make_server(ContractMethod()).charge(amount="1")}),
        ContractMethod(token="replayed"),
    )
    transport.on_credential_created(created.append)
    async with client:
        response = await client.get("/paid")
    assert response.status_code == 402
    assert response.json()["type"] == f"{PROBLEMS}/invalid-challenge"
    assert len(created) == 1


def test_tempo_split_amounts_are_emitted_without_leading_zeros() -> None:
    from mpp.methods.tempo import PATH_USD
    from mpp.methods.tempo.schemas import ChargeInput, Split

    recipient = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
    split = Split(amount="000100", recipient="0x" + "11" * 20)
    wire = ChargeInput(amount="1", currency=PATH_USD, recipient=recipient, splits=[split])
    assert wire.model_dump()["methodDetails"]["splits"][0]["amount"] == "100"


class TestMethodIdAtConfiguration:
    @pytest.mark.parametrize("name", ["stripe-pi", "tempo2", "Tempo"])
    def test_mpp_rejects_invalid_method_ids_at_startup(self, name: str) -> None:
        with pytest.raises(ValueError, match="Invalid payment method id"):
            make_server(ContractMethod(name=name))


def test_hash_credentials_require_a_bound_memo() -> None:
    """Push (hash) credentials need the challenge-bound memo; pull transactions do not."""
    from mpp.errors import VerificationError
    from mpp.methods.tempo.intents import ChargeIntent

    intent = ChargeIntent(rpc_url="https://rpc.test")
    intent._assert_challenge_bound_memo([], challenge_id="c", realm="r")
    with pytest.raises(VerificationError, match="memo is not bound"):
        intent._assert_challenge_bound_memo([], challenge_id="c", realm="r", require=True)


async def test_mixed_case_problem_media_type_is_still_final() -> None:
    """Media types are case-insensitive: a mixed-case invalid-challenge stays final."""
    from mpp.client.transport import _is_invalid_challenge

    body = json.dumps({"type": f"{PROBLEMS}/invalid-challenge"}).encode()
    for content_type in ("application/Problem+JSON", "APPLICATION/PROBLEM+JSON; charset=utf-8"):
        response = httpx.Response(402, headers={"content-type": content_type}, content=body)
        assert await _is_invalid_challenge(response)
    response = httpx.Response(402, headers={"content-type": "application/json"}, content=body)
    assert not await _is_invalid_challenge(response)


def test_attribution_memo_rules_for_pull_and_push() -> None:
    """Pull accepts plain and non-attribution memos; any other attribution memo fails."""
    from mpp.errors import VerificationError
    from mpp.methods.tempo._attribution import encode as encode_attribution
    from mpp.methods.tempo.intents import ChargeIntent, MatchedTransferLog

    intent = ChargeIntent(rpc_url="https://rpc.test")

    def legs(memo: str | None) -> list[MatchedTransferLog]:
        if memo is None:
            return [MatchedTransferLog(kind="transfer")]
        return [MatchedTransferLog(kind="memo", memo=memo)]

    bound = encode_attribution(challenge_id="c", server_id="r")
    other_challenge = encode_attribution(challenge_id="other", server_id="r")
    other_realm = encode_attribution(challenge_id="c", server_id="elsewhere")
    for memo in (None, "0x" + "ab" * 32, bound):
        intent._assert_challenge_bound_memo(legs(memo), challenge_id="c", realm="r")
    # Another realm's memo could later be redeemed there as a hash credential.
    for memo in (other_challenge, other_realm):
        with pytest.raises(VerificationError, match="memo is not bound"):
            intent._assert_challenge_bound_memo(legs(memo), challenge_id="c", realm="r")
    intent._assert_challenge_bound_memo(legs(bound), challenge_id="c", realm="r", require=True)
    for memo in (None, "0x" + "ab" * 32, other_realm, other_challenge):
        with pytest.raises(VerificationError, match="memo is not bound"):
            intent._assert_challenge_bound_memo(
                legs(memo), challenge_id="c", realm="r", require=True
            )
