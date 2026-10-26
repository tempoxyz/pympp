"""Property-based tests for the server engine, challenge binding and units.

Mirrors the HMAC binding rules in mppx src/Challenge.ts and the route matching in
src/server/Mppx.ts: for generated route configurations, the engine accepts only
the unmodified credential issued for that route and answers every altered,
re-signed, expired or cross-route credential with a 402, never an exception;
challenge IDs are deterministic and change with every bound field; amounts
convert to base units exactly; and a composed route settles a credential on
exactly the offer that issued it.
"""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from mpp import Challenge, Credential, Receipt, generate_challenge_id
from mpp._units import parse_units, transform_units
from mpp.server import Mpp, PaymentRequired, PaymentVerified, compose
from tests import challenge, challenges, http_request, server_method

REALM = "api.example.com"
SECRET = "property-secret"

# Small budgets keep this file fast; no example database is written to the repository.
ENGINE = settings(max_examples=25, deadline=None, database=None)
FAST = settings(max_examples=100, deadline=None, database=None)


# Strategies -----------------------------------------------------------------

addresses = st.binary(min_size=20, max_size=20).map(lambda value: "0x" + value.hex())
amounts = st.decimals(min_value=0, max_value=10**9, places=6, allow_nan=False).map(
    lambda value: format(value, "f")
)
meta_values = st.dictionaries(
    st.text(st.characters(codec="ascii", categories=["L", "N"]), min_size=1, max_size=8),
    st.text(max_size=12),
    max_size=3,
)
lifetimes = st.none() | st.integers(min_value=60, max_value=7 * 24 * 3600)
route_configs = st.fixed_dictionaries(
    {
        "amount": amounts,
        "currency": addresses,
        "recipient": addresses,
        "meta": st.none() | meta_values,
        "lifetime": lifetimes,
    }
)
# Pipe-free: the HMAC input joins fields with "|" (mppx Challenge.ts), so a field
# boundary shifted across "|" maps to the same input by design.
pipe_free = st.text(max_size=16).filter(lambda value: "|" not in value)
# JCS (RFC 8785) only encodes integers that are exact as JSON doubles.
json_ints = st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
request_dicts = st.dictionaries(st.text(max_size=8), st.text(max_size=8) | json_ints, max_size=4)


def _expires(seconds: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _options(config: dict[str, Any]) -> dict[str, Any]:
    options = {key: config[key] for key in ("amount", "currency", "recipient", "meta")}
    if config["lifetime"] is not None:
        options["expires"] = _expires(config["lifetime"])
    return options


def _b64(value: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


class Route:
    """One configured engine route whose verify hook counts settlements."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.settled: list[dict[str, Any]] = []
        self.server = Mpp(
            methods=server_method(verify=self._verify), realm=REALM, secret_key=SECRET
        )
        self.handler = self.server.charge(**_options(config))

    async def _verify(self, context: Any) -> Receipt:
        self.settled.append(context.request)
        return Receipt(
            status="success", timestamp=datetime.now(UTC), reference="ref", method="tempo"
        )

    async def issue(self) -> Challenge:
        return challenge(await self.handler(http_request()))

    async def pay(self, credential: Credential | str) -> Any:
        value = credential if isinstance(credential, str) else credential.to_authorization()
        return await self.handler(http_request(value))


def _resign(issued: Challenge, secret: str = SECRET, **changes: Any) -> Challenge:
    """Re-issue a challenge with a valid HMAC over changed fields."""
    fields = {
        "realm": issued.realm,
        "method": issued.method,
        "intent": issued.intent,
        "request": issued.request,
        "expires": issued.expires,
        "digest": issued.digest,
        "meta": issued.opaque,
        **changes,
    }
    return Challenge.create(secret_key=secret, **fields)


def _mutations(issued: Challenge, other_meta: dict[str, str]) -> dict[str, Credential]:
    """Credentials a client could derive from a valid one; none may pay the route."""
    echo = issued.to_echo()
    payload = {"token": "valid"}
    request = dict(issued.request)
    nonce = (issued.opaque or {})["_mpp_nonce"]

    def echoed(**changes: Any) -> Credential:
        return Credential(challenge=replace(echo, **changes), payload=payload)

    def signed(**changes: Any) -> Credential:
        return Credential(challenge=_resign(issued, **changes).to_echo(), payload=payload)

    tampered = {**request, "amount": request["amount"] + "1"}
    other_scope = {**request, "_mppx_scope": {"http_method": "GET", "resource": "/other"}}
    return {
        # Any echoed field changed after issuance breaks the HMAC.
        "id": echoed(id=echo.id[:-1] + ("A" if echo.id[-1] != "A" else "B")),
        "realm": echoed(realm=echo.realm + "x"),
        "method": echoed(method="stripe"),
        "intent": echoed(intent="session"),
        "request": echoed(request=_b64(tampered)),
        "expires": echoed(expires=_expires(10 * 24 * 3600)),
        "digest": echoed(digest="sha-256=" + base64.b64encode(b"x" * 32).decode()),
        "opaque": echoed(opaque=_b64({**other_meta, "_mpp_nonce": nonce})),
        "opaque-removed": echoed(opaque=None),
        "header": echoed(header="Payment-Authorization"),
        # A valid HMAC over different terms still has to match the route.
        "wrong-secret": signed(secret="another-secret"),
        "signed-request": signed(request=tampered),
        "signed-scope": signed(request=other_scope),
        "signed-meta": signed(meta={**other_meta, "_mpp_nonce": nonce}),
        "signed-realm": signed(realm="other.example.com"),
        "signed-intent": signed(intent="session"),
        "signed-digest": signed(digest="sha-256=" + base64.b64encode(b"x" * 32).decode()),
        "expired": signed(expires=_expires(-1)),
        "missing-expires": signed(expires=None),
    }


def _assert_rejected(route: Route, result: Any, label: str) -> None:
    assert isinstance(result, PaymentRequired), label
    assert result.status == 402, label
    assert json.loads(result.challenge.body or b"")["status"] == 402, label
    assert route.settled == [], label


class TestEngineAcceptsOnlyTheIssuedCredential:
    @ENGINE
    @given(config=route_configs, other_meta=meta_values.filter(bool))
    def test_mutations_are_rejected(self, config: dict[str, Any], other_meta: dict) -> None:
        route = Route(config)
        meta = config["meta"] or None
        assume(other_meta != (meta or {}))

        async def run() -> None:
            issued = await route.issue()
            for label, credential in _mutations(issued, other_meta).items():
                _assert_rejected(route, await route.pay(credential), label)
            paid = await route.pay(Credential(challenge=issued.to_echo(), payload={"t": 1}))
            assert isinstance(paid, PaymentVerified)
            assert route.settled == [{k: config[k] for k in ("amount", "currency", "recipient")}]

        asyncio.run(run())

    @ENGINE
    @given(config=route_configs, other=route_configs)
    def test_credentials_do_not_pay_other_routes(
        self, config: dict[str, Any], other: dict[str, Any]
    ) -> None:
        def terms(value: dict[str, Any]) -> tuple:
            return (value["amount"], value["currency"], value["recipient"], value["meta"] or None)

        assume(terms(config) != terms(other))
        issuer, target = Route(config), Route(other)

        async def run() -> None:
            issued = await issuer.issue()
            credential = Credential(challenge=issued.to_echo(), payload={"t": 1})
            _assert_rejected(target, await target.pay(credential), "cross-route")

        asyncio.run(run())

    @ENGINE
    @given(
        config=route_configs,
        field=st.sampled_from(["id", "realm", "request", "expires", "digest", "opaque"]),
        value=st.text(st.characters(codec="ascii", exclude_categories=["Cc"]), max_size=40),
    )
    def test_arbitrary_echo_values_are_rejected(
        self, config: dict[str, Any], field: str, value: str
    ) -> None:
        route = Route(config)

        async def run() -> None:
            issued = await route.issue()
            echo = issued.to_echo()
            # An empty optional field is omitted on the wire, like an absent one.
            assume((getattr(echo, field) or "") != value)
            credential = Credential(challenge=replace(echo, **{field: value}), payload={"t": 1})
            _assert_rejected(route, await route.pay(credential), field)

        asyncio.run(run())

    @ENGINE
    @given(config=route_configs, authorization=st.text(st.characters(codec="latin-1")))
    def test_arbitrary_authorization_is_rejected(
        self, config: dict[str, Any], authorization: str
    ) -> None:
        route = Route(config)

        async def run() -> None:
            for value in (authorization, f"Payment {authorization}"):
                result = await route.pay(value)
                assert isinstance(result, PaymentRequired)
                assert result.status == 402
            assert route.settled == []

        asyncio.run(run())


class TestChallengeId:
    fields = st.fixed_dictionaries(
        {
            "realm": pipe_free,
            "method": pipe_free,
            "intent": pipe_free,
            "request": request_dicts,
            "expires": st.none() | pipe_free.filter(bool),
            "digest": st.none() | pipe_free.filter(bool),
            "opaque": st.none() | st.dictionaries(st.text(max_size=6), st.text(max_size=6)),
            "header": st.sampled_from([None, "Payment-Authorization"]),
        }
    )

    @FAST
    @given(fields=fields)
    def test_deterministic_and_order_independent(self, fields: dict[str, Any]) -> None:
        first = generate_challenge_id(secret_key=SECRET, **fields)
        reordered = {
            **fields,
            "request": dict(reversed(list(fields["request"].items()))),
            "opaque": None
            if fields["opaque"] is None
            else dict(reversed(list(fields["opaque"].items()))),
        }
        assert generate_challenge_id(secret_key=SECRET, **reordered) == first
        assert generate_challenge_id(secret_key=SECRET, **fields) == first

    @FAST
    @given(fields=fields, data=st.data())
    def test_every_bound_field_changes_the_id(self, fields: dict[str, Any], data: Any) -> None:
        original = generate_challenge_id(secret_key=SECRET, **fields)
        name = data.draw(st.sampled_from([*fields, "secret_key"]))
        value: Any = fields.get(name)
        if name == "secret_key":
            assert generate_challenge_id(secret_key=SECRET + "x", **fields) != original
            return
        if name == "request":
            changed: Any = {**value, "\x00mutated": data.draw(st.text(max_size=4))}
        elif name == "opaque":
            changed = {**(value or {}), "\x00mutated": data.draw(st.text(max_size=4))}
        elif name == "header":
            changed = None if value else "Payment-Authorization"
        else:
            changed = (value or "") + data.draw(pipe_free.filter(bool))
        assert generate_challenge_id(secret_key=SECRET, **{**fields, name: changed}) != original


class TestUnits:
    @FAST
    @given(
        base_units=st.integers(min_value=0, max_value=10**27),
        decimals=st.integers(min_value=0, max_value=18),
        padding=st.integers(min_value=0, max_value=4),
    )
    def test_decimal_strings_round_trip(self, base_units: int, decimals: int, padding: int) -> None:
        whole, fraction = divmod(base_units, 10**decimals)
        text = str(whole)
        if decimals:
            text += "." + str(fraction).zfill(decimals) + "0" * padding
        assert parse_units(text, decimals) == base_units
        assert parse_units(f" 0{text} ", decimals) == base_units
        assert Decimal(text).scaleb(decimals) == base_units

    @FAST
    @given(
        base_units=st.integers(min_value=1, max_value=10**20),
        decimals=st.integers(min_value=0, max_value=18),
    )
    def test_precision_beyond_decimals_is_rejected(self, base_units: int, decimals: int) -> None:
        text = format(Decimal(base_units).scaleb(-decimals - 1), "f")
        assume(base_units % 10)
        with pytest.raises(ValueError, match="fractional base units"):
            parse_units(text, decimals)

    @FAST
    @given(
        amount=st.integers(min_value=0, max_value=10**24),
        deposit=st.none() | st.integers(min_value=0, max_value=10**24),
        decimals=st.integers(min_value=0, max_value=18),
        extra=st.dictionaries(st.sampled_from(["currency", "recipient"]), st.text()),
    )
    def test_transform_units_converts_amounts_without_mutating(
        self, amount: int, deposit: int | None, decimals: int, extra: dict
    ) -> None:
        def text(value: int) -> str:
            return format(Decimal(value).scaleb(-decimals), "f")

        request = {**extra, "amount": text(amount), "decimals": decimals}
        if deposit is not None:
            request["suggestedDeposit"] = text(deposit)
        before = dict(request)

        result = transform_units(request)

        assert request == before
        assert result == {
            **extra,
            "amount": str(amount),
            **({"suggestedDeposit": str(deposit)} if deposit is not None else {}),
        }

    @pytest.mark.xfail(
        strict=True,
        reason="parse_units multiplies in Decimal's default 28-digit context, so "
        "amounts with more significant digits are silently rounded (viem parseUnits is exact)",
    )
    @pytest.mark.parametrize(
        ("value", "decimals", "expected"),
        [
            (str(2**256 - 1), 0, 2**256 - 1),
            ("12345678901.123456789012345678", 18, 12345678901123456789012345678),
        ],
        ids=["uint256-max", "29-digits-18-decimals"],
    )
    def test_amounts_beyond_28_significant_digits_are_exact(
        self, value: str, decimals: int, expected: int
    ) -> None:
        assert parse_units(value, decimals) == expected


class TestComposeSelectsOneOffer:
    @ENGINE
    @given(
        configs=st.lists(
            route_configs,
            min_size=2,
            max_size=5,
            unique_by=lambda c: (
                c["amount"],
                c["currency"],
                c["recipient"],
                str(c["meta"] or None),
            ),
        ),
        data=st.data(),
    )
    def test_credential_settles_on_its_issuing_offer(self, configs: list, data: Any) -> None:
        settled: list[dict[str, Any]] = []

        async def verify(context: Any) -> Receipt:
            settled.append(context.request)
            return Receipt(
                status="success", timestamp=datetime.now(UTC), reference="ref", method="tempo"
            )

        server = Mpp(methods=server_method(verify=verify), realm=REALM, secret_key=SECRET)
        handler = compose(*(server.charge(**_options(config)) for config in configs))
        chosen = data.draw(st.integers(min_value=0, max_value=len(configs) - 1))

        async def run() -> None:
            issued = challenges(await handler(http_request()))
            assert len(issued) == len(configs)
            credential = Credential(challenge=issued[chosen].to_echo(), payload={"t": 1})

            tampered = Credential(
                challenge=replace(credential.challenge, realm="x"), payload={"t": 1}
            )
            rejected = await handler(http_request(tampered.to_authorization()))
            assert isinstance(rejected, PaymentRequired) and rejected.status == 402
            assert settled == []

            paid = await handler(http_request(credential.to_authorization()))
            assert isinstance(paid, PaymentVerified)

        asyncio.run(run())
        terms = configs[chosen]
        assert settled == [{k: terms[k] for k in ("amount", "currency", "recipient")}]
