"""Property-based and edge-case tests for Payment header parsing.

Mirrors mppx src/Challenge.fuzz.test.ts and the multi-challenge cases in
src/Challenge.test.ts: parsers fail only with ParseError on hostile input, and
values survive a serialize/parse roundtrip.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp._canonical import canonical_b64url
from mpp._parsing import (
    ParseError,
    parse_authorization,
    parse_payment_receipt,
    parse_www_authenticate,
)
from mpp.client.transport import _payment_challenges

# Small budgets keep this file fast; no example database is written to the repository.
FUZZ = settings(max_examples=200, deadline=None, database=None)
SLOW_FUZZ = settings(max_examples=100, deadline=None, database=None)
LIST_FUZZ = settings(max_examples=50, deadline=None, database=None)

PARSERS = (parse_www_authenticate, parse_authorization, parse_payment_receipt)


def b64(value: Any) -> str:
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def assert_only_parse_error(parse: Any, header: str) -> None:
    try:
        parse(header)
    except ParseError:
        pass


# Strategies -----------------------------------------------------------------

header_text = st.text().filter(lambda value: "\r" not in value and "\n" not in value)
nonempty_header_text = header_text.filter(bool)
scheme_like_text = st.tuples(
    header_text,
    st.sampled_from(["Payment ", "payment ", "PAYMENT  ", 'Payment id="x", ']),
    header_text,
).map("".join)
quoted_field = st.one_of(nonempty_header_text, scheme_like_text)
method_ids = st.from_regex(r"\A[a-z][a-z0-9:_-]{0,15}\Z")
json_scalars = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-(2**63), max_value=2**63), st.text()
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=12,
)
json_objects = st.dictionaries(st.text(), json_values, max_size=5)
request_dicts = st.dictionaries(
    st.from_regex(r"\A[a-zA-Z_][a-zA-Z0-9_]{0,10}\Z"),
    st.one_of(st.text(), st.integers().map(str), st.booleans().map(str)),
    max_size=5,
)
optional_text = st.none() | st.text(min_size=1)

adversarial_headers = st.one_of(
    st.text(),
    st.text().map(lambda value: f"Payment {value}"),
    st.text().map(lambda value: f'Payment id="{value}'),
    st.text().map(lambda value: f'Payment id="\\{value}"'),
    st.integers(min_value=0, max_value=100).map(lambda count: "Payment " + ",,,," * count),
    st.text(alphabet="abc", min_size=500, max_size=2000).map(lambda key: f'Payment {key}="v"'),
    st.binary(min_size=1, max_size=200).map(lambda raw: f'Payment id="{raw.decode("latin-1")}"'),
    json_values.map(lambda value: f"Payment {b64(value)}"),
    json_values.map(b64),
    json_values.map(
        lambda value: f'Payment id="a", realm="r", method="m", intent="i", request="{b64(value)}"'
    ),
)


# Robustness -----------------------------------------------------------------


class TestParsersOnlyRaiseParseError:
    @FUZZ
    @given(header=adversarial_headers)
    def test_adversarial_headers(self, header: str) -> None:
        for parse in PARSERS:
            assert_only_parse_error(parse, header)

    @SLOW_FUZZ
    @given(
        challenge=st.dictionaries(
            st.sampled_from(
                [
                    "id",
                    "realm",
                    "method",
                    "intent",
                    "request",
                    "expires",
                    "digest",
                    "opaque",
                    "header",
                    "description",
                ]
            ),
            json_values,
        ),
        payload=json_values,
        source=json_values,
    )
    def test_structured_credentials(self, challenge: Any, payload: Any, source: Any) -> None:
        """Valid base64 JSON with wrongly typed fields fails only with ParseError."""
        header = f"Payment {b64({'challenge': challenge, 'payload': payload, 'source': source})}"
        assert_only_parse_error(parse_authorization, header)

    @FUZZ
    @given(
        receipt=st.fixed_dictionaries(
            {},
            optional={
                "status": json_values | st.just("success"),
                "timestamp": json_values | st.just("2026-01-01T00:00:00Z"),
                "reference": json_values,
                "method": json_values | method_ids,
                "externalId": json_values,
                "extra": json_values,
            },
        )
    )
    def test_structured_receipts(self, receipt: dict[str, Any]) -> None:
        assert_only_parse_error(parse_payment_receipt, b64(receipt))

    @FUZZ
    @given(value=st.text())
    def test_challenge_splitting_never_raises(self, value: str) -> None:
        for field in _payment_challenges(value):
            assert field.lower().startswith("payment")
            assert_only_parse_error(parse_www_authenticate, field)

    def test_deeply_nested_credential_json(self) -> None:
        depth = 20_000
        nested = b'{"a":' + b"[" * depth + b"]" * depth + b"}"
        with pytest.raises(ParseError):
            parse_authorization(f"Payment {b64(nested)}")

    def test_oversized_values_are_rejected(self) -> None:
        with pytest.raises(ParseError, match="exceeds maximum size"):
            parse_authorization("Payment " + "A" * (64 * 1024 + 1))
        with pytest.raises(ParseError, match="exceeds maximum size"):
            parse_payment_receipt("A" * (16 * 1024 + 1))


# Roundtrips -----------------------------------------------------------------


class TestRoundtrip:
    @SLOW_FUZZ
    @given(
        id_=quoted_field,
        realm=quoted_field,
        method=method_ids,
        intent=quoted_field,
        request=request_dicts,
        description=st.none() | quoted_field,
        expires=st.none() | quoted_field,
        digest=st.none() | quoted_field,
        opaque=st.none() | st.dictionaries(st.text(), st.text(), max_size=3),
        header=st.sampled_from([None, "Payment-Authorization", "X-Pay"]),
    )
    def test_challenge(
        self,
        id_: str,
        realm: str,
        method: str,
        intent: str,
        request: dict[str, Any],
        description: str | None,
        expires: str | None,
        digest: str | None,
        opaque: dict[str, str] | None,
        header: str | None,
    ) -> None:
        challenge = Challenge(
            id=id_,
            method=method,
            intent=intent,
            request=request,
            description=description,
            expires=expires,
            digest=digest,
            opaque=opaque,
            header=header,
        )
        parsed = parse_www_authenticate(challenge.to_www_authenticate(realm))

        assert parsed == Challenge(
            id=id_,
            method=method,
            intent=intent,
            request=request,
            realm=realm,
            request_b64=canonical_b64url(request),
            description=description,
            expires=expires,
            digest=digest,
            opaque=opaque,
            header=header,
        )

    @SLOW_FUZZ
    @given(
        echo=st.builds(
            ChallengeEcho,
            id=st.text(),
            realm=st.text(),
            method=method_ids,
            intent=st.text(),
            request=st.text(),
            expires=optional_text,
            digest=optional_text,
            opaque=optional_text,
            header=st.sampled_from([None, "Payment-Authorization"]),
            description=st.none()
            | st.text(
                st.characters(blacklist_categories=["Cs", "Cc"]) | st.sampled_from(["\t", "\\"])
            ),
        ),
        payload=json_objects,
        source=optional_text,
    )
    def test_credential(
        self, echo: ChallengeEcho, payload: dict[str, Any], source: str | None
    ) -> None:
        credential = Credential(challenge=echo, payload=payload, source=source)

        assert parse_authorization(credential.to_authorization()) == credential

    @SLOW_FUZZ
    @given(
        receipt=st.builds(
            Receipt,
            status=st.just("success"),
            timestamp=st.datetimes(timezones=st.just(UTC)),
            reference=st.text(),
            method=method_ids,
            external_id=optional_text,
            subscription_id=optional_text,
            funding_currency=optional_text,
            extra=st.none() | json_objects.filter(bool),
            extensions=st.none()
            | st.dictionaries(st.text().map(lambda key: f"x-{key}"), json_values, min_size=1),
        )
    )
    def test_receipt(self, receipt: Receipt) -> None:
        assert parse_payment_receipt(receipt.to_payment_receipt()) == receipt


# Multiple challenges ----------------------------------------------------------


def quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


decoy_schemes = st.tuples(st.sampled_from(["Basic", "Bearer", "Digest"]), scheme_like_text).map(
    lambda pair: f"{pair[0]} realm={quote(pair[1])}"
)
challenges_for_list = st.builds(
    Challenge,
    id=quoted_field,
    method=method_ids,
    intent=quoted_field,
    request=request_dicts,
    description=st.none() | quoted_field,
    opaque=st.none() | st.dictionaries(st.text(), st.text(), min_size=1, max_size=2),
)


def parse_list(value: str) -> list[Challenge]:
    """Split and parse a WWW-Authenticate value like the client transport does."""
    return [parse_www_authenticate(field) for field in _payment_challenges(value)]


class TestChallengeList:
    @LIST_FUZZ
    @given(
        entries=st.lists(
            st.tuples(
                challenges_for_list,
                quoted_field,
                st.none() | decoy_schemes,
                st.sampled_from(["Payment ", "payment ", "PAYMENT  "]),
            ),
            min_size=1,
            max_size=4,
        ),
        trailing=st.none() | decoy_schemes,
    )
    def test_finds_only_payment_challenges_among_decoys(
        self,
        entries: list[tuple[Challenge, str, str | None, str]],
        trailing: str | None,
    ) -> None:
        parts: list[str] = []
        for challenge, realm, decoy, scheme in entries:
            if decoy is not None:
                parts.append(decoy)
            serialized = challenge.to_www_authenticate(realm)
            parts.append(scheme + serialized.removeprefix("Payment "))
        if trailing is not None:
            parts.append(trailing)

        parsed = parse_list(", ".join(parts))

        assert [(c.id, c.realm, c.method, c.intent) for c in parsed] == [
            (challenge.id, realm, challenge.method, challenge.intent)
            for challenge, realm, _decoy, _scheme in entries
        ]
        for result, (challenge, _realm, _decoy, _scheme) in zip(parsed, entries, strict=True):
            assert result.request == challenge.request
            assert result.description == challenge.description
            assert result.opaque == challenge.opaque

    second = Challenge(
        id="second", method="tempo", intent="charge", request={"amount": "1000000"}
    ).to_www_authenticate("api.example.com")

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("description", "Agentcash card payment test"),
            ("description", "Payment at the start"),
            ("description", 'Use "Payment now", then retry \\'),
            ("description", "comma, Payment fake challenge"),
            ("id", "id with Payment text"),
            ("intent", "payment plan"),
        ],
    )
    def test_ignores_scheme_like_text_in_parameters(self, field: str, value: str) -> None:
        values: dict[str, Any] = {"id": "first", "intent": "charge", "description": None}
        values[field] = value
        first = Challenge(method="stripe", request={"amount": "50"}, **values)

        parsed = parse_list(f"{first.to_www_authenticate('example.com')}, {self.second}")

        assert [c.id for c in parsed] == [values["id"], "second"]
        assert getattr(parsed[0], field) == value

    def test_ignores_scheme_like_text_in_realm(self) -> None:
        first = Challenge(id="first", method="stripe", intent="charge", request={})

        parsed = parse_list(f"{first.to_www_authenticate('Payment realm')}, {self.second}")

        assert [(c.id, c.realm) for c in parsed] == [
            ("first", "Payment realm"),
            ("second", "api.example.com"),
        ]

    def test_finds_case_insensitive_schemes_among_other_schemes(self) -> None:
        first = Challenge(id="first", method="stripe", intent="charge", request={})
        header = (
            f'Bearer error_description="use Payment challenge", '
            f"{first.to_www_authenticate('example.com')}, "
            f'Digest realm="fallback Payment realm", '
            f"{self.second.replace('Payment ', 'pAyMeNt ', 1)}"
        )

        assert [c.id for c in parse_list(header)] == ["first", "second"]

    def test_whitespace_around_equals_stays_in_its_challenge(self) -> None:
        header = (
            'Payment id = "first", realm = "example.com", method = "stripe", '
            f'intent = "charge", request = "e30", {self.second}'
        )

        parsed = parse_list(header)

        assert [(c.id, c.realm, c.method) for c in parsed] == [
            ("first", "example.com", "stripe"),
            ("second", "api.example.com", "tempo"),
        ]

    def test_quoted_payment_text_is_not_a_challenge(self) -> None:
        assert _payment_challenges('Bearer error_description="use Payment challenge"') == []


# Uncovered branches -------------------------------------------------------------

VALID_PARAMS = {
    "id": "abc",
    "realm": "api.example.com",
    "method": "tempo",
    "intent": "charge",
    "request": "e30",
}


def www_authenticate(**params: str | None) -> str:
    values = {**VALID_PARAMS, **params}
    return "Payment " + ", ".join(
        f'{key}="{value}"' for key, value in values.items() if value is not None
    )


class TestEdgeCases:
    @pytest.mark.parametrize("field", ["intent", "request"])
    @pytest.mark.parametrize("value", [None, ""])
    def test_challenge_requires_intent_and_request(self, field: str, value: str | None) -> None:
        with pytest.raises(ParseError, match=f"Missing '{field}' field"):
            parse_www_authenticate(www_authenticate(**{field: value}))

    def test_challenge_parses_with_every_required_field(self) -> None:
        parsed = parse_www_authenticate(www_authenticate())
        assert (parsed.intent, parsed.request) == ("charge", {})

    def test_challenge_rejects_invalid_credential_header_name(self) -> None:
        with pytest.raises(ParseError, match="Invalid HTTP header name"):
            parse_www_authenticate(www_authenticate(header="Bad Header"))

    def test_credential_rejects_invalid_credential_header_name(self) -> None:
        challenge = {**VALID_PARAMS, "header": "Bad Header"}
        header = f"Payment {b64({'challenge': challenge, 'payload': {}})}"

        with pytest.raises(ParseError, match="Invalid HTTP header name"):
            parse_authorization(header)

    def test_credential_accepts_valid_credential_header_name(self) -> None:
        challenge = {**VALID_PARAMS, "header": "Payment-Authorization"}
        header = f"Payment {b64({'challenge': challenge, 'payload': {}})}"

        assert parse_authorization(header).challenge.header == "Payment-Authorization"

    @pytest.mark.parametrize("status", ["failed", "pending", "SUCCESS", "", None, True])
    def test_receipt_rejects_non_success_status(self, status: Any) -> None:
        receipt = {
            "status": status,
            "timestamp": "2026-01-01T00:00:00Z",
            "reference": "0xabc",
            "method": "tempo",
        }

        with pytest.raises(ParseError, match="Invalid receipt status"):
            parse_payment_receipt(b64(receipt))

    @pytest.mark.parametrize(
        ("description", "wire"),
        [
            ("a\\b", 'description="a\\\\b"'),
            ("trailing\\", 'description="trailing\\\\"'),
            ('\\"', 'description="\\\\\\""'),
            ("\\u0041", 'description="\\\\u0041"'),
        ],
    )
    def test_backslashes_are_escaped_on_the_wire(self, description: str, wire: str) -> None:
        challenge = Challenge(
            id="abc", method="tempo", intent="charge", request={}, description=description
        )
        header = challenge.to_www_authenticate("api.example.com")

        assert wire in header
        assert parse_www_authenticate(header).description == description
