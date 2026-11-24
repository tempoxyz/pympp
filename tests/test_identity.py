"""The identity core: outcomes, precedence, any_of, from_fn, routes, requirements, provers."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from mpp import identity
from mpp.identity import (
    AnyOfValue,
    PaymentCheck,
    Prover,
    Rejected,
    RejectionError,
    Requirement,
    Results,
    Route,
    Valid,
    Verification,
    Verifier,
    any_of,
    from_fn,
)
from mpp.identity import _decide as decide
from mpp.identity import _requirements as requirements
from mpp.server._identity import IdentityContext
from tests import http_request


def fixed(
    outcome: Verification[Any], calls: list[str] | None = None, name: str = ""
) -> Verifier[Any]:
    async def verify(request: Any) -> Verification[Any]:
        del request
        if calls is not None:
            calls.append(name)
        return outcome

    return Verifier(verify=verify)


async def check_outcome(_: Any) -> Verification[Any]:
    return Valid(None)


# --- Outcomes and precedence ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code", "reason"),
    [
        ("missing", 401, "Identity verification is required."),
        ("invalid", 401, "The identity proof is invalid."),
        ("forbidden", 403, "This identity is not allowed."),
        ("unavailable", 503, "Identity verification is unavailable."),
    ],
)
def test_each_status_has_a_fixed_code_and_default_reason(
    status: Any, code: int, reason: str
) -> None:
    rejected = Rejected(status)
    assert (rejected.code, rejected.reason) == (code, reason)
    assert identity.STATUS_CODES[status] == code


def test_unknown_status_fails_closed_to_invalid() -> None:
    rejected = Rejected("teapot", "ignored")  # pyright: ignore[reportArgumentType]
    assert rejected.status == "invalid"
    assert rejected.code == 401
    assert rejected.reason == "The identity verifier returned an unknown status."


def test_rejected_headers_are_normalized_to_immutable_pairs() -> None:
    from_mapping = identity.missing("x", {"WWW-Authenticate": "Bearer"})
    from_pairs = identity.missing("x", [("WWW-Authenticate", "Bearer")])
    assert from_mapping == from_pairs
    assert from_mapping.headers == (("WWW-Authenticate", "Bearer"),)


@pytest.mark.parametrize(
    ("statuses", "winner"),
    [
        (["missing"], "missing"),
        (["missing", "invalid"], "invalid"),
        (["invalid", "unavailable"], "unavailable"),
        (["unavailable", "forbidden", "missing"], "forbidden"),
        (["missing", "missing"], "missing"),
    ],
)
def test_decide_takes_the_highest_precedence(statuses: list[Any], winner: str) -> None:
    assert decide([Rejected(status) for status in statuses]).status == winner


def test_decide_keeps_the_first_reason_on_ties_and_every_header() -> None:
    decision = decide(
        [
            identity.invalid("first", {"A": "1"}),
            identity.missing("ignored", {"B": "2"}),
            identity.invalid("second", {"C": "3"}),
        ]
    )
    assert decision == Rejected("invalid", "first", (("A", "1"), ("B", "2"), ("C", "3")))


def test_decide_needs_a_rejection() -> None:
    with pytest.raises(ValueError, match="at least one"):
        decide([])


# --- any_of ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ([Valid("a"), Rejected("missing")], Valid(AnyOfValue(0, "a"))),
        ([Rejected("missing"), Valid("b")], Valid(AnyOfValue(1, "b"))),
        ([Valid("a"), Valid("b")], Valid(AnyOfValue(0, "a"))),
        (
            [Rejected("missing"), Rejected("missing")],
            Rejected("missing", "None of the accepted identity proofs was presented."),
        ),
        ([Rejected("missing"), identity.forbidden("no")], identity.forbidden("no")),
        ([identity.invalid("bad"), Rejected("missing")], identity.invalid("bad")),
    ],
)
async def test_any_of_accepts_the_first_valid_member(
    outcomes: list[Verification[Any]], expected: Verification[Any]
) -> None:
    combined = any_of(*(fixed(outcome) for outcome in outcomes))
    assert await combined.verify(http_request()) == expected


async def test_any_of_runs_every_member_so_each_nonce_is_spent() -> None:
    calls: list[str] = []
    combined = any_of(fixed(Valid(1), calls, "a"), fixed(Valid(2), calls, "b"))
    await combined.verify(http_request())
    assert calls == ["a", "b"]


def test_any_of_validates_its_members() -> None:
    with pytest.raises(ValueError, match="at least two"):
        any_of(fixed(Valid(1)))
    with pytest.raises(TypeError, match="only verifiers"):
        any_of(fixed(Valid(1)), "nope")  # pyright: ignore[reportArgumentType]


def test_any_of_reads_authorization_when_a_member_does() -> None:
    reads = Verifier(verify=fixed(Valid(1)).verify, authorization=True)
    assert any_of(fixed(Valid(1)), reads).authorization
    assert not any_of(fixed(Valid(1)), fixed(Valid(2))).authorization


async def test_nested_any_of_values_are_found_by_every_level() -> None:
    leaf = fixed(Valid("leaf"))
    inner = any_of(fixed(Rejected("missing")), leaf)
    outer = any_of(fixed(Rejected("missing")), inner)
    results = await IdentityContext(http_request()).verify(Route(request=(outer,)))
    assert isinstance(results, Results)
    assert results.get(leaf) == "leaf"
    assert results.get(inner) == AnyOfValue(1, "leaf")
    assert results.get(outer) == AnyOfValue(1, AnyOfValue(1, "leaf"))


async def test_context_runs_each_verifier_once_per_request() -> None:
    calls: list[str] = []
    shared = fixed(Valid(1), calls, "shared")
    context = IdentityContext(http_request())
    await context.verify(Route(request=(shared, any_of(shared, fixed(Valid(2))))))
    await context.verify(Route(request=(shared,)))
    assert calls == ["shared"]


async def test_context_combines_route_rejections_by_precedence() -> None:
    route = Route(request=(fixed(Rejected("missing")), fixed(identity.forbidden("no"))))
    assert await IdentityContext(http_request()).verify(route) == identity.forbidden("no")


async def test_context_refuses_a_verifier_that_returns_something_else() -> None:
    async def wrong(request: Any) -> Any:
        return True

    with pytest.raises(TypeError, match="Valid or Rejected"):
        await IdentityContext(http_request()).evaluate(Verifier(verify=wrong))


# --- from_fn --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("behavior", "expected"),
    [
        (lambda: "customer", Valid("customer")),
        (lambda: None, Rejected("missing", "", (("WWW-Authenticate", "ApiKey"),))),
        (
            lambda: (_ for _ in ()).throw(RejectionError("unknown key", status="forbidden")),
            Rejected("forbidden", "unknown key", (("WWW-Authenticate", "ApiKey"),)),
        ),
        (
            lambda: (_ for _ in ()).throw(RejectionError("bad key")),
            Rejected("invalid", "bad key", (("WWW-Authenticate", "ApiKey"),)),
        ),
    ],
)
async def test_from_fn_maps_a_lookup_to_outcomes(
    behavior: Any, expected: Rejected | Valid[Any]
) -> None:
    async def lookup(request: Any) -> Any:
        return behavior()

    verifier = from_fn(lookup, challenge={"WWW-Authenticate": "ApiKey"})
    assert await verifier.verify(http_request()) == expected


async def test_from_fn_lets_other_errors_through() -> None:
    async def broken(request: Any) -> Any:
        raise RuntimeError("database down")

    with pytest.raises(RuntimeError, match="database down"):
        await from_fn(broken).verify(http_request())


def test_rejection_error_refuses_missing() -> None:
    with pytest.raises(ValueError, match="invalid, forbidden or unavailable"):
        RejectionError("x", status="missing")  # pyright: ignore[reportArgumentType]


# --- Routes ---------------------------------------------------------------------------------------

VERIFIER = fixed(Valid(1))
CHECK = PaymentCheck(requires=(Requirement("kyc"),), verify=check_outcome)


@pytest.mark.parametrize(
    ("option", "expected"),
    [
        (None, Route()),
        ([], Route()),
        ([VERIFIER], Route(request=(VERIFIER,))),
        ((VERIFIER,), Route(request=(VERIFIER,))),
        (Route(payment=CHECK), Route(payment=CHECK)),
    ],
)
def test_route_option_shapes(option: Any, expected: Route) -> None:
    assert Route.of(option) == expected


@pytest.mark.parametrize(
    ("option", "match"),
    [
        (VERIFIER, "wrap a single verifier"),
        (CHECK, "wrap a single verifier"),
        ({"request": [VERIFIER]}, "list of verifiers"),
        (["not a verifier"], "only verifiers"),
    ],
)
def test_route_option_refuses_other_shapes(option: Any, match: str) -> None:
    with pytest.raises(TypeError, match=match):
        Route.of(option)


def test_route_properties() -> None:
    reads = Verifier(verify=VERIFIER.verify, authorization=True)
    route = Route(request=(VERIFIER, reads), payment=CHECK)
    assert (route.empty, route.authorization, route.requirements) == (
        False,
        True,
        (Requirement("kyc"),),
    )
    assert Route().empty and not Route().authorization and Route().requirements == ()


def test_payment_check_refuses_requirements_it_cannot_send() -> None:
    with pytest.raises(ValueError, match="not a token"):
        PaymentCheck(requires=(Requirement("not a token"),), verify=check_outcome)


def test_results_are_read_only_and_keyed_by_object() -> None:
    other = fixed(Valid(1))
    results = Results({VERIFIER: "value"})
    assert results.get(VERIFIER) == "value"
    assert results.get(other) is None
    assert VERIFIER in results and other not in results
    with pytest.raises(TypeError):
        results.values[other] = "x"  # pyright: ignore[reportIndexIssue]


# --- Identity-Required ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("items", "header"),
    [
        ((), ""),
        ((Requirement("kyc"),), "kyc"),
        (
            (Requirement("tempo-id", "https://id.tempo.xyz"),),
            'tempo-id;issuer="https://id.tempo.xyz"',
        ),
        ((Requirement("a"), Requirement("b", 'say "hi" \\')), 'a, b;issuer="say \\"hi\\" \\\\"'),
    ],
)
def test_requirements_serialize_and_parse_back(items: tuple[Requirement, ...], header: str) -> None:
    assert requirements.serialize(items) == header
    assert requirements.parse(header) == items


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, ()),
        ("kyc,", ()),
        ("kyc;;", ()),
        ('kyc;issuer="unterminated', ()),
        ("kyc kyc", ()),
        ("  kyc ,\tb  ", (Requirement("kyc"), Requirement("b"))),
        ('(a b), "string", 1, ?1, :aGk=:, kyc', (Requirement("kyc"),)),
        ("kyc;issuer=token", (Requirement("kyc"),)),
        ('kyc;level=2;verified;issuer="i"', (Requirement("kyc", "i"),)),
        ('(a b);x=1, kyc;issuer="https://k.example"', (Requirement("kyc", "https://k.example"),)),
    ],
)
def test_requirements_parse_leniently(
    header: str | None, expected: tuple[Requirement, ...]
) -> None:
    assert requirements.parse(header) == expected


def test_requirements_refuse_an_issuer_that_is_not_printable_ascii() -> None:
    with pytest.raises(ValueError, match="printable ASCII"):
        requirements.serialize((Requirement("kyc", "caf\u00e9"),))


def test_requirements_merge_keeps_first_seen_order() -> None:
    a, b, c = Requirement("a"), Requirement("b", "x"), Requirement("b")
    assert requirements.merge([(a, b), (b, c, a)]) == (a, b, c)


TOKENS = st.from_regex(r"[A-Za-z*][A-Za-z0-9!#$%&'*+.^_|~:/-]{0,12}", fullmatch=True)
ISSUERS = st.none() | st.text(st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=24)


@given(st.lists(st.builds(Requirement, TOKENS, ISSUERS), max_size=5))
def test_requirements_round_trip(items: list[Requirement]) -> None:
    assert requirements.parse(requirements.serialize(items)) == tuple(items)


# --- Provers --------------------------------------------------------------------------------------


async def unchanged(request: httpx.Request, context: Any) -> httpx.Request:
    return request


@pytest.mark.parametrize(
    ("scope", "url", "covered"),
    [
        ("*", "https://anything.example/x", True),
        (["https://api.example"], "https://api.example/paid?q=1", True),
        (["https://api.example"], "https://api.example:443/paid", True),
        (["https://api.example:443"], "https://api.example/paid", True),
        (["https://api.example"], "http://api.example/paid", False),
        (["https://api.example"], "https://api.example:8443/paid", False),
        (["https://api.example"], "https://evil.example/https://api.example", False),
        (["http://localhost:8000"], "http://localhost:8000/x", True),
    ],
)
def test_prover_scope_matches_exact_origins(scope: Any, url: str, covered: bool) -> None:
    assert Prover(scope=scope, prove=unchanged).covers(url) is covered


@pytest.mark.parametrize("scope", ["https://api.example", 42, [1]])
def test_prover_scope_must_be_star_or_origins(scope: Any) -> None:
    with pytest.raises(TypeError, match="scope"):
        Prover(scope=scope, prove=unchanged)


def test_prover_headers_are_lowercased() -> None:
    assert Prover(scope="*", prove=unchanged, headers=("DPoP",)).headers == ("dpop",)


def test_prove_context_is_fresh_per_attempt() -> None:
    first, second = identity.ProveContext.new(), identity.ProveContext.new()
    assert first.nonce != second.nonce
    assert len(first.nonce) == 86  # 64 bytes, unpadded base64url


def test_with_headers_copies_the_request() -> None:
    original = httpx.Request("POST", "https://api.example/x", headers={"A": "1"}, content=b"body")
    copy = identity.with_headers(original, {"B": "2", "A": "3"})
    assert dict(original.headers) | {} == {"a": "1", "host": "api.example", "content-length": "4"}
    assert (copy.headers["A"], copy.headers["B"], copy.read()) == ("3", "2", b"body")


# --- Properties ---------------------------------------------------------------------------------

STATUSES = st.sampled_from(["missing", "invalid", "forbidden", "unavailable"])
REJECTIONS = st.builds(
    Rejected,
    STATUSES,
    st.text(min_size=1, max_size=8),
    st.lists(st.tuples(st.just("X"), st.text(max_size=4)), max_size=2).map(tuple),
)


@given(st.lists(REJECTIONS, min_size=1, max_size=6))
def test_decide_is_the_first_rejection_with_the_highest_precedence(
    rejections: list[Rejected],
) -> None:
    decision = decide(rejections)
    best = min(identity.PRECEDENCE.index(r.status) for r in rejections)
    first = next(r for r in rejections if identity.PRECEDENCE.index(r.status) == best)
    assert (decision.status, decision.reason) == (first.status, first.reason)
    assert decision.headers == tuple(pair for r in rejections for pair in r.headers)


@given(st.lists(st.one_of(REJECTIONS, st.integers().map(Valid)), min_size=2, max_size=5))
async def test_any_of_is_valid_exactly_when_a_member_is(outcomes: list[Any]) -> None:
    combined = await any_of(*(fixed(outcome) for outcome in outcomes)).verify(http_request())
    valid = [i for i, outcome in enumerate(outcomes) if isinstance(outcome, Valid)]
    if valid:
        assert combined == Valid(AnyOfValue(valid[0], outcomes[valid[0]].value))
    else:
        assert isinstance(combined, Rejected)
        assert combined.status == decide(outcomes).status


async def test_context_runs_each_payment_check_once_per_challenge() -> None:
    from mpp import Challenge, Credential
    from mpp.identity import PaymentCheckInput

    calls: list[str] = []

    async def verify(input: PaymentCheckInput) -> Verification[Any]:
        calls.append(input.challenge.id)
        return Valid(len(calls))

    check = PaymentCheck(requires=(), verify=verify)
    context = IdentityContext(http_request())

    def given(challenge_id: str) -> PaymentCheckInput:
        challenge = Challenge(id=challenge_id, realm="r", method="m", intent="i", request={})
        credential = Credential(challenge=challenge.to_echo(), payload={})
        return PaymentCheckInput(
            request=context.request, challenge=challenge, credential=credential
        )

    assert await context.check(check, given("a")) == Valid(1)
    assert await context.check(check, given("a")) == Valid(1)
    assert await context.check(check, given("b")) == Valid(2)
    assert calls == ["a", "b"]


async def test_context_refuses_a_payment_check_that_returns_something_else() -> None:
    from mpp import Challenge, Credential
    from mpp.identity import PaymentCheckInput

    async def wrong(input: PaymentCheckInput) -> Any:
        return "yes"

    challenge = Challenge(id="a", realm="r", method="m", intent="i", request={})
    input = PaymentCheckInput(
        request=http_request(),
        challenge=challenge,
        credential=Credential(challenge=challenge.to_echo(), payload={}),
    )
    with pytest.raises(TypeError, match="Valid or Rejected"):
        await IdentityContext(http_request()).check(PaymentCheck(requires=(), verify=wrong), input)
