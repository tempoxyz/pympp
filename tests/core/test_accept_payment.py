from dataclasses import dataclass, replace

import pytest

from mpp import Challenge
from mpp import _accept_payment as ap


@dataclass(frozen=True)
class M:
    name: str
    intent: str


@dataclass(frozen=True)
class Offer:
    method: str
    intent: str


def ch(id: str, method: str, intent: str, request: dict | None = None) -> Challenge:
    return Challenge(id=id, method=method, intent=intent, realm="test", request=request or {})


def strip(entries: tuple[ap.Entry, ...]) -> list[tuple[str, str, float]]:
    return [(e.method, e.intent, e.q) for e in entries]


def test_resolve_builds_header() -> None:
    resolved = ap.resolve(
        [M("tempo", "charge"), M("tempo", "session"), M("stripe", "charge")],
        lambda keys: {keys["stripe"]["charge"]: 0.5, keys["tempo"]["session"]: 0},
    )
    assert resolved.header == "tempo/charge, tempo/session;q=0, stripe/charge;q=0.5"
    assert resolved.keys["tempo"]["session"] == "tempo/session"


def test_parse_q_and_wildcards() -> None:
    assert strip(ap.parse("tempo/*, stripe/charge;q=0.5, */session;q=0")) == [
        ("tempo", "*", 1),
        ("stripe", "charge", 0.5),
        ("*", "session", 0),
    ]


@pytest.mark.parametrize(
    ("header", "entries", "normalized"),
    [
        ("tempo/charge", [("tempo", "charge", 1)], "tempo/charge"),
        (
            " stripe/charge ; q = 0.25 , */session ; q=0 ",
            [("stripe", "charge", 0.25), ("*", "session", 0)],
            "stripe/charge;q=0.25, */session;q=0",
        ),
        (
            "tempo/*;q=1, tempo/charge;q=0, stripe/*;q=0.5",
            [("tempo", "*", 1), ("tempo", "charge", 0), ("stripe", "*", 0.5)],
            "tempo/*, tempo/charge;q=0, stripe/*;q=0.5",
        ),
    ],
)
def test_parse_vectors(header: str, entries: list, normalized: str) -> None:
    parsed = ap.parse(header)
    assert strip(parsed) == entries
    assert ap.serialize(parsed) == normalized


@pytest.mark.parametrize(
    ("header", "error"),
    [
        ("", "Accept-Payment header is empty."),
        ("tempo", "Invalid Accept-Payment entry: tempo"),
        ("Tempo/charge", "Invalid Accept-Payment method: Tempo"),
        ("tempo/charge;q", "Invalid Accept-Payment parameter: q"),
        ("tempo/charge;q=1.001", "Expected an HTTP qvalue"),
    ],
)
def test_parse_errors(header: str, error: str) -> None:
    with pytest.raises(ValueError, match=error.replace(".", r"\.")):
        ap.parse(header)


def test_rank() -> None:
    offers = [Offer("tempo", "charge"), Offer("stripe", "charge"), Offer("tempo", "session")]
    prefs = ap.parse("stripe/charge;q=0.5, tempo/charge;q=0.9, tempo/session;q=0.9")
    assert ap.rank(offers, prefs) == [
        Offer("tempo", "charge"),
        Offer("tempo", "session"),
        Offer("stripe", "charge"),
    ]
    assert ap.rank(
        [Offer("tempo", "session")], ap.parse("tempo/*;q=0.5, tempo/session;q=0.5, */*;q=0.1")
    ) == [Offer("tempo", "session")]
    assert ap.rank(
        [Offer("tempo", "charge"), Offer("stripe", "charge")],
        ap.parse("tempo/*;q=1, tempo/charge;q=0, stripe/*;q=0.5"),
    ) == [Offer("stripe", "charge")]
    assert ap.rank(
        [Offer("tempo", "charge"), Offer("stripe", "session")],
        ap.parse("tempo/charge;q=0, stripe/*;q=0.1"),
    ) == [Offer("stripe", "session")]


def test_select_candidates() -> None:
    candidates = ap.select_challenge_candidates(
        [ch("1", "unknown", "charge"), ch("2", "tempo", "session"), ch("3", "stripe", "charge")],
        [M("tempo", "session"), M("stripe", "charge")],
        ap.parse("stripe/charge;q=0.5, tempo/session;q=0.9"),
    )
    assert [
        (c.challenge.id, c.index, ap.key_of(c.method.name, c.method.intent)) for c in candidates
    ] == [
        ("2", 1, "tempo/session"),
        ("3", 2, "stripe/charge"),
    ]


def test_native_before_x402() -> None:
    x402 = replace(ch("x402:0", "evm", "charge", {"scheme": "exact"}), protocol="x402")
    candidates = ap.select_challenge_candidates(
        [x402, ch("native", "tempo", "charge")],
        [M("evm", "charge"), M("tempo", "charge")],
        ap.parse("evm/charge, tempo/charge;q=0.5"),
    )
    assert [c.challenge.id for c in candidates] == ["native", "x402:0"]


def test_preference_order_within_native() -> None:
    candidates = ap.select_challenge_candidates(
        [ch("tempo", "tempo", "charge"), ch("evm", "evm", "charge")],
        [M("tempo", "charge"), M("evm", "charge")],
        ap.parse("evm/charge, tempo/charge;q=0.5"),
    )
    assert [c.challenge.id for c in candidates] == ["evm", "tempo"]


def test_duplicate_keys_with_predicates() -> None:
    challenges = [
        ch("primary", "tempo", "session", {"methodDetails": {"sessionProtocol": "primary"}}),
        ch("fallback", "tempo", "session", {"methodDetails": {"sessionProtocol": "fallback"}}),
        ch("unmarked", "tempo", "session"),
    ]
    first, second = M("tempo", "session"), M("tempo", "session")

    def protocol(challenge: Challenge) -> str | None:
        return (challenge.request.get("methodDetails") or {}).get("sessionProtocol")

    def can_handle(method: M, challenge: Challenge) -> bool:
        if method is first:
            return protocol(challenge) == "primary"
        return protocol(challenge) in (None, "fallback")

    candidates = ap.select_challenge_candidates(
        challenges, [first, second], ap.parse("tempo/session"), can_handle
    )
    assert [c.challenge.id for c in candidates] == ["primary", "fallback", "unmarked"]


def test_specific_opt_out_and_disabled() -> None:
    candidates = ap.select_challenge_candidates(
        [ch("1", "tempo", "charge"), ch("2", "stripe", "charge")],
        [M("tempo", "charge"), M("stripe", "charge")],
        ap.parse("tempo/*;q=1, tempo/charge;q=0, stripe/*;q=0.5"),
    )
    assert candidates[0].challenge.id == "2"
    assert not ap.select_challenge_candidates(
        [ch("1", "tempo", "charge"), ch("2", "stripe", "charge")],
        [M("tempo", "charge")],
        ap.parse("tempo/charge;q=0, stripe/charge"),
    )


@pytest.mark.parametrize(
    ("prefs", "error"),
    [
        ({"stripe/charge": 1}, 'Unknown payment preference "stripe/charge"'),
        ({"tempo/charge": 0.3333}, "Expected at most 3 decimal places"),
        ({"tempo/charge": float("inf")}, "Expected a finite number"),
    ],
)
def test_resolve_errors(prefs: dict, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        ap.resolve([M("tempo", "charge")], prefs)


def test_header_q_values_are_ascii_digits_only() -> None:
    with pytest.raises(ValueError, match="Expected an HTTP qvalue"):
        ap.parse("tempo/charge;q=0." + chr(0x0665))
