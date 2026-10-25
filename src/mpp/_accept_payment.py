"""``Accept-Payment`` negotiation (client preferences and server-side challenge ranking)."""

import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from mpp.challenge import Challenge


class MethodLike(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def intent(self) -> str: ...


class _Offer(Protocol):
    @property
    def method(self) -> str: ...

    @property
    def intent(self) -> str: ...


@dataclass(frozen=True, slots=True)
class Entry:
    """A parsed ``Accept-Payment`` entry with its declaration order."""

    method: str
    intent: str
    q: float
    index: int


@dataclass(frozen=True, slots=True)
class ChallengeCandidate[M]:
    """A supported challenge paired with the configured client method that can sign it."""

    challenge: Challenge
    index: int
    method: M


type KeyTree = dict[str, dict[str, str]]
"""Method keys grouped by method name: ``keys["tempo"]["charge"] == "tempo/charge"``."""

type Preferences = Mapping[str, float] | Callable[[KeyTree], Mapping[str, float]]
"""Per-capability q-values keyed by ``method/intent`` (or a callback receiving a key tree)."""


@dataclass(frozen=True, slots=True)
class Resolved:
    """Resolved negotiation data derived from client methods and preferences."""

    definition: dict[str, float]
    entries: tuple[Entry, ...]
    header: str
    keys: KeyTree


_ENTRY = re.compile(
    r"^(?P<method>[^/;\s]+|\*)\s*/\s*(?P<intent>[^/;\s]+|\*)(?P<params>(?:\s*;\s*.+)?)\Z"
)
_PARAM = re.compile(r"^(?P<name>[A-Za-z0-9_-]+)\s*=\s*(?P<value>\S+)\Z")
_HEADER_Q = re.compile(r"^0(?:\.[0-9]{0,3})?\Z|^1(?:\.0{0,3})?\Z")
_TOKEN = re.compile(r"^[a-z0-9-]+\Z")


def key_of(method: str, intent: str) -> str:
    """Returns the canonical ``method/intent`` key."""
    return f"{method}/{intent}"


def build_keys(methods: Sequence[MethodLike]) -> KeyTree:
    """Builds the key tree used by callback-style preferences."""
    keys: KeyTree = {}
    for method in methods:
        keys.setdefault(method.name, {})[method.intent] = key_of(method.name, method.intent)
    return keys


def resolve(methods: Sequence[MethodLike], preferences: Preferences | None = None) -> Resolved:
    """Resolves configured payment preferences into a header value and parsed entries.

    Raises:
        ValueError: On unknown keys or invalid q-values.
    """
    keys = build_keys(methods)
    definition = _resolve_definition(methods, keys, preferences)
    entries = tuple(
        Entry(
            method=method.name,
            intent=method.intent,
            q=definition.get(key_of(method.name, method.intent), 1),
            index=index,
        )
        for index, method in enumerate(methods)
    )
    return Resolved(definition=definition, entries=entries, header=serialize(entries), keys=keys)


def parse(header: str) -> tuple[Entry, ...]:
    """Parses an ``Accept-Payment`` header.

    Raises:
        ValueError: When the header is empty or malformed.
    """
    parts = [part.strip() for part in re.split(r"\s*,\s*", header)]
    parts = [part for part in parts if part]
    if not parts:
        raise ValueError("Accept-Payment header is empty.")
    return tuple(_parse_entry(part, index) for index, part in enumerate(parts))


def serialize(entries: Sequence[Entry]) -> str:
    """Serializes entries to an ``Accept-Payment`` header value."""
    values = []
    for entry in entries:
        value = f"{entry.method}/{entry.intent}"
        values.append(value if entry.q == 1 else f"{value};q={_format_q(entry.q)}")
    return ", ".join(values)


def rank[O: _Offer](offers: Sequence[O], preferences: Sequence[Entry]) -> list[O]:
    """Orders offers by best matching preference (specific matches beat wildcards; q=0 drops)."""
    ranked: list[tuple[float, int, O]] = []
    for index, offer in enumerate(offers):
        match = _best_match(offer.method, offer.intent, preferences)
        if match is not None and match.q > 0:
            ranked.append((match.q, index, offer))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [offer for _, _, offer in ranked]


def protocol_rank(challenge: Challenge) -> int:
    """Native Payment-auth challenges are preferred over synthesized x402 ones."""
    return 1 if challenge.protocol == "x402" else 0


def select_challenge_candidates[M: MethodLike](
    challenges: Sequence[Challenge],
    methods: Sequence[M],
    preferences: Sequence[Entry],
    can_handle: Callable[[M, Challenge], bool] | None = None,
) -> list[ChallengeCandidate[M]]:
    """Returns supported challenge candidates ordered by preference."""
    by_key: dict[str, list[M]] = {}
    for method in methods:
        by_key.setdefault(key_of(method.name, method.intent), []).append(method)
    scored: list[tuple[int, float, int, ChallengeCandidate[M]]] = []
    for index, challenge in enumerate(challenges):
        matching = by_key.get(key_of(challenge.method, challenge.intent))
        if not matching:
            continue
        match = _best_match(challenge.method, challenge.intent, preferences)
        if match is None or match.q <= 0:
            continue
        for method in matching:
            if can_handle is not None and not can_handle(method, challenge):
                continue
            candidate = ChallengeCandidate(challenge=challenge, index=index, method=method)
            scored.append((protocol_rank(challenge), match.q, index, candidate))
    scored.sort(key=lambda item: (item[0], -item[1], item[2]))
    return [candidate for *_, candidate in scored]


def _best_match(method: str, intent: str, preferences: Sequence[Entry]) -> Entry | None:
    best: Entry | None = None
    best_specificity = -1
    for preference in preferences:
        if preference.method not in ("*", method) or preference.intent not in ("*", intent):
            continue
        specificity = int(preference.method != "*") + int(preference.intent != "*")
        if (
            best is None
            or specificity > best_specificity
            or (specificity == best_specificity and preference.q > best.q)
            or (
                specificity == best_specificity
                and preference.q == best.q
                and preference.index < best.index
            )
        ):
            best = preference
            best_specificity = specificity
    return best


def _parse_entry(part: str, index: int) -> Entry:
    match = _ENTRY.match(part)
    if not match:
        raise ValueError(f"Invalid Accept-Payment entry: {part}")
    method, intent = match.group("method"), match.group("intent")
    _assert_token(method, "method")
    _assert_token(intent, "intent")
    q = 1.0
    params = match.group("params")
    for param in [p for p in re.split(r"\s*;\s*", params) if p] if params else []:
        parameter = _PARAM.match(param)
        if not parameter:
            raise ValueError(f"Invalid Accept-Payment parameter: {param}")
        if parameter.group("name") != "q":
            continue
        q = _parse_header_q(parameter.group("value"), f'Accept-Payment entry "{part}"')
    return Entry(method=method, intent=intent, q=q, index=index)


def _resolve_definition(
    methods: Sequence[MethodLike], keys: KeyTree, preferences: Preferences | None
) -> dict[str, float]:
    if not preferences:
        return {}
    raw = preferences(keys) if callable(preferences) else preferences
    allowed = [key_of(method.name, method.intent) for method in methods]
    normalized: dict[str, float] = {}
    for key, value in (raw or {}).items():
        if key not in allowed:
            raise ValueError(
                f'Unknown payment preference "{key}". Available: {", ".join(dict.fromkeys(allowed))}'
            )
        normalized[key] = _parse_q(value, f'payment preference "{key}"')
    return normalized


def _parse_q(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError(f"Invalid q-value for {context}. Expected a finite number.")
    return _assert_q(float(value), context)


def _parse_header_q(value: str, context: str) -> float:
    if not _HEADER_Q.match(value):
        raise ValueError(f"Invalid q-value for {context}. Expected an HTTP qvalue.")
    return _assert_q(float(value), context)


def _assert_q(value: float, context: str) -> float:
    if value < 0 or value > 1:
        raise ValueError(f"Invalid q-value for {context}. Expected a value between 0 and 1.")
    rounded = round(value * 1000)
    if abs(value * 1000 - rounded) > 1e-9:
        raise ValueError(f"Invalid q-value for {context}. Expected at most 3 decimal places.")
    return rounded / 1000


def _format_q(value: float) -> str:
    text = f"{value:.3f}"
    text = re.sub(r"\.0+$", "", text)
    return re.sub(r"(\.\d*?)0+$", r"\1", text)


def _assert_token(value: str, label: str) -> None:
    if value != "*" and not _TOKEN.match(value):
        raise ValueError(f"Invalid Accept-Payment {label}: {value}")
