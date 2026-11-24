"""The `Identity-Required` header: a structured-field list (RFC 9651) of requirements.

Each requirement is a token item, such as `tempo-id`, with an `issuer` string parameter when
set: `tempo-id;issuer="https://id.tempo.xyz"`. The parser is lenient (members that are not
requirements are skipped, and a malformed value is no requirements) and the serializer is strict
(a type that is not a token raises).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mpp.identity import Requirement

HEADER = "Identity-Required"
"""The response header in which a 402 lists the identities its payment check requires."""

_TOKEN_RE = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")
_KEY_RE = re.compile(r"[a-z*][a-z0-9_\-.*]*")
_NUMBER_RE = re.compile(r"-?[0-9]{1,15}(\.[0-9]{1,3})?")
_BYTES_RE = re.compile(r":[A-Za-z0-9+/=]*:")


def serialize(requirements: Sequence[Requirement]) -> str:
    """Serialize requirements as a structured-field list.

    Raises:
        ValueError: If a type is not a structured-field token, or an issuer is not a
            printable ASCII string.
    """
    return ", ".join(_serialize_one(requirement) for requirement in requirements)


def _serialize_one(requirement: Requirement) -> str:
    if not _TOKEN_RE.fullmatch(requirement.type):
        raise ValueError(f"identity requirement type {requirement.type!r} is not a token")
    if requirement.issuer is None:
        return requirement.type
    if any(not (0x20 <= ord(char) <= 0x7E) for char in requirement.issuer):
        raise ValueError("identity requirement issuer must be printable ASCII")
    escaped = requirement.issuer.replace("\\", "\\\\").replace('"', '\\"')
    return f'{requirement.type};issuer="{escaped}"'


def parse(value: str | None) -> tuple[Requirement, ...]:
    """Parse an `Identity-Required` value, skipping members that are not requirements."""
    from mpp.identity import Requirement

    if not value:
        return ()
    try:
        members = _Parser(value).parse_list()
    except ValueError:
        return ()
    requirements: list[Requirement] = []
    for item, params in members:
        if not isinstance(item, _Token):
            continue
        issuer = params.get("issuer")
        requirements.append(
            Requirement(
                type=str(item),
                issuer=issuer
                if isinstance(issuer, str) and not isinstance(issuer, _Token)
                else None,
            )
        )
    return tuple(requirements)


def merge(lists: Iterable[Sequence[Requirement]]) -> tuple[Requirement, ...]:
    """Return the distinct requirements of several lists, in first-seen order."""
    return tuple(dict.fromkeys(requirement for group in lists for requirement in group))


class _Token(str):
    """A structured-field token, told apart from a string item."""


_BareItem = _Token | str | int | float | bool | bytes


class _Parser:
    """A minimal RFC 9651 list parser: items and inner lists, with parameters."""

    def __init__(self, value: str) -> None:
        self.text = value
        self.pos = 0

    def parse_list(self) -> list[tuple[object, dict[str, _BareItem]]]:
        self._skip(" \t")
        members: list[tuple[object, dict[str, _BareItem]]] = []
        while self.pos < len(self.text):
            if self._peek() == "(":
                members.append(self._inner_list())
            else:
                members.append(self._item())
            self._skip(" \t")
            if self.pos >= len(self.text):
                break
            if self._peek() != ",":
                raise ValueError("expected a comma")
            self.pos += 1
            self._skip(" \t")
            if self.pos >= len(self.text):
                raise ValueError("trailing comma")
        return members

    def _inner_list(self) -> tuple[object, dict[str, _BareItem]]:
        self.pos += 1
        items: list[tuple[_BareItem, dict[str, _BareItem]]] = []
        while True:
            self._skip(" ")
            if self._peek() == ")":
                self.pos += 1
                return (tuple(items), self._params())
            items.append(self._item())
            if self._peek() not in (" ", ")"):
                raise ValueError("malformed inner list")

    def _item(self) -> tuple[_BareItem, dict[str, _BareItem]]:
        return (self._bare_item(), self._params())

    def _params(self) -> dict[str, _BareItem]:
        params: dict[str, _BareItem] = {}
        while self._peek() == ";":
            self.pos += 1
            self._skip(" ")
            key = self._match(_KEY_RE)
            value: _BareItem = True
            if self._peek() == "=":
                self.pos += 1
                value = self._bare_item()
            params[key] = value
        return params

    def _bare_item(self) -> _BareItem:
        char = self._peek()
        if char == '"':
            return self._string()
        if char == "?":
            flag = self.text[self.pos : self.pos + 2]
            if flag not in ("?0", "?1"):
                raise ValueError("malformed boolean")
            self.pos += 2
            return flag == "?1"
        if char == ":":
            return self._match(_BYTES_RE).encode()
        if char == "-" or char.isdigit():
            number = self._match(_NUMBER_RE)
            return float(number) if "." in number else int(number)
        return _Token(self._match(_TOKEN_RE))

    def _string(self) -> str:
        self.pos += 1
        out: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == "\\":
                if self.pos >= len(self.text) or self.text[self.pos] not in '"\\':
                    raise ValueError("malformed escape")
                out.append(self.text[self.pos])
                self.pos += 1
            elif char == '"':
                return "".join(out)
            elif not (0x20 <= ord(char) <= 0x7E):
                raise ValueError("invalid string character")
            else:
                out.append(char)
        raise ValueError("unterminated string")

    def _match(self, pattern: re.Pattern[str]) -> str:
        match = pattern.match(self.text, self.pos)
        if match is None:
            raise ValueError("unexpected character")
        self.pos = match.end()
        return match.group(0)

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _skip(self, chars: str) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in chars:
            self.pos += 1
