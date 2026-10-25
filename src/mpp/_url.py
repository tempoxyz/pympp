"""WHATWG URL parsing for special schemes (``new URL(value)`` parity with mppx).

Mirrors host canonicalization (IPv4 shorthand/hex/octal, bracketed IPv6, IDNA UTS #46), port
validation, dot-segment removal and path percent-encoding. Used for realm auto-detection and by
HTTP message signatures (``@authority`` / ``@path`` / origins). Depends only on ``idna``, which
``httpx`` already requires.
"""

from __future__ import annotations

import ipaddress
import re
import string
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

import idna

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):(.*)", re.DOTALL)
_FORBIDDEN_DOMAIN = frozenset("#%/:<>?@[\\]^|\x7f") | frozenset(map(chr, range(0x21)))
_PATH_ENCODE = frozenset(' "#<>?`{}^')
_SINGLE_DOT = frozenset({".", "%2e"})
_DOUBLE_DOT = frozenset({"..", ".%2e", "%2e.", "%2e%2e"})
_HEX = frozenset(string.hexdigits)


@dataclass(frozen=True, slots=True, kw_only=True)
class Url:
    scheme: str
    username: str
    password: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str

    @property
    def authority(self) -> str:
        """``URL.host``: the serialized host plus any non-default port."""
        return self.host if self.port is None else f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"


def parse_url(value: str) -> Url | None:
    """Parses an absolute special-scheme URL; returns ``None`` where ``new URL()`` would throw
    (or for non-special schemes, which are out of scope)."""
    value = value.strip("".join(map(chr, range(0x21)))).replace("\t", "")
    value = value.replace("\n", "").replace("\r", "")
    match = _SCHEME.fullmatch(value)
    if not match:
        return None
    scheme = match[1].lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    rest = match[2].lstrip("/\\")
    end = next((i for i, c in enumerate(rest) if c in "/\\?#"), len(rest))
    authority, rest = rest[:end], rest[end:]

    username = password = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        username, _, password = userinfo.partition(":")
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            return None
        raw_host, after = authority[: close + 1], authority[close + 1 :]
        if after and not after.startswith(":"):
            return None
        raw_port = after[1:] if after else ""
    else:
        raw_host, _, raw_port = authority.partition(":")
    host = _parse_host(raw_host)
    if host is None:
        return None
    port: int | None = None
    if raw_port:
        if not (raw_port.isascii() and raw_port.isdigit()) or int(raw_port) > 65535:
            return None
        port = int(raw_port)
        if port == _DEFAULT_PORTS[scheme]:
            port = None

    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    return Url(
        scheme=scheme,
        username=username,
        password=password,
        host=host,
        port=port,
        path=_parse_path(rest),
        query=query,
        fragment=fragment,
    )


def _parse_host(raw: str) -> str | None:
    if not raw:
        return None
    if raw.startswith("["):
        return _parse_ipv6(raw[1:-1])
    domain = unquote_to_bytes(raw).decode("utf-8", errors="replace")
    ascii_domain = _domain_to_ascii(domain)
    if not ascii_domain or any(c in _FORBIDDEN_DOMAIN for c in ascii_domain):
        return None
    if _ends_in_number(ascii_domain):
        return _parse_ipv4(ascii_domain)
    return ascii_domain


def _domain_to_ascii(domain: str) -> str | None:
    if domain.isascii():
        return domain.lower()
    try:
        mapped = idna.uts46_remap(domain, std3_rules=False, transitional=False)
        return ".".join(
            label if label.isascii() else idna.alabel(label).decode("ascii")
            for label in mapped.split(".")
        )
    except (idna.IDNAError, UnicodeError, ValueError):
        return None


def _ends_in_number(domain: str) -> bool:
    parts = domain.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    last = parts[-1]
    if last and last.isdigit():
        return True
    return last[:2].lower() == "0x" and all(c in _HEX for c in last[2:])


def _parse_ipv4(domain: str) -> str | None:
    parts = domain.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return None
    numbers: list[int] = []
    for part in parts:
        number = _parse_ipv4_number(part)
        if number is None:
            return None
        numbers.append(number)
    if any(number > 255 for number in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    address = numbers[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(numbers[:-1]))
    return ".".join(str((address >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _parse_ipv4_number(part: str) -> int | None:
    if not part:
        return None
    radix = 10
    if part[:2].lower() == "0x":
        radix, part = 16, part[2:]
    elif len(part) > 1 and part.startswith("0"):
        radix, part = 8, part[1:]
    if not part:
        return 0
    digits = string.hexdigits if radix == 16 else string.digits[:radix]
    if not all(c in digits for c in part):
        return None
    return int(part, radix)


def _parse_ipv6(raw: str) -> str | None:
    if "%" in raw:
        return None
    try:
        value = int(ipaddress.IPv6Address(raw))
    except ValueError:
        return None
    pieces = [(value >> (112 - 16 * i)) & 0xFFFF for i in range(8)]
    best_start, best_length, i = -1, 1, 0
    while i < 8:
        if pieces[i] == 0:
            j = i
            while j < 8 and pieces[j] == 0:
                j += 1
            if j - i > best_length:
                best_start, best_length = i, j - i
            i = j
        else:
            i += 1
    if best_start == -1:
        return "[" + ":".join(f"{p:x}" for p in pieces) + "]"
    head = ":".join(f"{p:x}" for p in pieces[:best_start])
    tail = ":".join(f"{p:x}" for p in pieces[best_start + best_length :])
    return f"[{head}::{tail}]"


def _parse_path(raw: str) -> str:
    if raw[:1] in ("/", "\\"):
        raw = raw[1:]
    segments: list[str] = []
    buffers = re.split(r"[/\\]", raw)
    for index, buffer in enumerate(buffers):
        encoded = "".join(_encode_path_char(c) for c in buffer)
        lowered = encoded.lower()
        is_last = index == len(buffers) - 1
        if lowered in _DOUBLE_DOT:
            if segments:
                segments.pop()
            if is_last:
                segments.append("")
        elif lowered in _SINGLE_DOT:
            if is_last:
                segments.append("")
        else:
            segments.append(encoded)
    return "/" + "/".join(segments)


def _encode_path_char(char: str) -> str:
    if char in _PATH_ENCODE or not 0x20 <= ord(char) <= 0x7E:
        return "".join(f"%{b:02X}" for b in char.encode("utf-8", errors="replace"))
    return char


def hostname(value: str) -> str | None:
    """``new URL(value).hostname`` for special schemes (``None`` where the URL is invalid)."""
    url = parse_url(value)
    return url.host if url is not None else None
