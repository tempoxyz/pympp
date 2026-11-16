"""x402 ``sign-in-with-x`` (SIWX): wallets that proved their address skip payment.

A server that accepts SIWX adds the ``sign-in-with-x`` extension to its x402 402. A
client signs that challenge as an EIP-4361 (Sign-In with Ethereum) message and sends it
back in the ``SIGN-IN-WITH-X`` header; when the server's ``grant`` approves the wallet,
it serves the resource without settling a payment. Ported from mppx ``x402/Siwx``.

Servers enable it with the ``siwx`` option of :func:`mpp.methods.evm.server.charge`;
clients wrap their transport with :class:`SiwxTransport`.

See https://github.com/coinbase/x402/blob/main/specs/extensions/sign-in-with-x.md
"""

from __future__ import annotations

import base64
import binascii
import inspect
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict, cast
from urllib.parse import urlsplit

import httpx

from mpp.store import ExpiringStore
from mpp.x402._header import MAX_HEADER_SIZE, decode_payment_required
from mpp.x402._types import PAYMENT_REQUIRED_HEADER

if TYPE_CHECKING:
    from mpp.server.http import Request
    from mpp.store import Store

__all__ = [
    "EXTENSION_KEY",
    "HEADER",
    "PAYLOAD_JSON_SCHEMA",
    "TTL_SECONDS",
    "Chain",
    "ErrorCode",
    "Extension",
    "Info",
    "InvalidProofError",
    "Payload",
    "SiwxOptions",
    "SiwxTransport",
    "VerifiedProof",
    "create_extension",
    "decode",
    "encode",
    "from_payment_required",
    "to_message",
    "verify",
]

EXTENSION_KEY = "sign-in-with-x"
"""Key of the x402 ``sign-in-with-x`` (SIWX) extension in a 402's ``extensions``."""

HEADER = "SIGN-IN-WITH-X"
"""Request header that carries a signed SIWX proof as base64-encoded JSON."""

TTL_SECONDS = 5 * 60
"""How long a SIWX challenge stays valid (mppx ``ttl``, five minutes)."""

# Tolerance for client clocks that run slightly ahead of the server.
_CLOCK_SKEW_SECONDS = 60

ErrorCode = Literal[
    "invalid_siwx_payload",
    "invalid_siwx_domain_mismatch",
    "invalid_siwx_uri_mismatch",
    "invalid_siwx_issued_at",
    "invalid_siwx_issued_at_too_old",
    "invalid_siwx_issued_at_in_future",
    "invalid_siwx_expiration_time",
    "invalid_siwx_expired",
    "invalid_siwx_not_before",
    "invalid_siwx_not_yet_valid",
    "invalid_siwx_nonce",
    "invalid_siwx_signature",
    "invalid_siwx_chain_id",
    "invalid_siwx_unsupported_chain",
    "invalid_siwx_verifier_error",
]
"""Machine-readable codes for a rejected proof, as the x402 SIWX spec names them."""


class Chain(TypedDict):
    """A signing method a server accepts."""

    chainId: str
    type: str
    signatureScheme: NotRequired[str]


class Info(TypedDict):
    """Message fields a server declares in its 402."""

    domain: str
    issuedAt: str
    nonce: str
    uri: str
    version: str
    expirationTime: NotRequired[str]
    notBefore: NotRequired[str]
    requestId: NotRequired[str]
    resources: NotRequired[list[str]]
    statement: NotRequired[str]


class Extension(TypedDict):
    """The extension's value in a 402's ``extensions``."""

    info: Info
    schema: dict[str, Any]
    supportedChains: list[Chain]


class Payload(Info):
    """The signed proof a client sends in the :data:`HEADER`."""

    address: str
    chainId: str
    signature: str
    type: str
    signatureScheme: NotRequired[str]


PAYLOAD_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "properties": {
        "address": {"type": "string"},
        "chainId": {"type": "string"},
        "domain": {"type": "string"},
        "expirationTime": {"format": "date-time", "type": "string"},
        "issuedAt": {"format": "date-time", "type": "string"},
        "nonce": {"type": "string"},
        "notBefore": {"format": "date-time", "type": "string"},
        "requestId": {"type": "string"},
        "resources": {"items": {"format": "uri", "type": "string"}, "type": "array"},
        "signature": {"type": "string"},
        "statement": {"type": "string"},
        "type": {"type": "string"},
        "uri": {"format": "uri", "type": "string"},
        "version": {"type": "string"},
    },
    "required": [
        "domain",
        "address",
        "uri",
        "version",
        "chainId",
        "type",
        "nonce",
        "issuedAt",
        "signature",
    ],
    "type": "object",
}
"""JSON Schema of a :class:`Payload`, advertised in the 402 as the spec requires."""


class InvalidProofError(Exception):
    """A proof the server rejects. Its message is the spec's :data:`ErrorCode`."""

    code: ErrorCode

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code)
        self.code = code


SignatureVerifier = Callable[[str, str, str], "bool | Awaitable[bool]"]
"""Verifies ``(address, message, signature)``, such as an EIP-1271/EIP-6492 RPC check."""

GrantFn = Callable[[str, int, "Request"], "bool | Awaitable[bool]"]
"""Decides whether ``(address, chain_id, request)`` gets the resource without paying."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SiwxOptions:
    """Server options for accepting SIWX proofs on an x402 route (mppx ``ServerOptions``).

    Attributes:
        origin: Public origin of the server as clients see it, such as
            ``https://api.example.com``. Proofs must name it. It is never taken from
            request headers such as ``Host``, which a caller controls.
        store: Store that records used nonces, so each proof is accepted once. A store
            with ``put_if_absent_until`` (:class:`~mpp.store.ExpiringStore`) lets the
            claims expire once their proofs could no longer verify. In a composed route,
            give offers that share a backend the same store object: each store object
            records the nonce on its own, so two objects over one backend refuse a later
            offer.
        grant: Decides whether a wallet that proved its address gets the resource
            without paying, given ``(address, chain_id, request)``. Return ``False`` to
            answer 402 so it pays. May be sync or async.
        verifier: Verifies ``(address, message, signature)`` in place of EOA signature
            recovery, such as smart-wallet (EIP-1271 and EIP-6492) signatures with an
            RPC call. Without it, only EOA signatures verify.
        body: Set when ``grant`` reads the request body (such as ``await
            request.json()``), so the ASGI middleware and ``@pay`` load it first.
    """

    origin: str
    store: Store
    grant: GrantFn
    verifier: SignatureVerifier | None = None
    body: bool = False

    def __post_init__(self) -> None:
        if _url(self.origin) is None:
            raise ValueError("siwx origin must be an absolute http(s) URL")
        if not callable(self.grant):
            raise ValueError("siwx grant must be callable")
        if self.verifier is not None and not callable(self.verifier):
            raise ValueError("siwx verifier must be callable")


@dataclass(frozen=True, slots=True)
class VerifiedProof:
    """The wallet a proof authenticated."""

    address: str
    chain_id: int


# ---------------------------------------------------------------------------
# Message
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"([a-zA-Z]{2,63}|[xX][nN]--[a-zA-Z0-9-]{0,58}[a-zA-Z0-9])(:[0-9]{1,5})?$"
)
_IP_RE = re.compile(
    r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(:[0-9]{1,5})?$"
)
_LOCALHOST_RE = re.compile(r"^localhost(:[0-9]{1,5})?$")
_IPV6_RE = re.compile(r"^\[([0-9a-fA-F:.]+)\](:[0-9]{1,5})?$")
_NONCE_RE = re.compile(r"^[a-zA-Z0-9]{8,}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SIGNATURE_RE = re.compile(r"^0x[0-9a-fA-F]+$")
# A chain ID is at most a uint256 (78 digits), which keeps int() far below its digit limit.
_CHAIN_ID_RE = re.compile(r"^eip155:(\d{1,78})$")
_URI_RE = re.compile(r"(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?")


def _is_uri(value: str) -> bool:
    """viem's ``isUri`` (from valid-url): an RFC 3986 URI with a scheme."""
    if re.search(r"[^a-z0-9:/?#\[\]@!$&'()*+,;=.\-_~%]", value, re.IGNORECASE):
        return False
    if re.search(r"%[^0-9a-f]", value, re.IGNORECASE):
        return False
    if re.search(r"%[0-9a-f](:?[^0-9a-f]|$)", value, re.IGNORECASE):
        return False
    match = _URI_RE.match(value)
    assert match is not None
    scheme, authority, path = match.group(1), match.group(2), match.group(3)
    if not scheme:
        return False
    if authority:
        if path and not path.startswith("/"):
            return False
    elif path.startswith("//"):
        return False
    return re.fullmatch(r"[a-z][a-z0-9+\-.]*", scheme.lower()) is not None


def _parse_time(value: str) -> float | None:
    """Parse an ISO 8601 timestamp to Unix seconds (mppx ``Date.parse``), or ``None``.

    A timestamp without an offset is read as UTC.
    """
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _iso(seconds: float) -> str:
    """Format Unix seconds like JavaScript's ``Date.prototype.toISOString``."""
    milliseconds = int(seconds * 1000) if seconds >= 0 else -int(-seconds * 1000)
    moment = datetime.fromtimestamp(milliseconds // 1000, UTC)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{milliseconds % 1000:03d}Z"


# An RFC 3339 date-time, as SIWE timestamps are.
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")


def _message_time(value: str, field: str) -> str:
    """A timestamp as it is signed: exactly as the payload carries it, as the x402 reference."""
    if not _TIMESTAMP_RE.fullmatch(value) or _parse_time(value) is None:
        raise ValueError(f"Invalid SIWE message field {field}: {value!r}")
    return value


def _chain_id_of(value: str) -> int:
    match = _CHAIN_ID_RE.fullmatch(value)
    if match is None:
        raise InvalidProofError("invalid_siwx_chain_id")
    return int(match.group(1))


def _is_ipv6_authority(domain: str) -> bool:
    """Whether ``domain`` is a bracketed IPv6 host with an optional port, as ``URL.host``."""
    import ipaddress

    match = _IPV6_RE.fullmatch(domain)
    if match is None:
        return False
    try:
        ipaddress.IPv6Address(match.group(1))
    except ValueError:
        return False
    return True


def to_message(payload: Mapping[str, Any]) -> str:
    """Build the EIP-4361 (SIWE) message a payload signs.

    The layout is viem's ``createSiweMessage``, as mppx's, and timestamps are signed exactly
    as the payload carries them (RFC 3339), as the x402 reference does.
    ``payload`` is a :class:`Payload` without its ``signature``.

    Raises:
        ValueError: A field the message format rejects (as viem's
            ``SiweInvalidMessageFieldError``), such as a short nonce or an invalid URI.
        InvalidProofError: ``chainId`` is not ``eip155:<id>``.
    """
    from eth_utils.address import to_checksum_address

    address_value = payload["address"]
    if not isinstance(address_value, str) or not _ADDRESS_RE.fullmatch(address_value):
        raise ValueError(f"Invalid SIWE message field address: {address_value!r}")
    address = to_checksum_address(address_value)
    chain_id = _chain_id_of(payload["chainId"])
    domain: str = payload["domain"]
    nonce: str = payload["nonce"]
    uri: str = payload["uri"]
    if not (
        _DOMAIN_RE.fullmatch(domain)
        or _IP_RE.fullmatch(domain)
        or _LOCALHOST_RE.fullmatch(domain)
        or _is_ipv6_authority(domain)
    ):
        raise ValueError(f"Invalid SIWE message field domain: {domain!r}")
    if not _NONCE_RE.fullmatch(nonce):
        raise ValueError(f"Invalid SIWE message field nonce: {nonce!r}")
    if not _is_uri(uri):
        raise ValueError(f"Invalid SIWE message field uri: {uri!r}")
    statement = payload.get("statement")
    if statement and "\n" in statement:
        raise ValueError("Invalid SIWE message field statement: it must not include a newline")

    # As mppx: the version signed is always "1" and empty optional fields are left out.
    issued_at = _message_time(payload["issuedAt"], "issuedAt")
    # viem's layout: a blank line after the address and another before ``URI``.
    prefix = f"{domain} wants you to sign in with your Ethereum account:\n{address}\n\n"
    if statement:
        prefix += f"{statement}\n"
    lines = [
        f"URI: {uri}",
        "Version: 1",
        f"Chain ID: {chain_id}",
        f"Nonce: {nonce}",
        f"Issued At: {issued_at}",
    ]
    if expiration_time := payload.get("expirationTime"):
        lines.append(f"Expiration Time: {_message_time(expiration_time, 'expirationTime')}")
    if not_before := payload.get("notBefore"):
        lines.append(f"Not Before: {_message_time(not_before, 'notBefore')}")
    if request_id := payload.get("requestId"):
        if "\n" in request_id:
            raise ValueError("Invalid SIWE message field requestId: it must not include a newline")
        lines.append(f"Request ID: {request_id}")
    resources = payload.get("resources")
    if resources is not None:
        lines.append("Resources:")
        for resource in resources:
            if not _is_uri(resource):
                raise ValueError(f"Invalid SIWE message field resources: {resource!r}")
            lines.append(f"- {resource}")
    return prefix + "\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Header and extension
# ---------------------------------------------------------------------------

_INFO_REQUIRED = ("domain", "issuedAt", "nonce", "uri", "version")
_INFO_OPTIONAL = ("expirationTime", "notBefore", "requestId", "statement")
_PAYLOAD_REQUIRED = ("address", "chainId", "signature", "type")
_PAYLOAD_OPTIONAL = ("signatureScheme",)


def _strings(
    record: Mapping[str, Any], required: tuple[str, ...], optional: tuple[str, ...]
) -> dict[str, Any] | None:
    """The record's known string fields (unknown keys dropped, as zod does), or ``None``."""
    result: dict[str, Any] = {}
    for key in required:
        value = record.get(key)
        if not isinstance(value, str):
            return None
        result[key] = value
    for key in optional:
        if key not in record:
            continue
        value = record[key]
        if not isinstance(value, str):
            return None
        result[key] = value
    return result


def _parse_info(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    record = cast(Mapping[str, Any], value)
    info = _strings(record, _INFO_REQUIRED, _INFO_OPTIONAL)
    if info is None:
        return None
    if "resources" in record:
        resources = record["resources"]
        if not isinstance(resources, list) or not all(
            isinstance(item, str) for item in cast(list[Any], resources)
        ):
            return None
        info["resources"] = list(cast(list[str], resources))
    return info


def _parse_payload(value: Any) -> Payload | None:
    info = _parse_info(value)
    if info is None:
        return None
    fields = _strings(cast(Mapping[str, Any], value), _PAYLOAD_REQUIRED, _PAYLOAD_OPTIONAL)
    if fields is None:
        return None
    return cast(Payload, {**info, **fields})


def encode(payload: Mapping[str, Any]) -> str:
    """Encode a :class:`Payload` as a :data:`HEADER` value (base64 JSON)."""
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(text.encode()).decode("ascii")


def decode(value: str) -> Payload:
    """Decode a :data:`HEADER` value.

    Raises:
        InvalidProofError: ``invalid_siwx_payload`` when it is malformed.
    """
    if len(value) > MAX_HEADER_SIZE:
        raise InvalidProofError("invalid_siwx_payload")
    try:
        raw = value.strip().replace("-", "+").replace("_", "/")
        data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        parsed = json.loads(data.decode())
    except (binascii.Error, ValueError, UnicodeDecodeError, RecursionError) as error:
        # RecursionError: deeply nested JSON, as the x402 header decoder handles it.
        raise InvalidProofError("invalid_siwx_payload") from error
    payload = _parse_payload(parsed)
    if payload is None:
        raise InvalidProofError("invalid_siwx_payload")
    return payload


def from_payment_required(payment_required: Mapping[str, Any]) -> Extension | None:
    """Read the SIWX extension from a decoded x402 402 body, if it offers one."""
    extensions = payment_required.get("extensions")
    if not isinstance(extensions, Mapping):
        return None
    value = cast(Mapping[str, Any], extensions).get(EXTENSION_KEY)
    if not isinstance(value, Mapping):
        return None
    record = cast(Mapping[str, Any], value)
    info = _parse_info(record.get("info"))
    schema = record.get("schema")
    chains = record.get("supportedChains")
    if info is None or not isinstance(schema, Mapping) or not isinstance(chains, list):
        return None
    supported: list[Chain] = []
    for chain in cast(list[Any], chains):
        if not isinstance(chain, Mapping):
            return None
        parsed = _strings(cast(Mapping[str, Any], chain), ("chainId", "type"), _PAYLOAD_OPTIONAL)
        if parsed is None:
            return None
        supported.append(cast(Chain, parsed))
    return {
        "info": cast(Info, info),
        "schema": dict(cast(Mapping[str, Any], schema)),
        "supportedChains": supported,
    }


def create_extension(*, chain_id: int, origin: str, url: str) -> Extension:
    """Build the extension a server adds to a 402, with a fresh nonce.

    Args:
        chain_id: EVM chain ID the server accepts signatures for.
        origin: The server's public origin.
        url: URL of the requested resource.
    """
    server = _url(origin)
    if server is None:
        raise ValueError("origin must be an absolute http(s) URL")
    host, server_origin = server
    parts = urlsplit(url)
    path = parts.path or "/"
    search = f"?{parts.query}" if parts.query else ""
    now = time.time()
    return {
        "info": {
            "domain": host,
            "expirationTime": _iso(now + TTL_SECONDS),
            "issuedAt": _iso(now),
            "nonce": secrets.token_hex(16),
            "uri": server_origin + path + search,
            "version": "1",
        },
        "schema": PAYLOAD_JSON_SCHEMA,
        "supportedChains": [{"chainId": f"eip155:{chain_id}", "type": "eip191"}],
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def _url(value: str) -> tuple[str, str] | None:
    """A URL's ``(host, origin)`` as WHATWG ``URL`` gives them, or ``None``."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    hostname = parts.hostname
    if scheme not in _DEFAULT_PORTS or not hostname:
        return None
    if ":" in hostname:
        hostname = f"[{hostname}]"
    host = hostname if port is None or port == _DEFAULT_PORTS[scheme] else f"{hostname}:{port}"
    return host, f"{scheme}://{host}"


def _origin_of(value: str) -> str | None:
    parsed = _url(value)
    return parsed[1] if parsed is not None else None


def _recover(message: str, signature: str) -> str:
    from eth_account import Account
    from eth_account.messages import encode_defunct

    return str(
        Account.recover_message(  # pyright: ignore[reportUnknownMemberType]
            encode_defunct(text=message), signature=bytes.fromhex(signature[2:])
        )
    )


async def _claim(store: Store, key: str, expires_at: float) -> bool:
    """Claim ``key`` once until ``expires_at`` (mppx ``Store.tryClaim``)."""
    if expires_at <= time.time():
        return False
    # A string, as other replay claims store: Redis and SQL stores reject a dict.
    marker = json.dumps({"expires": int(expires_at * 1000), "type": "mppx:replay"})
    if isinstance(store, ExpiringStore):
        claimed = await store.put_if_absent_until(key, marker, expires_at)
    else:
        # A store without expiry keeps the claim; nonces are random, so it never collides.
        claimed = await store.put_if_absent(key, marker)
    return claimed and expires_at > time.time()


async def verify(
    *,
    chain_id: int,
    origin: str,
    store: Store,
    payload: Payload,
    verifier: SignatureVerifier | None = None,
    claim_nonce: bool = True,
) -> VerifiedProof:
    """Verify a SIWX proof against the server's origin and chain, then record its nonce.

    The checks run in mppx's order, and the nonce is claimed last, so a proof that fails
    verification cannot use up another's nonce.

    Args:
        chain_id: EVM chain ID the server accepts signatures for.
        origin: The server's public origin.
        store: Store that records used nonces under ``mppx:x402:siwx:<nonce>``.
        payload: The decoded proof.
        verifier: Optional ``(address, message, signature)`` check used instead of EOA
            recovery, such as for smart-wallet signatures.
        claim_nonce: Whether to record the nonce. Pass ``False`` to reserve it later with
            :func:`claim`, such as once every offer's checks have passed.

    Raises:
        InvalidProofError: With the spec's code, when the proof is rejected.
    """
    from eth_utils.address import to_checksum_address

    server = _url(origin)
    if server is None:
        raise ValueError("origin must be an absolute http(s) URL")
    host, server_origin = server
    now = time.time()

    if payload["domain"] != host:
        raise InvalidProofError("invalid_siwx_domain_mismatch")
    if _origin_of(payload["uri"]) != server_origin:
        raise InvalidProofError("invalid_siwx_uri_mismatch")

    issued_at = _parse_time(payload["issuedAt"])
    if issued_at is None:
        raise InvalidProofError("invalid_siwx_issued_at")
    if issued_at > now + _CLOCK_SKEW_SECONDS:
        raise InvalidProofError("invalid_siwx_issued_at_in_future")
    if now - issued_at > TTL_SECONDS:
        raise InvalidProofError("invalid_siwx_issued_at_too_old")
    if "expirationTime" in payload:
        expires = _parse_time(payload["expirationTime"])
        if expires is None:
            raise InvalidProofError("invalid_siwx_expiration_time")
        if expires <= now:
            raise InvalidProofError("invalid_siwx_expired")
    if "notBefore" in payload:
        not_before = _parse_time(payload["notBefore"])
        if not_before is None:
            raise InvalidProofError("invalid_siwx_not_before")
        if not_before > now:
            raise InvalidProofError("invalid_siwx_not_yet_valid")

    if not payload["chainId"].startswith("eip155:"):
        raise InvalidProofError("invalid_siwx_unsupported_chain")
    proof_chain_id = _chain_id_of(payload["chainId"])
    if proof_chain_id != chain_id:
        raise InvalidProofError("invalid_siwx_unsupported_chain")
    # EIP-4361 nonces are at least 8 alphanumeric characters. The nonce becomes a store key,
    # so it is also capped: servers issue 32 characters.
    nonce = payload["nonce"]
    if len(nonce) > _MAX_NONCE_LENGTH or not _NONCE_RE.fullmatch(nonce):
        raise InvalidProofError("invalid_siwx_nonce")

    if not _ADDRESS_RE.fullmatch(payload["address"]):
        raise InvalidProofError("invalid_siwx_payload")
    address = to_checksum_address(payload["address"])
    signature = payload["signature"]
    if not _SIGNATURE_RE.fullmatch(signature):
        raise InvalidProofError("invalid_siwx_signature")
    try:
        message = to_message(payload)
    except ValueError as error:
        raise InvalidProofError("invalid_siwx_payload") from error

    try:
        if verifier is not None:
            result = verifier(address, message, signature)
            if inspect.isawaitable(result):
                result = await result
            valid = result is True
        else:
            valid = to_checksum_address(_recover(message, signature)) == address
    except Exception as error:
        if verifier is not None:
            raise InvalidProofError("invalid_siwx_verifier_error") from error
        valid = False
    if not valid:
        raise InvalidProofError("invalid_siwx_signature")

    # Claim the nonce last, so a proof that fails verification cannot burn another's nonce.
    if claim_nonce:
        await claim(store=store, payload=payload)
    return VerifiedProof(address=address, chain_id=proof_chain_id)


# The longest nonce :func:`verify` accepts, which bounds each claim's store key.
_MAX_NONCE_LENGTH = 128


def _nonce_key(payload: Payload) -> str:
    return f"mppx:x402:siwx:{payload['nonce']}"


def _claim_expires(payload: Payload) -> float:
    issued_at = _parse_time(payload["issuedAt"])
    if issued_at is None:
        raise InvalidProofError("invalid_siwx_issued_at")
    return issued_at + TTL_SECONDS + _CLOCK_SKEW_SECONDS


async def claim(*, store: Store, payload: Payload) -> None:
    """Record a verified proof's nonce so it is accepted once.

    Raises:
        InvalidProofError: With ``invalid_siwx_nonce`` when the nonce was already used.
    """
    if not await _claim(store, _nonce_key(payload), _claim_expires(payload)):
        raise InvalidProofError("invalid_siwx_nonce")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


_SIWX_ORIGIN_EXTENSION = "mpp.siwx.original_origin"
# The first origin PaymentTransport records on the request it was given, before identity
# provers copy it: a SiwxTransport inside it sees only those copies.
_PAYMENT_ORIGIN_EXTENSION = "mpp.original_origin"


def _transport_origin(url: httpx.URL) -> tuple[str, str, int | None]:
    """A URL's origin as PaymentTransport records it."""
    port = url.port if url.port is not None else {"http": 80, "https": 443}.get(url.scheme)
    return (url.scheme, url.raw_host.decode("ascii"), port)


class SiwxTransport(httpx.AsyncBaseTransport):
    """httpx transport that answers a 402 offering SIWX once, before any payment.

    The equivalent of mppx ``Siwx.wrapFetch``: on a 402 whose ``PAYMENT-REQUIRED``
    offers ``sign-in-with-x`` for an ``eip155`` chain with ``eip191`` signatures, it
    signs the challenge with ``account`` and retries with the :data:`HEADER`, sending
    the request body again. When the server still answers 402 because it doesn't grant
    this wallet, that response is returned, so a
    :class:`~mpp.client.PaymentTransport` around it pays as usual.

    It signs only when the challenge's ``domain`` and ``uri`` origin match the URL that
    returned the 402, and never after a redirect to another origin.

    Example::

        from mpp.client import PaymentTransport
        from mpp.methods.evm import BASE_USDC
        from mpp.methods.evm import client as evm
        from mpp.x402.siwx import SiwxTransport

        transport = PaymentTransport(
            [evm.charge(currency=BASE_USDC, account=account)],
            inner=SiwxTransport(account=account),
        )

    Args:
        account: An eth-account ``LocalAccount`` (anything with ``address`` and
            ``sign_message``) that signs SIWX challenges.
        inner: The transport that sends requests (a new ``httpx.AsyncHTTPTransport``
            by default).
    """

    def __init__(self, *, account: Any, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self._account = account
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # As PaymentTransport: an async streaming body passes through unbuffered and
        # can't be sent again, so its 402 is returned unsigned.
        replayable = not (
            isinstance(request.stream, httpx.AsyncByteStream)
            and not isinstance(request.stream, httpx.SyncByteStream)
        )
        request.extensions.setdefault(_SIWX_ORIGIN_EXTENSION, _origin_of(str(request.url)))
        # Keep a replayable body so it can be sent again with the proof.
        body = await request.aread() if replayable else b""
        response = await self._inner.handle_async_request(request)
        if (
            not replayable
            or response.status_code != 402
            or HEADER in request.headers
            or not callable(getattr(self._account, "sign_message", None))
        ):
            return response
        extension = _offered(response)
        if extension is None:
            return response
        chain = next(
            (
                entry
                for entry in extension["supportedChains"]
                if entry["chainId"].startswith("eip155:") and entry["type"] == "eip191"
            ),
            None,
        )
        if chain is None:
            return response

        # As PaymentTransport: httpx carries a request's extensions across redirects, so
        # a hop to another origin than the first request's is never signed for.
        if request.extensions.get(_SIWX_ORIGIN_EXTENSION) != _origin_of(str(request.url)):
            return response
        payment_origin = request.extensions.get(_PAYMENT_ORIGIN_EXTENSION)
        if payment_origin is not None and payment_origin != _transport_origin(request.url):
            return response

        # A challenge naming another site must never get this wallet's signature.
        target = _url(str(request.url))
        info = extension["info"]
        if target is None or info["domain"] != target[0] or _origin_of(info["uri"]) != target[1]:
            return response

        unsigned: dict[str, Any] = {
            **info,
            "address": self._account.address,
            "chainId": chain["chainId"],
            "type": chain["type"],
        }
        if scheme := chain.get("signatureScheme"):
            unsigned["signatureScheme"] = scheme
        try:
            message = to_message(unsigned)
        except (InvalidProofError, ValueError):
            return response
        signature = _sign(self._account, message)
        headers = httpx.Headers(request.headers)
        headers[HEADER] = encode({**unsigned, "signature": signature})
        retry = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=body,
            extensions=request.extensions,
        )
        await response.aclose()
        return await self._inner.handle_async_request(retry)

    async def aclose(self) -> None:
        await self._inner.aclose()


def _offered(response: httpx.Response) -> Extension | None:
    value = response.headers.get(PAYMENT_REQUIRED_HEADER)
    if not value:
        return None
    try:
        payment_required = decode_payment_required(value)
    except ValueError:
        return None
    return from_payment_required(cast(Mapping[str, Any], payment_required))


def _sign(account: Any, message: str) -> str:
    from eth_account.messages import encode_defunct

    signed = account.sign_message(encode_defunct(text=message))
    signature: Any = signed.signature
    hex_value = signature.hex() if isinstance(signature, bytes | bytearray) else str(signature)
    return hex_value if hex_value.startswith("0x") else f"0x{hex_value}"
