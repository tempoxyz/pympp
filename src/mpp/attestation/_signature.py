"""RFC 9421 HTTP message signatures over the narrow request profile TAP and Web Bot Auth use."""

from __future__ import annotations

import inspect
import re
import time
import weakref
from collections.abc import Awaitable, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

import httpx

from mpp.attestation import (
    ED25519,
    RSA_PSS_SHA512,
    SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
    Absent,
    Invalid,
    KeyLookup,
    KeyResolver,
    SignatureAlgorithm,
    SigningContext,
    Unverified,
    Verified,
)
from mpp.store import ExpiringStore, Store

try:
    import http_sf
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
    from http_sf.innerlist import ser_innerlist
    from http_sf.item import ser_item
    from http_sf.parameters import ser_params
except ImportError as error:
    raise ImportError(
        f"{error}. Request attestation requires: pip install pympp[attestation]"
    ) from error

if TYPE_CHECKING:
    from mpp.server.http import Request

AUTHORITY = "@authority"
"""Derived component: the target host and non-default port."""
PATH = "@path"
"""Derived component: the request URL path without its query string."""
SIGNATURE_AGENT = "signature-agent"
"""The lowercased ``Signature-Agent`` request header."""
SIGNATURE_PARAMS = "@signature-params"

PrivateKey = Ed25519PrivateKey | RSAPrivateKey
"""An Ed25519 private key, or an RSA one signing with RSASSA-PSS SHA-512."""

CLOCK_SKEW = 5
"""Seconds a signature's ``created`` may run ahead of this server's clock."""

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64)
_ASCII = re.compile(r"[\x20-\x7e]*")


@dataclass(frozen=True, slots=True)
class Component:
    """A covered component: a derived identifier or lowercased field name, with parameters."""

    id: str
    parameters: dict[str, Any] = field(default_factory=dict[str, Any])


@dataclass(frozen=True, slots=True)
class SignatureInput:
    """One parsed or emitted ``Signature-Input`` member."""

    algorithm: SignatureAlgorithm
    components: tuple[Component, ...]
    created: int
    expires: int
    key_id: str
    label: str
    nonce: str
    parameters: dict[str, Any]
    tag: str


Validate = Callable[[SignatureInput, "Request"], "str | None"]
ValidateKey = Callable[[Any, SignatureInput, "Request"], "str | None"]


async def sign(
    request: httpx.Request,
    *,
    components: Sequence[str | Component],
    key: PrivateKey,
    key_id: str,
    label: str,
    tag: str,
    expires_in: int = 60,
    context: SigningContext | None = None,
) -> httpx.Request:
    """Return a copy of ``request`` with ``label`` added to its signature dictionaries."""
    context = context or SigningContext.create()
    if isinstance(key, Ed25519PrivateKey):
        algorithm: SignatureAlgorithm = ED25519
    elif isinstance(key, RSAPrivateKey):
        algorithm = RSA_PSS_SHA512
    else:
        raise TypeError("Request attestation requires an Ed25519 or RSA-PSS SHA-512 signing key.")
    expires = context.created + expires_in
    signature_input = SignatureInput(
        algorithm=algorithm,
        components=tuple(Component(c) if isinstance(c, str) else c for c in components),
        created=context.created,
        expires=expires,
        key_id=key_id,
        label=label,
        nonce=context.nonce,
        parameters={
            "created": context.created,
            "expires": expires,
            "keyid": key_id,
            "alg": algorithm,
            "nonce": context.nonce,
            "tag": tag,
        },
        tag=tag,
    )
    base = _signature_base(request.url, request.headers, signature_input).encode()
    if isinstance(key, Ed25519PrivateKey):
        signature = key.sign(base)
    else:
        signature = key.sign(base, _PSS, hashes.SHA512())

    inputs = parse_dictionary_header(request.headers, SIGNATURE_INPUT_HEADER)
    signatures = parse_dictionary_header(request.headers, SIGNATURE_HEADER)
    if inputs.keys() != signatures.keys():
        raise ValueError("Signature-Input and Signature must contain the same labels.")
    if label in inputs:
        raise ValueError(f'HTTP message signature label "{label}" already exists.')
    inputs[label] = _inner_list(signature_input)
    signatures[label] = (signature, {})
    headers = httpx.Headers(request.headers)
    headers[SIGNATURE_INPUT_HEADER] = http_sf.ser(inputs)
    headers[SIGNATURE_HEADER] = http_sf.ser(signatures)
    return with_headers(request, headers)


async def verify(
    request: Request,
    *,
    key_resolver: KeyResolver,
    max_age: int,
    nonce_namespace: str,
    nonce_store: ExpiringStore,
    required_components: Collection[str],
    tag: Collection[str],
    validate: Validate | None = None,
    validate_key: ValidateKey | None = None,
) -> Absent | Invalid | Unverified | Verified[SignatureInput]:
    """Verify a request signature, its lifetime, and its single-use nonce."""
    parsed = _parse(request.headers, tag)
    if parsed is None:
        return Absent()
    if isinstance(parsed, str):
        return Invalid(parsed)
    signature_input, signature = parsed

    ids = {component.id for component in signature_input.components}
    if not all(component in ids for component in required_components):
        return Invalid("The signature does not cover the required request components.")
    now = int(time.time())
    if (
        signature_input.created > now + CLOCK_SKEW
        or signature_input.expires <= now
        or signature_input.expires - signature_input.created > max_age
    ):
        return Invalid("The signature is expired or has an invalid lifetime.")
    if validate and (reason := validate(signature_input, request)):
        return Invalid(reason)
    lookup = KeyLookup(
        algorithm=signature_input.algorithm, key_id=signature_input.key_id, request=request
    )
    try:
        key = key_resolver(lookup)
        if inspect.isawaitable(key):
            key = await cast(Awaitable[Any], key)
    except Exception:
        return Unverified("The public key could not be resolved.")
    if key is None:
        return Unverified("No public key is available for the signature key ID.")
    expected = Ed25519PublicKey if signature_input.algorithm == ED25519 else RSAPublicKey
    if not isinstance(key, expected):
        return Invalid("The public key does not support the signature algorithm.")
    if validate_key and (reason := validate_key(key, signature_input, request)):
        return Invalid(reason)
    try:
        base = _signature_base(request.url, request.headers, signature_input).encode()
        if isinstance(key, Ed25519PublicKey):
            key.verify(signature, base)
        else:
            key.verify(signature, base, _PSS, hashes.SHA512())
    except Exception:
        return Invalid("The HTTP message signature is invalid.")
    key_name = f"{nonce_namespace}:{signature_input.key_id}:{signature_input.nonce}"
    claims = _request_claims(request)
    claim = (id(nonce_store), key_name)
    if claim not in claims:
        try:
            claimed = await _try_claim(nonce_store, key_name, signature_input.expires)
        except Exception:
            return Unverified("Replay protection is unavailable.")
        if not claimed:
            return Invalid("The signature nonce has already been used.")
        claims.add(claim)
    if signature_input.expires <= int(time.time()):
        return Invalid("The signature has expired.")
    return Verified(signature_input)


def parse_dictionary_header(headers: httpx.Headers, name: str) -> dict[str, Any]:
    """Parse a structured dictionary header, or raise ``ValueError`` when it is malformed."""
    value = headers.get(name)
    if not value:
        return {}
    try:
        return cast(dict[str, Any], http_sf.parse(value.encode(), tltype="dictionary"))
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError(f'HTTP header "{name}" is not a structured dictionary.') from error


def with_headers(request: httpx.Request, headers: httpx.Headers) -> httpx.Request:
    """Return a copy of ``request`` with ``headers``, sharing its body stream."""
    return httpx.Request(
        request.method,
        request.url,
        headers=headers,
        stream=request.stream,
        extensions=request.extensions,
    )


def require_expiring_store(store: Store) -> None:
    """Raise unless ``store`` can claim nonces only until their signature expires."""
    if not isinstance(store, ExpiringStore):
        raise TypeError(
            "Request attestation requires a nonce_store implementing put_if_absent_until."
        )


_claims: dict[int, set[tuple[int, str]]] = {}


def _request_claims(request: Request) -> set[tuple[int, str]]:
    """Nonces this request object already claimed, so other verifiers sharing a store accept it."""
    key = id(request)
    if (claims := _claims.get(key)) is None:
        claims = _claims[key] = set()
        weakref.finalize(request, _claims.pop, key, None)
    return claims


async def _try_claim(store: ExpiringStore, key: str, expires: int) -> bool:
    if expires <= time.time():
        return False
    return await store.put_if_absent_until(key, "1", expires)


def _parse(
    headers: httpx.Headers, tags: Collection[str]
) -> tuple[SignatureInput, bytes] | str | None:
    input_header = headers.get(SIGNATURE_INPUT_HEADER)
    signature_header = headers.get(SIGNATURE_HEADER)
    if not input_header and not signature_header:
        return None
    if not input_header or not signature_header:
        return "Signature-Input and Signature must both be provided."
    try:
        inputs = parse_dictionary_header(headers, SIGNATURE_INPUT_HEADER)
        signatures = parse_dictionary_header(headers, SIGNATURE_HEADER)
    except ValueError:
        return "The HTTP message signature is malformed."
    if inputs.keys() != signatures.keys():
        return "Signature-Input and Signature do not contain the same labels."
    for label, entry in inputs.items():
        if not isinstance(entry[0], list) or entry[1].get("tag") not in tags:
            continue
        signature_input = _signature_input(label, entry)
        if signature_input is None:
            return "The HTTP message signature is malformed."
        signature = signatures[label][0]
        if type(signature) is not bytes:
            return "No matching HTTP message signature was provided."
        return signature_input, signature
    return None


def _signature_input(label: str, entry: tuple[list[Any], dict[str, Any]]) -> SignatureInput | None:
    items, parameters = entry
    if not items or not all(type(item[0]) is str for item in items):
        return None
    created = _integer(parameters.get("created"))
    expires = _integer(parameters.get("expires"))
    algorithm = parameters.get("alg")
    key_id = parameters.get("keyid")
    nonce = parameters.get("nonce")
    tag = parameters.get("tag")
    if (
        created is None
        or expires is None
        or algorithm not in (ED25519, RSA_PSS_SHA512)
        or type(key_id) is not str
        or type(nonce) is not str
        or type(tag) is not str
    ):
        return None
    return SignatureInput(
        algorithm=algorithm,
        components=tuple(Component(item[0], dict(item[1])) for item in items),
        created=created,
        expires=expires,
        key_id=key_id,
        label=label,
        nonce=nonce,
        parameters=parameters,
        tag=tag,
    )


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value) if value == int(value) else None


def _inner_list(signature_input: SignatureInput) -> tuple[list[Any], dict[str, Any]]:
    return (
        [(component.id, dict(component.parameters)) for component in signature_input.components],
        dict(signature_input.parameters),
    )


def _signature_base(
    url: httpx.URL | str, headers: httpx.Headers, signature_input: SignatureInput
) -> str:
    lines = [
        f"{_serialize_component(component)}: {_component_value(url, headers, component)}"
        for component in signature_input.components
    ]
    params = ser_innerlist(_inner_list(signature_input))
    lines.append(f'"{SIGNATURE_PARAMS}": {params}')
    return "\n".join(lines)


def _serialize_component(component: Component) -> str:
    return f'"{component.id}"{ser_params(component.parameters)}'


def _component_value(url: httpx.URL | str, headers: httpx.Headers, component: Component) -> str:
    if component.id in (AUTHORITY, PATH):
        if component.parameters:
            raise ValueError(f'Unsupported parameters for "{component.id}".')
        parsed = httpx.URL(str(url))
        if component.id == AUTHORITY:
            return parsed.netloc.decode("ascii")
        return parsed.raw_path.decode("ascii").split("?", 1)[0]
    if component.parameters:
        return _dictionary_member(headers, component.id, component.parameters)
    value = headers.get(component.id)
    if value is None:
        raise ValueError(f'Missing signed HTTP header "{component.id}".')
    if not _ASCII.fullmatch(value):
        raise ValueError(f'Signed HTTP header "{component.id}" is not ASCII.')
    return value


def _dictionary_member(headers: httpx.Headers, name: str, parameters: Mapping[str, Any]) -> str:
    key = parameters.get("key")
    if type(key) is not str or len(parameters) != 1:
        raise ValueError(f'Unsupported parameters for signed HTTP header "{name}".')
    if headers.get(name) is None:
        raise ValueError(f'Missing signed HTTP header "{name}".')
    member = parse_dictionary_header(headers, name).get(key)
    if member is None or isinstance(member[0], list):
        raise ValueError(f'Signed HTTP header "{name}" has no member "{key}".')
    return ser_item(member)
