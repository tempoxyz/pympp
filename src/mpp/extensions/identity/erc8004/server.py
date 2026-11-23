"""ERC-8004 agents on the server: a verifier and a payment check (mppx `Erc8004.Server`)."""

from __future__ import annotations

import inspect
import re
import time
import weakref
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from pydantic import BaseModel, RootModel

from mpp._did import parse_pkh_source
from mpp.extensions.identity.erc8004 import (
    CHAIN_ID,
    CLOCK_TOLERANCE,
    ID_HEADER,
    IDENTITY_REGISTRY,
    MAX_AGE,
    RPC_URL,
    SIGNATURE_HEADER,
    TYPE,
    Agent,
    AgentRef,
    checksum,
    message,
)
from mpp.identity import (
    PaymentCheck,
    PaymentCheckInput,
    Rejected,
    Requirement,
    Valid,
    Verification,
    Verifier,
    forbidden,
    invalid,
    missing,
    unavailable,
)

if TYPE_CHECKING:
    from mpp.server.http import Request
    from mpp.store import ExpiringStore

Allow = Callable[[Agent], bool | Awaitable[bool]]
"""Decides whether a verified agent may call the API, such as by its ID or reputation."""

_GET_AGENT_WALLET = keccak(b"getAgentWallet(uint256)")[:4]
_IS_VALID_SIGNATURE = keccak(b"isValidSignature(bytes32,bytes)")[:4]
_ERC1271_MAGIC = bytes.fromhex("1626ba7e")
_ZERO_ADDRESS = "0x" + "0" * 40
_CREATED_RE = re.compile(r"\d{1,12}")
_SIGNATURE_RE = re.compile(r"0x[0-9a-fA-F]+")
# Seconds a nonce claim outlives the signature's last accepted second, so a verifier whose
# clock runs behind the store's still finds the claim (as Tempo proof claims do).
_CLAIM_GRACE = 300


@dataclass(frozen=True, slots=True)
class Erc8004:
    """An ERC-8004 agent verifier from :func:`create`.

    - ``verifier``: requires a request signed by the agent's wallet, before any 402.
    - ``payment_check``: requires that the agent's wallet paid.
    """

    verifier: Verifier[Agent]
    payment_check: PaymentCheck[Agent]


class RegistryError(Exception):
    """The registry's chain could not answer a call."""


class _Reverted(RegistryError):
    """The chain answered: the call reverted."""


def create(
    *,
    store: ExpiringStore | None = None,
    chain_id: int = CHAIN_ID,
    registry: str = IDENTITY_REGISTRY,
    rpc_url: str | None = None,
    http: httpx.AsyncClient | None = None,
    allow: Allow | None = None,
) -> Erc8004:
    """Create an ERC-8004 agent verifier and payment check for one API.

    - The verifier requires a request signed by the agent's wallet, as the Identity Registry's
      ``getAgentWallet`` names it: an EOA signature, or ERC-1271 for a contract or configurable
      account.
    - The payment check accepts a ``tempo`` charge the agent's wallet signed (a transaction or
      proof), so the payment itself proves the agent. For anything else (transaction hashes,
      sessions, Zones, other methods) it requires the signature.

    Args:
        store: Accepts each request signature once. Without it, a signature can be replayed for
            six minutes.
        chain_id: The registry's chain. Payments must settle on it too.
        registry: The Identity Registry.
        rpc_url: RPC URL of the registry's chain; required for a chain other than Tempo mainnet.
        http: Client used for RPC calls.
        allow: Decides whether a verified agent may call the API.

    Raises:
        ValueError: For a chain other than Tempo mainnet without ``rpc_url`` (or with an empty
            one), or a registry that is not an address.
    """
    if not rpc_url and chain_id != CHAIN_ID:
        raise ValueError("Pass rpc_url for a chain other than Tempo mainnet.")
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", registry) is None:
        raise ValueError("registry must be an address")
    rules = _Rules(
        chain_id=chain_id,
        registry=checksum(registry),
        rpc=_Rpc(rpc_url or RPC_URL, http),
        store=store,
    )
    # One lookup and one signature check per request, so the verifier and payment check share
    # them and spend a nonce once.
    lookups: _PerRequest = _PerRequest()
    signatures: _PerRequest = _PerRequest()

    async def lookup(request: Request) -> Verification[Agent]:
        outcome = lookups.get(request)
        if outcome is None:
            outcome = await rules.lookup(request)
            lookups.put(request, outcome)
        return outcome

    async def signed(request: Request) -> Verification[Agent]:
        outcome = signatures.get(request)
        if outcome is None:
            outcome = await lookup(request)
            if isinstance(outcome, Valid):
                outcome = await rules.verify_signature(request, outcome.value)
            signatures.put(request, outcome)
        return outcome

    async def allowed(outcome: Verification[Agent]) -> Verification[Agent]:
        if isinstance(outcome, Rejected) or allow is None:
            return outcome
        decision = allow(outcome.value)
        if inspect.isawaitable(decision):
            decision = await decision
        return outcome if decision else forbidden("This agent may not call this API.")

    async def verify_request(request: Request) -> Verification[Agent]:
        return await allowed(await signed(request))

    async def verify_payment(input: PaymentCheckInput) -> Verification[Agent]:
        # Only a tempo charge the source signed binds it to the payer: a transaction or a proof.
        # A hash credential doesn't (the charge can accept another sender), and neither do
        # sessions, Zones or other methods, so they need the agent's signature instead.
        kind = _payload_type(input.credential.payload)
        if (
            input.challenge.method != "tempo"
            or input.challenge.intent != "charge"
            or kind not in ("transaction", "proof")
        ):
            return await allowed(await signed(input.request))
        outcome = await lookup(input.request)
        if isinstance(outcome, Rejected):
            return outcome
        source = parse_pkh_source(input.credential.source or "")
        if source is None or source.chain_id != chain_id:
            return invalid(f"The payment must name its source account on chain {chain_id}.")
        if source.address.lower() != outcome.value.wallet.lower():
            return forbidden("The payment is not from the agent's wallet.")
        return await allowed(outcome)

    return Erc8004(
        verifier=Verifier(verify=verify_request),
        payment_check=PaymentCheck(requires=(Requirement(type=TYPE),), verify=verify_payment),
    )


def _payload_type(payload: object) -> object:
    """A credential payload's ``type``: a dict on the wire, a parsed model once a route verifies."""
    if isinstance(payload, RootModel):
        payload = cast("RootModel[object]", payload).root
    if isinstance(payload, BaseModel):
        return getattr(payload, "type", None)
    if isinstance(payload, dict):
        return cast("dict[str, object]", payload).get("type")
    return None


class _PerRequest:
    """Outcomes keyed by request object, dropped with the request."""

    def __init__(self) -> None:
        self._outcomes: dict[int, tuple[weakref.ref[Request], Verification[Agent]]] = {}

    def get(self, request: Request) -> Verification[Agent] | None:
        entry = self._outcomes.get(id(request))
        return entry[1] if entry is not None and entry[0]() is request else None

    def put(self, request: Request, outcome: Verification[Agent]) -> None:
        key = id(request)
        reference = weakref.ref(request, lambda _: self._outcomes.pop(key, None))
        self._outcomes[key] = (reference, outcome)


@dataclass(frozen=True, slots=True)
class _Rpc:
    """Read-only ``eth_call``s to the registry's chain."""

    url: str
    http: httpx.AsyncClient | None

    async def call(self, to: str, data: bytes) -> bytes:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": to, "data": "0x" + data.hex()}, "latest"],
        }
        try:
            if self.http is not None:
                response = await self.http.post(self.url, json=body)
            else:
                async with httpx.AsyncClient(timeout=10) as http:
                    response = await http.post(self.url, json=body)
            response.raise_for_status()
            answer: Any = response.json()
            error: Any = answer.get("error")
            if isinstance(error, dict) and _is_revert(cast("dict[str, Any]", error)):
                raise _Reverted("reverted")
            result: Any = answer.get("result")
            if not isinstance(result, str) or not result.startswith("0x"):
                raise RegistryError("no result")
            return bytes.fromhex(result[2:])
        except (httpx.HTTPError, ValueError, AttributeError) as error:
            raise RegistryError(str(type(error).__name__)) from error


@dataclass(frozen=True, slots=True)
class _Rules:
    """How one API verifies ERC-8004 agents."""

    chain_id: int
    registry: str
    rpc: _Rpc
    store: ExpiringStore | None

    async def lookup(self, request: Request) -> Verification[Agent]:
        """Read the request's agent and its wallet from the registry."""
        value = request.headers.get(ID_HEADER)
        if not value:
            return missing("Sign the request as an ERC-8004 agent.")
        agent = AgentRef.parse(value)
        if agent is None or agent.chain_id != self.chain_id or agent.registry != self.registry:
            return invalid(
                f"The agent must be in the Identity Registry {self.registry} "
                f"on chain {self.chain_id}."
            )
        try:
            result = await self.rpc.call(
                self.registry, _GET_AGENT_WALLET + agent.agent_id.to_bytes(32, "big")
            )
        except RegistryError:
            return unavailable("The Identity Registry is unavailable.")
        if len(result) < 32:
            return unavailable("The Identity Registry is unavailable.")
        wallet = "0x" + result[12:32].hex()
        if wallet == _ZERO_ADDRESS:
            return forbidden("The agent has no wallet.")
        return Valid(Agent(id=agent.format(), agent_id=agent.agent_id, wallet=checksum(wallet)))

    async def verify_signature(self, request: Request, agent: Agent) -> Verification[Agent]:
        """Check that the agent's wallet signed this request."""
        parts = (request.headers.get(SIGNATURE_HEADER) or "").split(".")
        if (
            len(parts) != 3
            or _CREATED_RE.fullmatch(parts[0]) is None
            or not parts[1]
            or _SIGNATURE_RE.fullmatch(parts[2]) is None
        ):
            return invalid("The agent signature is missing or malformed.")
        created, nonce, signature = int(parts[0]), parts[1], parts[2]
        now = int(time.time())
        expires = created + MAX_AGE + CLOCK_TOLERANCE
        if created > now + CLOCK_TOLERANCE or expires < now:
            return invalid("The agent signature has expired.")
        text = message(
            id=request.headers.get(ID_HEADER) or "",
            method=request.method,
            url=request.url,
            created=created,
            nonce=nonce,
        )
        signed = await self._signed_by(agent.wallet, text, signature)
        if signed is None:
            return unavailable("The Identity Registry is unavailable.")
        if not signed:
            return invalid("The agent's wallet did not sign the request.")
        if self.store is not None:
            key = f"mppx:erc8004:nonce:0x{_hash_message(f'{agent.id}:{nonce}').hex()}"
            try:
                # Held past expiry: the signature still verifies through the whole second
                # `now == expires`, and on verifiers whose clocks run behind the store's.
                fresh = await self.store.put_if_absent_until(key, "1", expires + 1 + _CLAIM_GRACE)
            except Exception:
                return unavailable("The replay store is unavailable.")
            if not fresh:
                return invalid("The agent signature was already used.")
        return Valid(agent)

    async def _signed_by(self, wallet: str, text: str, signature: str) -> bool | None:
        """Whether ``wallet`` signed ``text``: by EOA recovery, else by ERC-1271.

        None when the chain could not answer the ERC-1271 call; a revert means not signed.
        """
        hex_signature = signature[2:]
        if len(hex_signature) % 2:
            return False
        raw = bytes.fromhex(hex_signature)
        try:
            recovered = Account.recover_message(encode_defunct(text=text), signature=raw)
        except Exception:
            recovered = None
        if recovered is not None and recovered.lower() == wallet.lower():
            return True
        try:
            result = await self.rpc.call(wallet, _IS_VALID_SIGNATURE + _encode_1271(text, raw))
        except _Reverted:
            return False
        except RegistryError:
            return None
        return result[:4] == _ERC1271_MAGIC


def _is_revert(error: dict[str, Any]) -> bool:
    """Whether a JSON-RPC error is the call reverting, not the node failing."""
    message = error.get("message")
    return error.get("code") == 3 or (isinstance(message, str) and "revert" in message.lower())


def _hash_message(text: str) -> bytes:
    """EIP-191 hash of a text message, as viem's ``hashMessage``."""
    data = text.encode()
    return keccak(b"\x19Ethereum Signed Message:\n" + str(len(data)).encode() + data)


def _encode_1271(text: str, signature: bytes) -> bytes:
    """ABI-encode ``isValidSignature(bytes32 hash, bytes signature)``'s arguments."""
    padded = signature + b"\x00" * (-len(signature) % 32)
    return (
        _hash_message(text) + (64).to_bytes(32, "big") + len(signature).to_bytes(32, "big") + padded
    )


__all__ = ["Allow", "Erc8004", "RegistryError", "create"]
