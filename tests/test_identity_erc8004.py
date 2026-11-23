"""ERC-8004 agent identity (mppx `extensions/identity/erc8004`)."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest
from eth_account import Account
from eth_hash.auto import keccak

from mpp import Challenge, Credential
from mpp.extensions.identity import erc8004
from mpp.extensions.identity.erc8004 import IDENTITY_REGISTRY, Agent, AgentRef, message
from mpp.identity import REQUEST_HEADERS, PaymentCheckInput, ProveContext, Rejected, Valid
from mpp.server.http import Request
from mpp.store import MemoryStore

ORIGIN = "https://api.example"
URL = f"{ORIGIN}/haiku?q=1"
AGENT_KEY = Account.from_key("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")
OTHER_KEY = Account.from_key("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a")
CONTRACT_WALLET = "0x3333333333333333333333333333333333333333"
ZERO = "0x" + "0" * 40
GET_AGENT_WALLET = "0x" + keccak(b"getAgentWallet(uint256)")[:4].hex()
IS_VALID_SIGNATURE = "0x" + keccak(b"isValidSignature(bytes32,bytes)")[:4].hex()


class Registry:
    """A stand-in for the Identity Registry: agent 1's wallet is AGENT_KEY, agent 2 has none,
    agent 3 is a contract wallet."""

    def __init__(self, *, down: bool = False, erc1271: bool = False) -> None:
        self.down = down
        self.erc1271 = erc1271
        self.calls = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["method"] == "eth_call"
        if self.down:
            return httpx.Response(503)
        self.calls += 1
        call = body["params"][0]
        data: str = call["data"]
        to: str = call["to"]
        if data.startswith(GET_AGENT_WALLET) and to.lower() == IDENTITY_REGISTRY.lower():
            agent_id = int(data[10:], 16)
            wallet = {1: AGENT_KEY.address, 3: CONTRACT_WALLET}.get(agent_id, ZERO)
            result = "0x" + "0" * 24 + wallet[2:].lower()
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})
        if data.startswith(IS_VALID_SIGNATURE) and self.erc1271 and to == CONTRACT_WALLET:
            result = "0x1626ba7e" + "0" * 56
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "reverted"}}
        )

    def http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))


def setup(registry: Registry | None = None, **options: Any) -> erc8004.server.Erc8004:
    return erc8004.server.create(
        store=MemoryStore(), http=(registry or Registry()).http(), **options
    )


async def signed(account: Any = AGENT_KEY, agent_id: int = 1, method: str = "GET") -> Request:
    """A request to URL signed by the client prover, as the server sees it."""
    prover = erc8004.client.prover(account=account, agent_id=agent_id, scope=[ORIGIN])
    proved = await prover.prove(httpx.Request(method, URL), ProveContext.new())
    headers = {name: proved.headers[name] for name in ("agent-id", "agent-signature")}
    return Request(method, URL, headers)


def agent_id(number: int) -> str:
    return AgentRef(4217, IDENTITY_REGISTRY, number).format()


def payment(request: Request, payer: str, *, intent: str = "charge", type: str | None = None):
    challenge = Challenge(id="c1", realm="api.example", method="tempo", intent=intent, request={})
    payload = {} if type is None else {"type": type}
    credential = Credential(
        challenge=challenge.to_echo(), payload=payload, source=f"did:pkh:eip155:4217:{payer}"
    )
    return PaymentCheckInput(request=request, challenge=challenge, credential=credential)


def rejected(outcome: Any) -> Rejected:
    assert isinstance(outcome, Rejected), outcome
    return outcome


def test_formats_and_parses_agent_ids() -> None:
    assert agent_id(42) == "eip155:4217:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42"
    lower = "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42"
    parsed = AgentRef.parse(lower)
    assert parsed is not None and parsed.format() == agent_id(42)
    for malformed in (
        "",
        "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432",
        "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42:1",
        "eip155:4217:0x8004:42",
        "cosmos:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42",
        "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:" + "9" * 78,
    ):
        assert AgentRef.parse(malformed) is None, malformed
    assert message(id="a", method="GET", url=URL, created=10, nonce="n") == (
        f"mppx:erc8004\na\nGET {URL}\n10\nn"
    )
    assert erc8004.target("https://api.example") == "https://api.example/"
    assert erc8004.target("https://api.example:443/x?") == "https://api.example/x"


def test_marks_the_agent_headers_as_bearer_identity_headers() -> None:
    assert "agent-id" in REQUEST_HEADERS
    assert "agent-signature" in REQUEST_HEADERS


def test_advertises_erc8004_and_needs_an_rpc_off_tempo_mainnet() -> None:
    assert setup().payment_check.requires[0].type == "erc8004"
    with pytest.raises(ValueError):
        erc8004.server.create(chain_id=1)
    with pytest.raises(ValueError):
        erc8004.server.create(registry="nope")
    erc8004.server.create(chain_id=1, rpc_url="http://localhost:8545")


async def test_an_agent_signs_and_pays_from_its_registered_wallet() -> None:
    registry = Registry()
    agents = setup(registry)
    request = await signed()
    expected = Agent(id=agent_id(1), agent_id=1, wallet=AGENT_KEY.address)
    assert await agents.verifier.verify(request) == Valid(expected)
    outcome = await agents.payment_check.verify(
        payment(request, AGENT_KEY.address, type="transaction")
    )
    assert outcome == Valid(expected)
    # The verifier and the payment check share one registry lookup.
    assert registry.calls == 1


async def test_a_tempo_transaction_from_the_wallet_proves_the_agent_without_a_signature() -> None:
    agents = setup()
    request = Request("GET", URL, {"Agent-Id": agent_id(1)})
    outcome = await agents.payment_check.verify(payment(request, AGENT_KEY.address, type="proof"))
    assert isinstance(outcome, Valid)


async def test_rejects_a_request_without_an_agent() -> None:
    outcome = rejected(await setup().verifier.verify(Request("GET", URL)))
    assert outcome.status == "missing"


async def test_rejects_a_signature_from_a_key_other_than_the_wallet() -> None:
    outcome = rejected(await setup().verifier.verify(await signed(OTHER_KEY)))
    assert (outcome.status, outcome.reason) == (
        "invalid",
        "The agent's wallet did not sign the request.",
    )


async def test_rejects_a_signature_for_another_request() -> None:
    request = await signed()
    moved = Request("POST", URL, dict(request.headers))
    outcome = rejected(await setup().verifier.verify(moved))
    assert outcome.reason == "The agent's wallet did not sign the request."


async def test_rejects_a_payment_from_an_account_other_than_the_wallet() -> None:
    agents = setup()
    check = payment(await signed(), OTHER_KEY.address, type="transaction")
    outcome = rejected(await agents.payment_check.verify(check))
    assert (outcome.status, outcome.reason) == (
        "forbidden",
        "The payment is not from the agent's wallet.",
    )


async def test_rejects_an_agent_without_a_wallet() -> None:
    outcome = rejected(await setup().verifier.verify(await signed(agent_id=2)))
    assert outcome.status == "forbidden"


async def test_rejects_an_agent_in_another_registry() -> None:
    request = Request("GET", URL, {"Agent-Id": f"eip155:1:{IDENTITY_REGISTRY}:1"})
    outcome = rejected(await setup().verifier.verify(request))
    assert outcome.status == "invalid"


async def test_accepts_an_erc1271_wallet_that_approves_the_signature() -> None:
    agents = setup(Registry(erc1271=True))
    outcome = await agents.verifier.verify(await signed(agent_id=3))
    assert isinstance(outcome, Valid) and outcome.value.wallet == CONTRACT_WALLET


async def test_rejects_a_replayed_signature() -> None:
    agents = setup()
    first = await signed()
    assert isinstance(await agents.verifier.verify(first), Valid)
    replay = Request("GET", URL, dict(first.headers))
    outcome = rejected(await agents.verifier.verify(replay))
    assert outcome.status == "invalid" and "already used" in outcome.reason


async def test_rejects_an_expired_or_malformed_signature() -> None:
    agents = setup()
    stale = f"{int(time.time()) - 400}.n.0x00"
    for value in (stale, "", "1.2", "x.n.0x00", "1.n.zz", "1..0x00", "1.n.0x0.extra"):
        request = Request("GET", URL, {"Agent-Id": agent_id(1), "Agent-Signature": value})
        assert rejected(await agents.verifier.verify(request)).status == "invalid", value


async def test_answers_503_when_the_registry_is_unavailable() -> None:
    outcome = rejected(await setup(Registry(down=True)).verifier.verify(await signed()))
    assert outcome.status == "unavailable"


async def test_answers_503_when_the_replay_store_fails() -> None:
    class Broken(MemoryStore):
        async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
            raise RuntimeError("down")

    agents = erc8004.server.create(store=Broken(), http=Registry().http())
    outcome = rejected(await agents.verifier.verify(await signed()))
    assert outcome.status == "unavailable"


async def test_allow_decides_by_agent() -> None:
    async def allow(agent: Agent) -> bool:
        return agent.agent_id != 1

    outcome = rejected(await setup(allow=allow).verifier.verify(await signed()))
    assert outcome.status == "forbidden"


@pytest.mark.parametrize(
    ("intent", "type"),
    [("session", "topUp"), ("charge", "hash"), ("charge", "zone"), ("charge", None)],
)
async def test_needs_the_agents_signature_when_the_payment_does_not_bind_its_source(
    intent: str, type: str | None
) -> None:
    agents = setup()
    request = Request("GET", URL, {"Agent-Id": agent_id(1)})
    check = payment(request, AGENT_KEY.address, intent=intent, type=type)
    assert rejected(await agents.payment_check.verify(check)).status == "invalid"


async def test_the_prover_runs_only_in_scope() -> None:
    prover = erc8004.client.prover(account=AGENT_KEY, agent_id=1, scope=[ORIGIN])
    assert prover.covers(URL)
    assert not prover.covers("https://other.example/")


# --- Revisions ------------------------------------------------------------------------------------


@pytest.mark.parametrize("parsed", [True, False])
async def test_reads_the_payment_kind_from_a_parsed_charge_payload(parsed: bool) -> None:
    from mpp.methods.tempo.schemas import ChargePayload, TransactionCredentialPayload

    wire = {"type": "transaction", "signature": "0x00"}
    # A route hands payment checks the parsed payload, not the wire dict.
    model: Any = (
        ChargePayload.model_validate(wire)
        if parsed
        else TransactionCredentialPayload.model_validate(wire)
    )
    agents = setup()
    request = Request("GET", URL, {"Agent-Id": agent_id(1)})
    check = payment(request, AGENT_KEY.address)
    wallet = PaymentCheckInput(
        request=request,
        challenge=check.challenge,
        credential=Credential(
            challenge=check.credential.challenge, payload=model, source=check.credential.source
        ),
    )
    assert isinstance(await agents.payment_check.verify(wallet), Valid)
    other = Credential(
        challenge=check.credential.challenge,
        payload=model,
        source=f"did:pkh:eip155:4217:{OTHER_KEY.address}",
    )
    signed_request = await signed()
    outcome = rejected(
        await agents.payment_check.verify(
            PaymentCheckInput(request=signed_request, challenge=check.challenge, credential=other)
        )
    )
    assert outcome.status == "forbidden"


async def test_a_route_accepts_a_wallet_transaction_without_a_signature() -> None:
    from mpp import Receipt
    from mpp.identity import Route
    from mpp.methods.tempo.schemas import charge
    from mpp.server import Mpp, PaymentVerified, ServerMethod, VerifyContext
    from tests import challenges, http_request

    settled: list[str] = []

    async def settle(context: VerifyContext) -> Receipt:
        settled.append(type(context.credential.payload).__name__)
        return Receipt.success("tx")

    method = ServerMethod(
        method=charge,
        defaults={
            "amount": "1",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x1111111111111111111111111111111111111111",
        },
        verify=settle,
    )
    agents = setup()
    mpp = Mpp(methods=[method], realm="api.example", secret_key="secret")
    handler = mpp.charge(identity=Route(payment=agents.payment_check))
    [issued] = challenges(await handler(http_request()))

    def paid(payer: str) -> Request:
        credential = Credential(
            challenge=issued.to_echo(),
            payload={"type": "transaction", "signature": "0x00"},
            source=f"did:pkh:eip155:4217:{payer}",
        )
        return http_request(credential.to_authorization(), headers={"Agent-Id": agent_id(1)})

    assert isinstance(await handler(paid(AGENT_KEY.address)), PaymentVerified)
    assert settled == ["ChargePayload"]
    assert not isinstance(await handler(paid(OTHER_KEY.address)), PaymentVerified)
    assert len(settled) == 1


def test_an_empty_rpc_url_does_not_fall_back_to_tempo_mainnet() -> None:
    with pytest.raises(ValueError):
        erc8004.server.create(chain_id=1, rpc_url="")


async def test_holds_a_nonce_claim_past_the_signatures_last_accepted_second() -> None:
    claims: list[float] = []

    class Recording(MemoryStore):
        async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
            claims.append(expires_at)
            return await super().put_if_absent_until(key, value, expires_at)

    agents = erc8004.server.create(store=Recording(), http=Registry().http())
    request = await signed()
    assert isinstance(await agents.verifier.verify(request), Valid)
    created = int(request.headers["agent-signature"].split(".")[0])
    last_accepted = created + erc8004.MAX_AGE + erc8004.CLOCK_TOLERANCE
    assert claims == [last_accepted + 1 + 300]


async def test_answers_503_when_an_erc1271_wallet_cannot_be_checked() -> None:
    class Flaky(Registry):
        def handle(self, request: httpx.Request) -> httpx.Response:
            if json.loads(request.content)["params"][0]["to"] == CONTRACT_WALLET:
                return httpx.Response(503)
            return super().handle(request)

    outcome = rejected(await setup(Flaky()).verifier.verify(await signed(agent_id=3)))
    assert (outcome.status, outcome.reason) == (
        "unavailable",
        "The Identity Registry is unavailable.",
    )
    # A wallet that reverts did not sign.
    reverted = rejected(await setup().verifier.verify(await signed(agent_id=3)))
    assert reverted.status == "invalid"


class _DecodedPathRequest:
    """A framework request as Starlette before 1.x exposes it: ``url`` rebuilt from the
    decoded path, so an encoded "#" in the path puts the query inside a fragment."""

    method = "GET"

    def __init__(self, raw_path: bytes, query: bytes, headers: dict[str, str]) -> None:
        path = raw_path.decode().replace("%23", "#")
        self.url = f"{ORIGIN}{path}?{query.decode()}" if query else f"{ORIGIN}{path}"
        self.headers = headers
        self.scope = {"type": "http", "path": path, "raw_path": raw_path, "query_string": query}


async def _prove(url: str) -> dict[str, str]:
    prover = erc8004.client.prover(account=AGENT_KEY, agent_id=1, scope=[ORIGIN])
    proved = await prover.prove(httpx.Request("GET", url), ProveContext.new())
    return {name: proved.headers[name] for name in ("agent-id", "agent-signature")}


async def test_binds_the_query_on_an_encoded_hash_path_from_a_framework_request() -> None:
    from mpp.server.decorator import to_request

    agents = setup()
    signed_url = f"{ORIGIN}/notes/a%23b?q=1"
    framework = _DecodedPathRequest(b"/notes/a%23b", b"q=1", await _prove(signed_url))
    request = await to_request(framework, read_body=False)
    assert str(request.url) == signed_url
    assert isinstance(await agents.verifier.verify(request), Valid)

    # A proof signed without the query does not verify for a request that has one.
    queryless = await _prove(f"{ORIGIN}/notes/a%23b")
    framework = _DecodedPathRequest(b"/notes/a%23b", b"q=1", queryless)
    outcome = await agents.verifier.verify(await to_request(framework, read_body=False))
    assert isinstance(outcome, Rejected)
