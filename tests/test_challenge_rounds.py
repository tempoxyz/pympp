"""New challenge rounds after a refused credential, over HTTP and MCP (mppx ``Fetch``).

A server offers a zero-amount Tempo proof (paid from prepaid credit) before the real
charge. A wallet without credit has its proof refused by a ``credit_insufficient`` 402
that offers only the real charge, under a new Challenge id: the client pays it as a new
round, bounded by its retry limit, with every selection check applied again.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import (
    Challenge,
    Credential,
    PaymentError,
    PaymentExpiredError,
    PaymentOutcomeUnknownError,
)
from mpp.client import Mpp, PaymentTransport
from mpp.methods.tempo import PATH_USD, TempoAccount
from mpp.methods.tempo._proof import proof_hash, recover_proof_signer
from mpp.methods.tempo.client import charge
from mpp.runtime import ClientMethod, CredentialParams

ACCOUNT = TempoAccount.from_key("0x" + "11" * 32)
CHAIN = 42431
REALM = "api.example.com"
URL = f"https://{REALM}/resource"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
PRICE = "10000"
CREDIT_INSUFFICIENT = {
    "type": "https://paymentauth.org/problems/credit_insufficient",
    "title": "Credit insufficient",
    "status": 402,
    "reason": "credit_insufficient",
}


def _expires() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")


def offer(
    challenge_id: str,
    amount: str = PRICE,
    *,
    realm: str = REALM,
    recipient: str = RECIPIENT,
    expires: str | None = None,
) -> Challenge:
    """A ``tempo/charge`` Challenge; amount ``"0"`` asks for a proof."""
    return Challenge(
        id=challenge_id,
        method="tempo",
        intent="charge",
        realm=realm,
        request={
            "amount": amount,
            "currency": PATH_USD,
            "recipient": recipient,
            "methodDetails": {"chainId": CHAIN},
        },
        expires=expires or _expires(),
    )


class Wallet:
    """The Tempo charge client method, recording every Challenge it signs.

    Zero-amount proofs are signed by the real method. A real charge would build a
    transaction over RPC, so it returns a placeholder credential instead; the method's
    challenge selection (amount caps, currency and recipient policy) is the real one.
    """

    def __init__(self, *, payload_type: str = "transaction", **policy: Any) -> None:
        self.signed: list[Challenge] = []
        real = charge(account=ACCOUNT, chain_id=CHAIN, currency=PATH_USD, **policy)

        async def create(params: CredentialParams) -> str:
            self.signed.append(params.challenge)
            if int(params.challenge.request["amount"]) == 0:
                return await real.create_credential(params)
            return Credential(
                challenge=params.challenge.to_echo(),
                payload={"type": payload_type, "signature": "0x76f8"},
                source=f"did:pkh:eip155:{CHAIN}:{ACCOUNT.address}",
            ).to_authorization()

        self.method = ClientMethod(
            method=real.method,
            create_credential=create,
            can_handle_challenge=real.can_handle_challenge,
        )

    @property
    def signed_ids(self) -> list[str]:
        return [challenge.id for challenge in self.signed]


Handler = Callable[[Credential | None, int], httpx.Response]


class Server:
    """A local payment server: ``handler`` answers each request's credential."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []
        self.credentials: list[Credential] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        authorization = request.headers.get("authorization")
        credential = None
        if authorization is not None:
            credential = Credential.from_authorization(authorization)
            self.credentials.append(credential)
        return self.handler(credential, len(self.requests))

    @property
    def paid_ids(self) -> list[str]:
        return [credential.challenge.id for credential in self.credentials]


def payment_required(
    *challenges: Challenge, problem: dict[str, Any] | None = None
) -> httpx.Response:
    headers = [("www-authenticate", c.to_www_authenticate(c.realm or REALM)) for c in challenges]
    if problem is None:
        return httpx.Response(402, headers=headers)
    headers.append(("content-type", "application/problem+json"))
    return httpx.Response(402, headers=headers, content=json.dumps(problem).encode())


def ok() -> httpx.Response:
    return httpx.Response(200, json={"data": "paid content"})


def proof_then_charge(
    *, credit: bool, refusal: Callable[[], httpx.Response] | None = None
) -> Handler:
    """Offer a proof, then the real charge; refuse the proof unless the wallet has credit."""

    def handle(credential: Credential | None, _: int) -> httpx.Response:
        if credential is None:
            return payment_required(offer("proof-1", "0"), offer("charge-1"))
        if credential.payload["type"] == "proof":
            if credit:
                return ok()
            if refusal is not None:
                return refusal()
            return payment_required(offer("charge-2"), problem=CREDIT_INSUFFICIENT)
        if credential.challenge.id == "charge-2":
            return ok()
        return payment_required(offer("charge-3"), problem=CREDIT_INSUFFICIENT)

    return handle


async def fetch(
    server: Server,
    wallet: Wallet,
    *,
    method: str = "GET",
    **options: Any,
) -> httpx.Response:
    request_options = {
        key: options.pop(key) for key in ("json", "headers", "params") if key in options
    }
    transport = PaymentTransport(
        methods=[wallet.method], inner=httpx.MockTransport(server), **options
    )
    async with httpx.AsyncClient(transport=transport) as client:
        return await client.request(method, URL, **request_options)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pays_real_charge_after_proof_refused_for_insufficient_credit() -> None:
    server = Server(proof_then_charge(credit=False))
    wallet = Wallet()

    response = await fetch(server, wallet)

    assert response.status_code == 200
    assert response.json() == {"data": "paid content"}
    # The proof first, as the server offers it, then the charge from the second 402.
    assert server.paid_ids == ["proof-1", "charge-2"]
    assert wallet.signed_ids == ["proof-1", "charge-2"]
    proof, payment = server.credentials
    assert proof.payload["type"] == "proof"
    digest = proof_hash(
        account=ACCOUNT.address, chain_id=CHAIN, challenge_id="proof-1", realm=REALM
    )
    signer = recover_proof_signer(
        proof.payload["signature"], account=ACCOUNT.address, digest=digest
    )
    assert signer is not None and signer.address == ACCOUNT.address
    assert payment.payload["type"] == "transaction"


@pytest.mark.asyncio
async def test_mpp_fetch_pays_real_charge_after_proof_refused() -> None:
    server = Server(proof_then_charge(credit=False))
    wallet = Wallet()

    async with Mpp(methods=[wallet.method]) as mpp:
        mpp.payment_transport._inner = httpx.MockTransport(server)
        response = await mpp.fetch(URL)

    assert response.status_code == 200
    assert server.paid_ids == ["proof-1", "charge-2"]


@pytest.mark.asyncio
async def test_wallet_with_credit_pays_only_the_proof() -> None:
    server = Server(proof_then_charge(credit=True))
    wallet = Wallet()

    response = await fetch(server, wallet)

    assert response.status_code == 200
    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_refusal_without_a_payable_challenge_is_final() -> None:
    server = Server(
        proof_then_charge(
            credit=False,
            refusal=lambda: httpx.Response(402, json=CREDIT_INSUFFICIENT),
        )
    )

    response = await fetch(server, Wallet())

    assert response.status_code == 402
    assert response.json()["reason"] == "credit_insufficient"
    assert server.paid_ids == ["proof-1"]
    assert len(server.requests) == 2


@pytest.mark.asyncio
async def test_refusal_offering_only_unpayable_challenges_is_final() -> None:
    other_method = Challenge(
        id="stripe-1", method="stripe", intent="charge", realm=REALM, request={"amount": "1"}
    )
    server = Server(
        proof_then_charge(
            credit=False,
            refusal=lambda: payment_required(other_method, problem=CREDIT_INSUFFICIENT),
        )
    )

    response = await fetch(server, Wallet())

    assert response.status_code == 402
    assert server.paid_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_pushed_payment_refused_is_not_paid_again() -> None:
    server = Server(lambda _, number: payment_required(offer(f"charge-{number}")))

    response = await fetch(server, Wallet(payload_type="hash"))

    # The payment is on chain: a second credential for the same request could pay twice.
    assert response.status_code == 402
    assert server.paid_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_same_challenge_offered_again_is_bounded_by_retry_limit() -> None:
    charge_offer = offer("charge-1")
    server = Server(lambda _, __: payment_required(charge_offer))

    wallet = Wallet()
    response = await fetch(server, wallet, max_payment_retries=3)

    # As mppx Fetch, the same Challenge resends the same Credential, signed once, never
    # past the retry limit, and the last 402 is the answer.
    assert response.status_code == 402
    assert server.paid_ids == ["charge-1"] * 3
    assert wallet.signed_ids == ["charge-1"]
    assert len({r.headers["authorization"] for r in server.requests[1:]}) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [1, 2, 3, 5])
async def test_new_challenges_forever_stop_at_retry_limit(limit: int) -> None:
    server = Server(
        lambda _, number: payment_required(offer(f"charge-{number}"), problem=CREDIT_INSUFFICIENT)
    )

    response = await fetch(server, Wallet(), max_payment_retries=limit)

    assert response.status_code == 402
    assert server.paid_ids == [f"charge-{n}" for n in range(1, limit + 1)]
    assert len(server.requests) == limit + 1


@pytest.mark.asyncio
async def test_new_round_skips_charge_over_amount_cap() -> None:
    def handle(credential: Credential | None, _: int) -> httpx.Response:
        if credential is None:
            return payment_required(offer("proof-1", "0"), offer("charge-1"))
        return payment_required(offer("charge-2", "50000"), problem=CREDIT_INSUFFICIENT)

    server = Server(handle)
    wallet = Wallet(max_atomic_amount="20000")

    response = await fetch(server, wallet)

    assert response.status_code == 402
    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_new_round_skips_charge_to_unexpected_recipient() -> None:
    def handle(credential: Credential | None, _: int) -> httpx.Response:
        if credential is None:
            return payment_required(offer("proof-1", "0"))
        return payment_required(
            offer("charge-2", recipient="0x" + "ab" * 20), problem=CREDIT_INSUFFICIENT
        )

    server = Server(handle)

    response = await fetch(server, Wallet(expected_recipients=[RECIPIENT]))

    assert response.status_code == 402
    assert server.paid_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_new_round_skips_proof_for_another_realm() -> None:
    def handle(credential: Credential | None, _: int) -> httpx.Response:
        if credential is None:
            return payment_required(offer("charge-1"))
        return payment_required(offer("proof-2", "0", realm="evil.example"))

    server = Server(handle)
    wallet = Wallet()

    # A zero-amount proof binds the realm it names, which must be the request's host.
    with pytest.raises(PaymentError, match="differs from request host"):
        await fetch(server, wallet)

    assert server.paid_ids == ["charge-1"]
    assert wallet.signed_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_new_round_does_not_pay_expired_challenge() -> None:
    def handle(credential: Credential | None, _: int) -> httpx.Response:
        if credential is None:
            return payment_required(offer("proof-1", "0"))
        return payment_required(
            offer("charge-2", expires="2020-01-01T00:00:00Z"), problem=CREDIT_INSUFFICIENT
        )

    server = Server(handle)
    wallet = Wallet()

    response = await fetch(server, wallet)

    assert response.status_code == 402
    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_each_round_resends_the_same_request() -> None:
    server = Server(proof_then_charge(credit=False))

    response = await fetch(
        server,
        Wallet(),
        method="POST",
        params={"q": "1"},
        json={"amount": 5, "memo": "invoice"},
        headers={"x-request-id": "req-1"},
    )

    assert response.status_code == 200
    assert len(server.requests) == 3
    for request in server.requests:
        assert request.method == "POST"
        assert str(request.url) == f"{URL}?q=1"
        assert json.loads(request.content) == {"amount": 5, "memo": "invoice"}
        assert request.headers["x-request-id"] == "req-1"
        assert request.headers["content-type"] == "application/json"
    authorizations = [request.headers.get("authorization") for request in server.requests]
    assert authorizations[0] is None
    assert None not in authorizations[1:]
    assert authorizations[1] != authorizations[2]


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


def _mcp_error(
    *challenges: Challenge, code: int = -32042, http_status: int | None = None
) -> Exception:
    exceptions = pytest.importorskip("mcp.shared.exceptions")
    types = pytest.importorskip("mcp.types")
    from mpp.extensions.mcp.types import MCPChallenge

    data: dict[str, Any] = {
        "challenges": [
            MCPChallenge.from_core(c, c.realm or REALM, c.expires).to_dict() for c in challenges
        ],
        "problem": CREDIT_INSUFFICIENT,
    }
    if http_status is not None:
        data["httpStatus"] = http_status
    return exceptions.McpError(types.ErrorData(code=code, message="Payment Required", data=data))


class ToolResult:
    meta = None
    content = [{"type": "text", "text": "paid content"}]


McpHandler = Callable[[dict[str, Any] | None, int], Any]


class McpServer:
    """An MCP session whose ``call_tool`` answers the credential in its ``_meta``."""

    def __init__(self, handler: McpHandler) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, name: str, arguments: Any = None, **kwargs: Any) -> Any:
        from mpp.extensions.mcp import META_CREDENTIAL

        self.calls.append({"name": name, "arguments": arguments, **kwargs})
        meta = kwargs.get("meta") or {}
        result = self.handler(meta.get(META_CREDENTIAL), len(self.calls))
        if isinstance(result, Exception):
            raise result
        return result

    @property
    def paid_ids(self) -> list[str]:
        from mpp.extensions.mcp import META_CREDENTIAL

        return [
            call["meta"][META_CREDENTIAL]["challenge"]["id"]
            for call in self.calls
            if call.get("meta") and META_CREDENTIAL in call["meta"]
        ]


def mcp_proof_then_charge(
    *, credit: bool, code: int = -32042, http_status: int | None = None
) -> McpHandler:
    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        if credential is None:
            return _mcp_error(offer("proof-1", "0"), offer("charge-1"))
        if credential["payload"]["type"] == "proof":
            if credit:
                return ToolResult()
            return _mcp_error(offer("charge-2"), code=code, http_status=http_status)
        if credential["challenge"]["id"] in ("charge-1", "charge-2"):
            return ToolResult()
        return _mcp_error(offer("charge-3"))

    return handle


def _mcp_client(server: McpServer, wallet: Wallet, **options: Any) -> Any:
    pytest.importorskip("mcp")
    from mpp.extensions.mcp import McpClient

    options.setdefault("trusted_tempo_realms", [REALM])
    return McpClient(server, methods=[wallet.method], **options)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "http_status"), [(-32042, None), (-32042, 402), (-32043, None), (-32043, 402)]
)
async def test_mcp_pays_real_charge_after_proof_refused(code: int, http_status: int | None) -> None:
    server = McpServer(mcp_proof_then_charge(credit=False, code=code, http_status=http_status))
    wallet = Wallet()

    result = await _mcp_client(server, wallet).call_tool(
        "premium", {"q": "1"}, meta={"trace": "t-1"}, timeout=12.0
    )

    assert result.result.content[0]["text"] == "paid content"
    assert server.paid_ids == ["proof-1", "charge-2"]
    assert wallet.signed_ids == ["proof-1", "charge-2"]
    # Every round calls the same tool with the caller's arguments and _meta.
    for call in server.calls:
        assert call["name"] == "premium"
        assert call["arguments"] == {"q": "1"}
        assert call["meta"]["trace"] == "t-1"
    assert [call.get("read_timeout_seconds") for call in server.calls[1:]] == [12.0, 12.0]


@pytest.mark.asyncio
@pytest.mark.parametrize("http_status", [403, 410])
async def test_mcp_verification_failure_other_than_402_is_final(http_status: int) -> None:
    server = McpServer(mcp_proof_then_charge(credit=False, code=-32043, http_status=http_status))
    wallet = Wallet()

    # As over HTTP, only a 402 starts a new round: a channel gone (410) is final.
    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, wallet).call_tool("premium", {})

    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_mcp_wallet_with_credit_pays_only_the_proof() -> None:
    server = McpServer(mcp_proof_then_charge(credit=True))
    wallet = Wallet()

    await _mcp_client(server, wallet).call_tool("premium", {})

    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_mcp_refusal_without_a_payable_challenge_is_final() -> None:
    exceptions = pytest.importorskip("mcp.shared.exceptions")
    types = pytest.importorskip("mcp.types")
    refusal = exceptions.McpError(
        types.ErrorData(code=-32042, message="Payment Required", data={"challenges": []})
    )

    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        return _mcp_error(offer("proof-1", "0")) if credential is None else refusal

    server = McpServer(handle)

    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, Wallet()).call_tool("premium", {})

    assert server.paid_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_mcp_error_without_challenges_after_payment_is_not_paid_again() -> None:
    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        return _mcp_error(offer("charge-1")) if credential is None else TimeoutError("timed out")

    server = McpServer(handle)

    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, Wallet()).call_tool("premium", {})

    assert server.paid_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_mcp_pushed_payment_refused_is_not_paid_again() -> None:
    server = McpServer(lambda _, number: _mcp_error(offer(f"charge-{number}")))

    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, Wallet(payload_type="hash")).call_tool("premium", {})

    assert server.paid_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_mcp_new_challenges_forever_stop_at_three_credentials() -> None:
    server = McpServer(lambda _, number: _mcp_error(offer(f"charge-{number}")))

    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, Wallet()).call_tool("premium", {})

    assert server.paid_ids == ["charge-1", "charge-2", "charge-3"]
    assert len(server.calls) == 4


@pytest.mark.asyncio
async def test_mcp_same_challenge_offered_again_resends_the_credential() -> None:
    charge_offer = offer("charge-1")
    server = McpServer(lambda _, __: _mcp_error(charge_offer))
    wallet = Wallet()

    # As mppx Fetch: the same Challenge resends the same Credential, signed once, up to
    # the attempt limit; the last refusal is the answer.
    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, wallet).call_tool("premium", {})

    assert server.paid_ids == ["charge-1"] * 3
    assert wallet.signed_ids == ["charge-1"]
    sent = [call["meta"] for call in server.calls if call.get("meta")]
    assert all(meta == sent[0] for meta in sent)


@pytest.mark.asyncio
async def test_mcp_same_challenge_with_new_description_is_the_same() -> None:
    charge_offer = offer("charge-1")
    described = dataclasses.replace(charge_offer, description="Premium tool")

    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        if credential is None:
            return _mcp_error(charge_offer)
        return ToolResult() if len(server.paid_ids) == 2 else _mcp_error(described)

    server = McpServer(handle)
    wallet = Wallet()

    await _mcp_client(server, wallet).call_tool("premium", {})

    # A display field is not part of the Challenge's identity: nothing is signed again.
    assert server.paid_ids == ["charge-1", "charge-1"]
    assert wallet.signed_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_mcp_new_round_skips_charge_over_amount_cap() -> None:
    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        if credential is None:
            return _mcp_error(offer("proof-1", "0"), offer("charge-1"))
        return _mcp_error(offer("charge-2", "50000"))

    server = McpServer(handle)
    wallet = Wallet(max_atomic_amount="20000")

    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, wallet).call_tool("premium", {})

    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_mcp_new_round_skips_proof_for_untrusted_realm() -> None:
    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        if credential is None:
            return _mcp_error(offer("charge-1"))
        return _mcp_error(offer("proof-2", "0", realm="evil.example"))

    server = McpServer(handle)
    wallet = Wallet()

    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, wallet).call_tool("premium", {})

    assert server.paid_ids == ["charge-1"]
    assert wallet.signed_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_mcp_new_round_does_not_pay_expired_challenge() -> None:
    def handle(credential: dict[str, Any] | None, _: int) -> Any:
        if credential is None:
            return _mcp_error(offer("proof-1", "0"))
        return _mcp_error(offer("charge-2", expires="2020-01-01T00:00:00Z"))

    server = McpServer(handle)
    wallet = Wallet()

    # The proof was sent and refused: its unknown outcome is reported, never the expiry alone.
    with pytest.raises(PaymentOutcomeUnknownError) as raised:
        await _mcp_client(server, wallet).call_tool("premium", {})

    assert raised.value.challenge.id == "proof-1"
    assert isinstance(raised.value.__cause__, PaymentExpiredError)
    assert server.paid_ids == ["proof-1"]
    assert wallet.signed_ids == ["proof-1"]


@pytest.mark.asyncio
async def test_mcp_untrusted_proof_is_skipped_for_the_real_charge() -> None:
    server = McpServer(mcp_proof_then_charge(credit=False))
    wallet = Wallet()

    # Without a pinned realm the proof is never signed: the real charge is paid at once.
    await _mcp_client(server, wallet, trusted_tempo_realms=[]).call_tool("premium", {})

    assert server.paid_ids == ["charge-1"]
    assert wallet.signed_ids == ["charge-1"]


@pytest.mark.asyncio
async def test_mcp_refused_evm_authorization_is_not_paid_again() -> None:
    from mpp.methods import Method

    def evm_offer(challenge_id: str) -> Challenge:
        return Challenge(
            id=challenge_id, method="evm", intent="charge", realm=REALM, request={"amount": "1"}
        )

    signed: list[str] = []

    async def create(params: CredentialParams) -> str:
        signed.append(params.challenge.id)
        return Credential(
            challenge=params.challenge.to_echo(), payload={"type": "authorization"}
        ).to_authorization()

    wallet = Wallet()
    wallet.method = ClientMethod(
        method=Method(name="evm", intent="charge", request_model=dict, payload_model=dict),
        create_credential=create,
    )
    server = McpServer(lambda _, number: _mcp_error(evm_offer(f"evm-{number}")))

    # The refused authorization stays spendable: paying a new challenge could pay twice.
    with pytest.raises(PaymentOutcomeUnknownError):
        await _mcp_client(server, wallet).call_tool("premium", {})

    assert server.paid_ids == ["evm-1"]
    assert signed == ["evm-1"]
