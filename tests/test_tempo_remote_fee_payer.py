"""Hosted (remote) Tempo fee payers: ``tempo.charge(fee_payer=<url | {url, headers}>)``.

The fake hosted service below co-signs with a local key from the
``eth_fillTransaction`` request alone, as mppx's tests do, so the request shape
and the sponsor-address recovery are checked against each other.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import attrs
import httpx
import pytest
import rlp
from eth_account import Account
from eth_hash.auto import keccak

from mpp.errors import InternalPaymentError, VerificationError
from mpp.methods.tempo import PATH_USD, USDC, TempoAccount
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo._attribution import encode as encode_attribution
from mpp.methods.tempo._fee_payer import resolve_fee_payer
from mpp.methods.tempo.client import EXPIRING_NONCE_KEY
from mpp.methods.tempo.fee_payer_envelope import encode_fee_payer_envelope
from mpp.methods.tempo.intents import (
    TRANSFER_WITH_MEMO_SELECTOR,
    TRANSFER_WITH_MEMO_TOPIC,
    ChargeIntent,
    _raw_transaction_hash,
)
from mpp.methods.tempo.remote_fee_payer import RemoteFeePayer
from tests import challenge, http_request, internal_cause, make_credential

SENDER_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SPONSOR_KEY = "0x" + "42" * 32
ACCESS_KEY = "0x" + "11" * 32
ROOT = "0x00000000000000000000000000000000000000aa"
SPONSOR = Account.from_key(SPONSOR_KEY).address
CHAIN_ID = 42431
CURRENCY = "0x20c0000000000000000000000000000000000000"
RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
CHALLENGE_ID = "challenge-hosted"
REALM = "api.example.com"
RPC_URL = "https://rpc.test"
FEE_PAYER_URL = "https://sponsor.test/rpc"
MEMO = encode_attribution(challenge_id=CHALLENGE_ID, server_id=REALM)
P256_PUBKEY = bytes(range(1, 65))
P256_SENDER = "0x" + keccak(P256_PUBKEY)[-20:].hex()


def _transaction(**overrides: Any) -> Any:
    from pytempo import Call, TempoTransaction

    to = RECIPIENT[2:].lower().zfill(64)
    data = f"0x{TRANSFER_WITH_MEMO_SELECTOR}{to}{1000:064x}{MEMO[2:]}"
    fields: dict[str, Any] = {
        "chain_id": CHAIN_ID,
        "gas_limit": 100_000,
        "max_fee_per_gas": 2,
        "max_priority_fee_per_gas": 1,
        "nonce_key": EXPIRING_NONCE_KEY,
        "valid_before": int(time.time()) + 300,
        "awaiting_fee_payer": True,
        "calls": (Call.create(to=CURRENCY, value=0, data=data),),
    }
    return TempoTransaction.create(**{**fields, **overrides})


def _envelope(sender: str = "secp256k1", **overrides: Any) -> tuple[str, str]:
    """Return a client-signed 0x78 envelope and the account it debits."""
    tx = _transaction(**overrides)
    if sender == "keychain":
        return "0x" + encode_fee_payer_envelope(tx.sign_access_key(ACCESS_KEY, ROOT)).hex(), ROOT
    signed = tx.sign(SENDER_KEY)
    if sender == "p256":
        # The hosted path, like mppx's, leaves the signature itself to the chain.
        fields = rlp.decode(encode_fee_payer_envelope(signed)[1:])
        fields[-1] = b"\x01" + b"\x01" * 64 + P256_PUBKEY + b"\x00"
        fields[11] = bytes.fromhex(P256_SENDER[2:])
        return "0x78" + rlp.encode(fields).hex(), P256_SENDER
    return "0x" + encode_fee_payer_envelope(signed).hex(), Account.from_key(SENDER_KEY).address


def _sponsor_signature(
    params: dict[str, Any], fee_token: str, key: str = SPONSOR_KEY, key_authorization: Any = None
) -> Any:
    """Co-sign the transaction an ``eth_fillTransaction`` request describes."""
    from pytempo import Call
    from pytempo.models import as_address

    def quantity(name: str) -> int | None:
        return int(params[name], 16) if name in params else None

    tx = _transaction(
        gas_limit=quantity("gas") or 0,
        max_fee_per_gas=quantity("maxFeePerGas") or 0,
        max_priority_fee_per_gas=quantity("maxPriorityFeePerGas") or 0,
        nonce=quantity("nonce") or 0,
        nonce_key=quantity("nonceKey") or 0,
        valid_before=quantity("validBefore"),
        valid_after=quantity("validAfter"),
        fee_token=fee_token,
        key_authorization=key_authorization,
        calls=tuple(
            Call.create(
                to=call["to"],
                value=0 if call["value"] == "0x" else int(call["value"], 16),
                data=call.get("data", "0x"),
            )
            for call in params["calls"]
        ),
    )
    tx = attrs.evolve(tx, sender_address=as_address(params["from"]))
    return tx.sign(key, for_fee_payer=True).fee_payer_signature


class FakeNetwork:
    """A Tempo RPC and a hosted fee payer that co-signs with ``SPONSOR_KEY``."""

    def __init__(self, *, sender: str, fee_token: str = PATH_USD) -> None:
        self.sender = sender
        self.fee_token = fee_token
        self.methods: list[str] = []
        self.simulations: list[dict[str, Any]] = []
        self.fill_requests: list[httpx.Request] = []
        self.broadcasts: list[str] = []
        self.fill_result: Any = None
        self.fill_error: dict[str, Any] | None = None
        self.revert_simulation: int | None = None
        self.key_authorization: Any = None

    def fill(self, params: dict[str, Any]) -> Any:
        if self.fill_result is not None:
            return self.fill_result(params) if callable(self.fill_result) else self.fill_result
        signature = _sponsor_signature(
            params, self.fee_token, key_authorization=self.key_authorization
        )
        return {
            "tx": {
                "feePayerSignature": {
                    "r": hex(signature.r),
                    "s": hex(signature.s),
                    "yParity": hex(signature.v - 27 if signature.v >= 27 else signature.v),
                },
                "feeToken": self.fee_token,
            }
        }

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body["method"]
        self.methods.append(method)
        reply: dict[str, Any] = {"jsonrpc": "2.0", "id": body["id"]}
        if str(request.url) == FEE_PAYER_URL:
            assert method == "eth_fillTransaction"
            self.fill_requests.append(request)
            if self.fill_error is not None:
                reply["error"] = self.fill_error
            else:
                reply["result"] = self.fill(body["params"][0])
        elif method == "eth_call":
            self.simulations.append(body["params"][0])
            if self.revert_simulation == len(self.simulations):
                reply["error"] = {"code": 3, "message": "execution reverted"}
            else:
                reply["result"] = "0x"
        elif method == "eth_sendRawTransactionSync":
            raw = body["params"][0]
            self.broadcasts.append(raw)
            reply["result"] = {
                "status": "0x1",
                "transactionHash": _raw_transaction_hash(raw),
                "logs": [
                    {
                        "address": CURRENCY,
                        "topics": [
                            TRANSFER_WITH_MEMO_TOPIC,
                            "0x" + self.sender[2:].lower().zfill(64),
                            "0x" + RECIPIENT[2:].lower().zfill(64),
                            MEMO,
                        ],
                        "data": "0x" + f"{1000:064x}",
                    }
                ],
            }
        else:
            raise AssertionError(f"unexpected RPC method {method}")
        return httpx.Response(200, json=reply)


def _credential(raw_tx: str) -> Any:
    return make_credential(
        payload={"type": "transaction", "signature": raw_tx},
        challenge_id=CHALLENGE_ID,
        realm=REALM,
        expires=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )


def _request() -> dict[str, Any]:
    return {
        "amount": "1000",
        "currency": CURRENCY,
        "recipient": RECIPIENT,
        "methodDetails": {"chainId": CHAIN_ID, "feePayer": True},
    }


async def _settle(network: FakeNetwork, raw_tx: str, **options: Any) -> Any:
    options.setdefault("fee_payer", FEE_PAYER_URL)
    async with httpx.AsyncClient(transport=httpx.MockTransport(network)) as client:
        intent = ChargeIntent(rpc_url=RPC_URL, http_client=client, **options)
        return await intent.broadcast(_credential(raw_tx), _request())


async def _bearer() -> dict[str, str]:
    return {"Authorization": "Bearer per-request"}


@pytest.mark.parametrize("sender_kind", ["secp256k1", "keychain", "p256"])
@pytest.mark.parametrize(
    ("fee_payer", "authorization"),
    [
        (FEE_PAYER_URL, None),
        ({"url": FEE_PAYER_URL, "headers": {"Authorization": "Bearer static"}}, "Bearer static"),
        (
            RemoteFeePayer(
                url=FEE_PAYER_URL,
                headers=lambda: {"Authorization": "Bearer sync", "Content-Type": "text/plain"},
            ),
            "Bearer sync",
        ),
        (RemoteFeePayer(url=FEE_PAYER_URL, headers=_bearer), "Bearer per-request"),
    ],
)
async def test_hosted_fee_payer_sponsors_and_server_broadcasts(
    fee_payer: Any, authorization: str | None, sender_kind: str
) -> None:
    raw_tx, sender = _envelope(sender_kind)
    client_fields = rlp.decode(bytes.fromhex(raw_tx[4:]))
    network = FakeNetwork(sender=sender)

    receipt = await _settle(network, raw_tx, fee_payer=fee_payer)

    assert receipt.status == "success"
    # Like mppx: simulate from the sender, ask the sponsor, simulate the final
    # sponsored transaction, then broadcast it here (not through the sponsor).
    assert network.methods == [
        "eth_call",
        "eth_fillTransaction",
        "eth_call",
        "eth_sendRawTransactionSync",
    ]
    [fill] = network.fill_requests
    assert fill.headers.get("authorization") == authorization
    assert fill.headers["content-type"] == "application/json"
    tx = _transaction()
    assert json.loads(fill.content)["params"] == [
        {
            "calls": [{"to": CURRENCY, "data": "0x" + tx.calls[0].data.hex(), "value": "0x"}],
            "feePayer": True,
            "from": sender.lower(),
            "gas": hex(100_000),
            "maxFeePerGas": "0x2",
            "maxPriorityFeePerGas": "0x1",
            "nonce": "0x0",
            "nonceKey": hex(EXPIRING_NONCE_KEY),
            "type": "0x76",
            "validBefore": hex(int.from_bytes(client_fields[8], "big")),
        }
    ]
    sender_simulation, sponsored_simulation = network.simulations
    assert "feePayer" not in sender_simulation and "gas" not in sender_simulation
    assert sponsored_simulation["feePayer"] == SPONSOR
    assert sponsored_simulation["feeToken"] == PATH_USD

    [broadcast] = network.broadcasts
    fields = rlp.decode(bytes.fromhex(broadcast[4:]))
    assert broadcast.startswith("0x76")
    assert fields[:10] == client_fields[:10]
    assert fields[10] == bytes.fromhex(PATH_USD[2:])
    assert fields[12] == client_fields[12]
    assert fields[-1] == client_fields[-1]
    v, r, s = (int.from_bytes(value, "big") for value in fields[11])
    payload = keccak(
        b"\x78" + rlp.encode([*client_fields[:10], fields[10], client_fields[11], fields[12]])
    )
    assert Account._recover_hash(payload, vrs=(v, r, s)) == SPONSOR


async def test_hosted_fee_payer_carries_a_key_authorization() -> None:
    """A key authorization reaches the sponsor, the simulation and the broadcast, as in mppx."""
    from pytempo.keychain import KeyAuthorization

    from mpp.methods.tempo._fee_payer import key_authorization_rpc

    authorization = KeyAuthorization(
        key_id=Account.from_key(ACCESS_KEY).address, chain_id=CHAIN_ID
    ).sign(SENDER_KEY)
    raw_tx, sender = _envelope(key_authorization=authorization)
    client_fields = rlp.decode(bytes.fromhex(raw_tx[4:]))
    assert len(client_fields) == 15
    network = FakeNetwork(sender=sender)
    network.key_authorization = authorization

    receipt = await _settle(network, raw_tx)

    assert receipt.status == "success"
    expected = key_authorization_rpc(client_fields[13])
    [fill] = network.fill_requests
    assert json.loads(fill.content)["params"][0]["keyAuthorization"] == expected
    _, sponsored_simulation = network.simulations
    assert sponsored_simulation["keyAuthorization"] == expected
    assert sponsored_simulation["feePayer"] == SPONSOR
    [broadcast] = network.broadcasts
    fields = rlp.decode(bytes.fromhex(broadcast[4:]))
    assert fields[13] == client_fields[13]
    assert fields[-1] == client_fields[-1]


async def test_hosted_fee_payer_refuses_an_authorization_list() -> None:
    raw_tx, sender = _envelope()
    fields = rlp.decode(bytes.fromhex(raw_tx[4:]))
    fields[12] = [[b"\x01", b"\x02"]]
    network = FakeNetwork(sender=sender)

    with pytest.raises(VerificationError, match="authorizationList"):
        await _settle(network, "0x78" + rlp.encode(fields).hex())
    assert network.methods == []


async def test_hosted_fee_payer_cannot_change_sender_committed_fields() -> None:
    """Only the sponsor's signature and fee token are used, as in mppx."""
    raw_tx, sender = _envelope()
    client_fields = rlp.decode(bytes.fromhex(raw_tx[4:]))
    network = FakeNetwork(sender=sender)

    def mutated(params: dict[str, Any]) -> Any:
        signature = _sponsor_signature(params, PATH_USD)
        return {
            "tx": {
                "feePayerSignature": {"r": signature.r, "s": signature.s, "yParity": 0}
                if signature.v in (0, 27)
                else {"r": signature.r, "s": signature.s, "yParity": 1},
                "feeToken": PATH_USD,
                "from": ROOT,
                "gas": "0x1",
                "maxFeePerGas": "0x99999999",
                "nonce": "0x99",
                "chainId": "0x1",
                "calls": [{"to": USDC, "data": "0x"}],
            }
        }

    network.fill_result = mutated

    await _settle(network, raw_tx)

    [broadcast] = network.broadcasts
    fields = rlp.decode(bytes.fromhex(broadcast[4:]))
    assert fields[:10] == client_fields[:10]
    assert fields[-1] == client_fields[-1]


async def test_hosted_fee_payer_signature_over_mutated_fields_names_another_sponsor() -> None:
    """A sponsor signing other fields recovers to another address, which must pay."""
    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    network.fill_result = lambda params: FakeNetwork(sender=sender).fill({**params, "gas": "0x1"})
    network.revert_simulation = 2

    with pytest.raises(VerificationError, match="pre-broadcast simulation"):
        await _settle(network, raw_tx)

    assert network.simulations[1]["feePayer"] != SPONSOR
    assert network.broadcasts == []


@pytest.mark.parametrize(
    ("allowed", "sponsor_token", "accepted"),
    [
        (None, USDC, True),
        ((PATH_USD,), PATH_USD, True),
        ((PATH_USD,), USDC, False),
    ],
)
async def test_hosted_fee_token_respects_allowlist(
    allowed: tuple[str, ...] | None, sponsor_token: str, accepted: bool
) -> None:
    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender, fee_token=sponsor_token)

    if not accepted:
        with pytest.raises(InternalPaymentError) as raised:
            await _settle(network, raw_tx, allowed_fee_tokens=allowed)
        assert "feeToken is not allowed" in str(internal_cause(raised.value))
        assert network.methods == ["eth_call", "eth_fillTransaction"]
        return

    await _settle(network, raw_tx, allowed_fee_tokens=allowed)
    [broadcast] = network.broadcasts
    assert rlp.decode(bytes.fromhex(broadcast[4:]))[10] == bytes.fromhex(sponsor_token[2:])


@pytest.mark.parametrize(
    ("result", "error", "reason"),
    [
        (None, None, "failed to sponsor transaction"),
        ({"tx": {}}, None, "failed to sponsor transaction"),
        ({"tx": {"feeToken": PATH_USD}}, None, "failed to sponsor transaction"),
        (
            {"tx": {"feePayerSignature": {"r": "0x1", "s": "0x1"}}},
            None,
            "did not return a feeToken",
        ),
        (
            {"tx": {"feePayerSignature": {"r": "0x1", "s": "0x1"}, "feeToken": "0x1234"}},
            None,
            "feeToken is invalid",
        ),
        (
            {"tx": {"feePayerSignature": {"r": "0x0", "s": "0x0", "yParity": 0}, "feeToken": USDC}},
            None,
            "invalid feePayerSignature",
        ),
        (None, {"code": -32000, "message": "Invalid or revoked API key"}, "revoked API key"),
    ],
)
async def test_hosted_fee_payer_failures_are_internal(
    result: Any, error: dict[str, Any] | None, reason: str
) -> None:
    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    network.fill_result = (lambda _params: None) if result is None else result
    network.fill_error = error

    with pytest.raises(InternalPaymentError) as raised:
        await _settle(network, raw_tx)

    assert reason in str(internal_cause(raised.value))
    assert network.broadcasts == []


async def test_hosted_fee_payer_is_not_asked_to_sponsor_policy_violations() -> None:
    raw_tx, sender = _envelope(gas_limit=3_000_000)
    network = FakeNetwork(sender=sender)

    with pytest.raises(VerificationError, match="gas limit exceeds sponsor policy"):
        await _settle(network, raw_tx)

    assert network.methods == []


async def test_hosted_fee_payer_is_not_asked_to_sponsor_reverting_calls() -> None:
    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    network.revert_simulation = 1

    with pytest.raises(VerificationError, match="pre-broadcast simulation"):
        await _settle(network, raw_tx)

    assert network.methods == ["eth_call"]


async def test_hosted_sponsorship_is_not_broadcast_when_final_simulation_reverts() -> None:
    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    network.revert_simulation = 2

    with pytest.raises(VerificationError, match="pre-broadcast simulation"):
        await _settle(network, raw_tx)

    assert network.methods == ["eth_call", "eth_fillTransaction", "eth_call"]


async def test_challenge_fee_payer_url_is_ignored() -> None:
    """Challenges no longer name the sponsor; only the server's configuration does."""
    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    request = _request()
    request["methodDetails"]["feePayerUrl"] = FEE_PAYER_URL

    async with httpx.AsyncClient(transport=httpx.MockTransport(network)) as client:
        intent = ChargeIntent(rpc_url=RPC_URL, http_client=client)
        with pytest.raises(InternalPaymentError) as raised:
            await intent.broadcast(_credential(raw_tx), request)

    assert "No fee payer configured" in str(internal_cause(raised.value))
    assert network.methods == []


@pytest.mark.parametrize(
    ("fee_payer", "route", "sponsored"),
    [
        (FEE_PAYER_URL, {}, True),
        ({"url": FEE_PAYER_URL, "headers": {"Authorization": "Bearer secret"}}, {}, True),
        (FEE_PAYER_URL, {"fee_payer": False}, False),
        # Local and hosted fee payers both sponsor by default (mppx resolvedFeePayer).
        (TempoAccount.from_key(SPONSOR_KEY), {}, True),
        (TempoAccount.from_key(SPONSOR_KEY), {"fee_payer": False}, False),
        (TempoAccount.from_key(SPONSOR_KEY), {"fee_payer": True}, True),
        (None, {"fee_payer": True}, False),
    ],
)
async def test_routes_advertise_hosted_sponsorship(
    monkeypatch: pytest.MonkeyPatch, fee_payer: Any, route: dict[str, Any], sponsored: bool
) -> None:
    from mpp.server import Mpp

    monkeypatch.setenv("MPP_SECRET_KEY", "test-secret-key")
    server = Mpp(
        methods=tempo_server.charge(recipient=RECIPIENT, currencies=[CURRENCY], fee_payer=fee_payer)
    )

    result = await server.charge(amount="0.001", **route)(http_request())

    issued = challenge(result)
    assert issued.request.get("methodDetails", {}).get("feePayer", False) is sponsored
    assert FEE_PAYER_URL not in issued.request_b64 + json.dumps(issued.request)
    assert "secret" not in json.dumps(issued.request)


def test_fee_token_requires_a_local_fee_payer() -> None:
    with pytest.raises(ValueError, match="local fee_payer"):
        tempo_server.charge(fee_payer=FEE_PAYER_URL, fee_token=PATH_USD)
    with pytest.raises(ValueError, match="local fee_payer"):
        ChargeIntent(rpc_url=RPC_URL, fee_payer=FEE_PAYER_URL, fee_token=PATH_USD)


def test_resolve_fee_payer_forms() -> None:
    account = TempoAccount.from_key(SPONSOR_KEY)
    assert resolve_fee_payer(None) == (None, None)
    assert resolve_fee_payer(account) == (account, None)
    assert resolve_fee_payer(FEE_PAYER_URL) == (None, RemoteFeePayer(url=FEE_PAYER_URL))
    _, remote = resolve_fee_payer({"url": FEE_PAYER_URL, "headers": {"X": "1"}})
    assert remote == RemoteFeePayer(url=FEE_PAYER_URL, headers={"X": "1"})
    with pytest.raises(ValueError, match="Unknown remote fee payer options"):
        resolve_fee_payer({"url": FEE_PAYER_URL, "fetch": object()})
    with pytest.raises(TypeError):
        resolve_fee_payer({"headers": {}})
    with pytest.raises(TypeError):
        resolve_fee_payer(True)


async def test_settled_hosted_credential_is_refused_before_asking_the_sponsor() -> None:
    from mpp.errors import CredentialReplayedError
    from mpp.store import MemoryStore

    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    store = MemoryStore()
    await _settle(network, raw_tx, store=store)
    asked = list(network.methods)

    with pytest.raises(CredentialReplayedError):
        await _settle(network, raw_tx, store=store)

    assert network.methods == asked


async def test_lost_hosted_broadcast_is_reconciled_without_asking_the_sponsor_again() -> None:
    """A hosted sponsorship whose broadcast outcome was lost is retried with the exact
    transaction the sponsor signed, never a second sponsorship (which could pick
    another fee token and pay twice)."""
    from mpp.errors import PaymentError
    from mpp.store import MemoryStore

    raw_tx, sender = _envelope()
    network = FakeNetwork(sender=sender)
    lost = {"count": 1}
    answer = network.__call__

    def flaky(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "eth_sendRawTransactionSync" and lost["count"]:
            lost["count"] -= 1
            network.broadcasts.append(body["params"][0])
            raise httpx.ReadTimeout("response lost")
        if body["method"] in ("eth_getTransactionReceipt", "eth_getTransactionByHash"):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": None})
        return answer(request)

    store = MemoryStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(flaky)) as client:
        intent = ChargeIntent(
            rpc_url=RPC_URL,
            http_client=client,
            fee_payer=FEE_PAYER_URL,
            store=store,
            confirmation_timeout=0.5,
        )
        with pytest.raises((PaymentError, httpx.HTTPError)):
            await intent.broadcast(_credential(raw_tx), _request())
        assert len(network.fill_requests) == 1
        receipt = await intent.broadcast(_credential(raw_tx), _request())

    assert receipt.status == "success"
    assert len(network.fill_requests) == 1
    assert len(set(network.broadcasts)) == 1
