"""Unit tests for the TIP-1034 session client (ports of mppx CredentialState, Session and
SessionManager tests): credential planning, deposit sizing, escrow and chain policy, and
per-channel serialization. Chain access is faked; see test_session_client_localnet.py for
the flow against an mppx server."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from mpp import Challenge, Credential
from mpp.client import Mpp
from mpp.methods.tempo import TempoAccount
from mpp.methods.tempo import client as tempo_client
from mpp.methods.tempo.session import chain
from mpp.methods.tempo.session.channel import compute_channel_id
from mpp.methods.tempo.session.client import (
    ChannelEntry,
    SessionContext,
    SessionManager,
    SessionMethod,
    channel_key,
    create_channel_store,
    create_json_channel_store,
    deserialize_entry,
    resolve_automatic_top_up,
    resolve_opening_deposit,
    serialize_entry,
    session,
    session_manager,
)
from mpp.methods.tempo.session.client.ops import resolve_escrow
from mpp.methods.tempo.session.client.state import (
    ChallengeContext,
    is_tip1034_session_challenge,
    plan_credential,
    resolve_challenge_context,
)
from mpp.methods.tempo.session.protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    create_session_receipt,
    serialize_session_receipt,
)
from mpp.methods.tempo.session.voucher import verify_voucher
from mpp.runtime import CredentialParams

PAYEE = "0x" + "11" * 20
TOKEN = "0x20c0000000000000000000000000000000000000"
CUSTOM_ESCROW = "0x" + "22" * 20
CHAIN_ID = 4217
ACCOUNT = TempoAccount.from_key("0x" + "ab" * 32)


def _expires() -> str:
    return (datetime.now(UTC) + timedelta(minutes=5)).isoformat()


def make_challenge(
    *,
    amount: str = "100",
    suggested_deposit: str | None = None,
    chain_id: int | None = CHAIN_ID,
    escrow: str | None = ESCROW_ADDRESS,
    fee_payer: bool | None = None,
    protocol: str = "v2",
    challenge_id: str | None = None,
) -> Challenge:
    details: dict[str, Any] = {"sessionProtocol": protocol}
    if escrow is not None:
        details["escrowContract"] = escrow
    if chain_id is not None:
        details["chainId"] = chain_id
    if fee_payer is not None:
        details["feePayer"] = fee_payer
    request: dict[str, Any] = {
        "amount": amount,
        "currency": TOKEN,
        "recipient": PAYEE,
        "unitType": "request",
        "methodDetails": details,
    }
    if suggested_deposit is not None:
        request["suggestedDeposit"] = suggested_deposit
    return Challenge(
        id=challenge_id or os.urandom(8).hex(),
        method="tempo",
        intent="session",
        request=request,
        realm="api.test",
        expires=_expires(),
    )


def descriptor_for(account: TempoAccount = ACCOUNT, salt: str | None = None) -> ChannelDescriptor:
    return ChannelDescriptor(
        payer=account.address,
        payee=PAYEE,
        operator=ZERO_ADDRESS,
        token=TOKEN,
        salt=salt or "0x" + os.urandom(32).hex(),
        authorized_signer=account.address,
        expiring_nonce_hash="0x" + os.urandom(32).hex(),
    )


def entry_for(
    *, cumulative: int = 100, deposit: int = 1000, account: TempoAccount = ACCOUNT
) -> ChannelEntry:
    descriptor = descriptor_for(account)
    return ChannelEntry(
        channel_id=compute_channel_id(descriptor, chain_id=CHAIN_ID),
        cumulative_amount=cumulative,
        deposit=deposit,
        descriptor=descriptor,
        escrow=ESCROW_ADDRESS,
        chain_id=CHAIN_ID,
        opened=True,
    )


@pytest.fixture
def fake_chain(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Replace open/top-up transaction building with deterministic fakes."""
    calls: dict[str, list[Any]] = {"open": [], "top_up": []}

    async def build_open_transaction(account: TempoAccount, **kwargs: Any) -> Any:
        calls["open"].append(kwargs)
        descriptor = ChannelDescriptor(
            payer=account.address,
            payee=kwargs["payee"],
            operator=kwargs["operator"],
            token=kwargs["token"],
            salt="0x" + os.urandom(32).hex(),
            authorized_signer=kwargs["authorized_signer"],
            expiring_nonce_hash="0x" + os.urandom(32).hex(),
        )
        channel_id = compute_channel_id(
            descriptor, chain_id=kwargs["chain_id"], escrow=kwargs["escrow"]
        )
        return "0x76" + "00" * 8, descriptor, channel_id

    async def build_top_up_transaction(
        account: TempoAccount, descriptor: ChannelDescriptor, additional: int, **kwargs: Any
    ) -> str:
        calls["top_up"].append({"additional": additional, **kwargs})
        return "0x76" + "11" * 8

    monkeypatch.setattr(chain, "build_open_transaction", build_open_transaction)
    monkeypatch.setattr(chain, "build_top_up_transaction", build_top_up_transaction)
    return calls


def payload_of(authorization: str) -> dict[str, Any]:
    return Credential.from_authorization(authorization).payload


async def _resolve_rpc(requested: int | None) -> tuple[str, int]:
    return "http://rpc.invalid", requested if requested is not None else CHAIN_ID


async def resolved_for(challenge: Challenge, **kwargs: Any) -> ChallengeContext:
    return await resolve_challenge_context(challenge, resolve_rpc=_resolve_rpc, **kwargs)


# ── deposit sizing (Runtime.ts) ────────────────────────────────────


class TestDepositSizing:
    def test_opening_deposit_defaults_to_request_amount(self) -> None:
        assert resolve_opening_deposit(request_amount=100) == 100
        assert resolve_opening_deposit(request_amount=100, max_deposit=10_000) == 100

    def test_opening_deposit_prefers_larger_suggestion_capped_by_max(self) -> None:
        assert resolve_opening_deposit(request_amount=100, suggested_deposit_raw="5000") == 5000
        assert (
            resolve_opening_deposit(
                request_amount=100, suggested_deposit_raw="5000", max_deposit=2000
            )
            == 2000
        )
        assert resolve_opening_deposit(request_amount=100, suggested_deposit_raw="50") == 100

    def test_opening_deposit_context_override(self) -> None:
        assert resolve_opening_deposit(request_amount=100, context_deposit_raw="700") == 700
        with pytest.raises(ValueError, match="below request amount"):
            resolve_opening_deposit(request_amount=100, context_deposit_raw="50")

    def test_opening_deposit_rejects_request_above_max(self) -> None:
        with pytest.raises(ValueError, match="exceeds local maxDeposit"):
            resolve_opening_deposit(request_amount=100, max_deposit=99)

    def test_top_up_zero_when_covered(self) -> None:
        assert resolve_automatic_top_up(deposit=1000, required_cumulative=1000) == 0

    def test_top_up_exact_shortfall_by_default(self) -> None:
        assert resolve_automatic_top_up(deposit=100, required_cumulative=200) == 100

    def test_top_up_prefers_amount_then_suggestion_never_below_shortfall(self) -> None:
        assert (
            resolve_automatic_top_up(deposit=100, required_cumulative=200, top_up_amount=500) == 500
        )
        assert (
            resolve_automatic_top_up(
                deposit=100, required_cumulative=200, top_up_amount=500, suggested_deposit=900
            )
            == 500
        )
        assert (
            resolve_automatic_top_up(deposit=100, required_cumulative=200, suggested_deposit=900)
            == 900
        )
        assert (
            resolve_automatic_top_up(deposit=100, required_cumulative=200, top_up_amount=10) == 100
        )

    def test_top_up_capped_by_max_deposit(self) -> None:
        assert (
            resolve_automatic_top_up(
                deposit=100, required_cumulative=200, top_up_amount=500, max_deposit=300
            )
            == 200
        )
        with pytest.raises(ValueError, match="exceeds local maxDeposit"):
            resolve_automatic_top_up(deposit=100, required_cumulative=400, max_deposit=300)


# ── challenge policy ──────────────────────────────────────────────


class TestChallengePolicy:
    def test_only_v2_session_challenges_are_handled(self) -> None:
        assert is_tip1034_session_challenge(make_challenge())
        assert not is_tip1034_session_challenge(make_challenge(protocol="v1"))
        method = session(account=ACCOUNT)
        assert method.key == "tempo/session"
        assert method.can_handle_challenge is not None
        assert not method.can_handle_challenge(make_challenge(protocol="v1"))

    def test_custom_escrow_rejected_unless_allowed(self) -> None:
        request = make_challenge(escrow=CUSTOM_ESCROW).request
        with pytest.raises(ValueError, match="does not match client escrow"):
            resolve_escrow(request)
        assert resolve_escrow(request, allow_custom_escrow=True) == CUSTOM_ESCROW
        assert resolve_escrow(make_challenge().request) == ESCROW_ADDRESS

    def test_escrow_pin_takes_precedence(self) -> None:
        request = make_challenge(escrow=CUSTOM_ESCROW).request
        assert resolve_escrow(request, CUSTOM_ESCROW) == CUSTOM_ESCROW
        with pytest.raises(ValueError, match="does not match"):
            resolve_escrow(make_challenge().request, CUSTOM_ESCROW, allow_custom_escrow=True)
        assert resolve_escrow(make_challenge(escrow=None).request, CUSTOM_ESCROW) == CUSTOM_ESCROW

    async def test_chain_allowlist(self) -> None:
        with pytest.raises(ValueError, match="Chain ID not allowed: 4217"):
            await resolved_for(make_challenge(), allowed_chain_ids=(42431,))
        with pytest.raises(ValueError, match="not allowed"):
            await resolved_for(make_challenge(), allowed_chain_ids=())
        resolved = await resolved_for(make_challenge(chain_id=None), allowed_chain_ids=(42431,))
        assert resolved.chain_id == 42431
        resolved = await resolved_for(make_challenge(), allowed_chain_ids=(42431, 4217))
        assert resolved.key == channel_key(
            payee=PAYEE, token=TOKEN, escrow=ESCROW_ADDRESS, chain_id=4217
        )

    async def test_rpc_chain_mismatch_rejected(self) -> None:
        async def other_chain(_: int | None) -> tuple[str, int]:
            return "http://rpc.invalid", 1337

        with pytest.raises(ValueError, match="Chain ID mismatch"):
            await resolve_challenge_context(make_challenge(), resolve_rpc=other_chain)

    async def test_custom_escrow_rejected_by_method(self) -> None:
        method = session(account=ACCOUNT)
        with pytest.raises(ValueError, match="does not match client escrow"):
            await method.create_credential(
                CredentialParams(challenge=make_challenge(escrow=CUSTOM_ESCROW))
            )


# ── planning (CredentialState.ts) ─────────────────────────────────


class TestPlanCredential:
    async def test_open_without_entry(self) -> None:
        resolved = await resolved_for(make_challenge())
        assert plan_credential(account=ACCOUNT, entry=None, resolved=resolved).type == "open"

    async def test_voucher_with_open_entry(self) -> None:
        resolved = await resolved_for(make_challenge())
        plan = plan_credential(account=ACCOUNT, entry=entry_for(), resolved=resolved)
        assert plan.type == "voucher"

    async def test_open_when_entry_closed_or_not_signable(self) -> None:
        resolved = await resolved_for(make_challenge())
        closed = entry_for()
        closed.opened = False
        assert plan_credential(account=ACCOUNT, entry=closed, resolved=resolved).type == "open"
        other = TempoAccount.from_key("0x" + "cd" * 32)
        plan = plan_credential(account=ACCOUNT, entry=entry_for(account=other), resolved=resolved)
        assert plan.type == "open"

    async def test_manual_action_requires_descriptor(self) -> None:
        resolved = await resolved_for(make_challenge())
        with pytest.raises(ValueError, match="descriptor required"):
            plan_credential(
                account=ACCOUNT,
                entry=None,
                resolved=resolved,
                context=SessionContext(action="voucher", cumulative_amount_raw="5"),
            )
        plan = plan_credential(
            account=ACCOUNT,
            entry=None,
            resolved=resolved,
            context=SessionContext(action="voucher", descriptor=descriptor_for()),
        )
        assert plan.type == "manual"

    async def test_recover_from_context_descriptor(self) -> None:
        resolved = await resolved_for(make_challenge())
        with pytest.raises(ValueError, match="descriptor required to reuse"):
            plan_credential(
                account=ACCOUNT,
                entry=None,
                resolved=resolved,
                context=SessionContext(channel_id="0x" + "00" * 32),
            )
        plan = plan_credential(
            account=ACCOUNT,
            entry=None,
            resolved=resolved,
            context=SessionContext(descriptor=descriptor_for()),
        )
        assert plan.type == "recover"


# ── store ─────────────────────────────────────────────────────────


class TestChannelStore:
    async def test_json_store_round_trips_amounts(self) -> None:
        backing: dict[str, str] = {}

        class Kv:
            def get(self, key: str) -> str | None:
                return backing.get(key)

            def set(self, key: str, value: str) -> None:
                backing[key] = value

            def delete(self, key: str) -> None:
                backing.pop(key, None)

        store = create_json_channel_store(Kv())
        entry = entry_for(cumulative=2**95, deposit=2**96 - 1)
        await store.set(entry)
        (key,) = backing
        assert key.startswith("chan:")
        assert json.loads(backing[key])["deposit"] == str(2**96 - 1)
        restored = await store.get(key.removeprefix("chan:"))
        assert restored == entry
        assert deserialize_entry(serialize_entry(entry)) == entry


# ── the session client method (Session.ts) ────────────────────────


def _topup_fetch(log: list[httpx.Request], status: int = 204) -> Any:
    async def fetch(request: httpx.Request) -> httpx.Response:
        log.append(request)
        return httpx.Response(status, request=request)

    return fetch


class TestSessionMethod:
    async def test_open_then_incremental_vouchers(self, fake_chain: dict[str, list[Any]]) -> None:
        updates: list[ChannelEntry] = []
        method = session(account=ACCOUNT, max_deposit="1", on_channel_update=updates.append)
        opened = payload_of(
            await method.create_credential(
                CredentialParams(challenge=make_challenge(suggested_deposit="10000"))
            )
        )
        assert opened["action"] == "open"
        assert opened["cumulativeAmount"] == "100"
        assert fake_chain["open"][0]["deposit"] == 10_000
        cumulative = [
            payload_of(await method.create_credential(CredentialParams(challenge=make_challenge())))
            for _ in range(3)
        ]
        assert [p["action"] for p in cumulative] == ["voucher"] * 3
        assert [p["cumulativeAmount"] for p in cumulative] == ["200", "300", "400"]
        assert {p["channelId"] for p in cumulative} == {opened["channelId"]}
        assert updates[-1].cumulative_amount == 400
        assert verify_voucher(
            ESCROW_ADDRESS,
            CHAIN_ID,
            _signed(cumulative[-1]),
            ACCOUNT.address,
        )
        credential = Credential.from_authorization(
            await method.create_credential(CredentialParams(challenge=make_challenge()))
        )
        assert credential.source == f"did:pkh:eip155:{CHAIN_ID}:{ACCOUNT.address}"

    async def test_open_deposit_respects_max_deposit(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT, max_deposit="0.002")
        await method.create_credential(
            CredentialParams(challenge=make_challenge(suggested_deposit="10000"))
        )
        assert fake_chain["open"][0]["deposit"] == 2000

    async def test_fee_payer_challenge_builds_sponsored_open(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT)
        await method.create_credential(CredentialParams(challenge=make_challenge(fee_payer=True)))
        assert fake_chain["open"][0]["fee_payer"] is True

    async def test_voucher_beyond_max_deposit_rejected(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT, max_deposit="0.0002")
        await method.create_credential(
            CredentialParams(challenge=make_challenge(suggested_deposit="200"))
        )
        await method.create_credential(CredentialParams(challenge=make_challenge()))
        with pytest.raises(ValueError, match="exceeds local maxDeposit"):
            await method.create_credential(CredentialParams(challenge=make_challenge()))

    async def test_tops_up_exact_shortfall_before_voucher(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT, max_deposit="1")
        await method.create_credential(CredentialParams(challenge=make_challenge()))
        log: list[httpx.Request] = []
        request = httpx.Request("GET", "http://api.test/paid#frag")
        voucher = payload_of(
            await method.create_credential(
                CredentialParams(
                    challenge=make_challenge(), request=request, fetch=_topup_fetch(log)
                )
            )
        )
        assert voucher["action"] == "voucher" and voucher["cumulativeAmount"] == "200"
        (post,) = log
        assert post.method == "POST" and str(post.url) == "http://api.test/paid"
        top_up = payload_of(post.headers["authorization"])
        assert top_up["action"] == "topUp" and top_up["additionalDeposit"] == "100"
        assert fake_chain["top_up"][0]["additional"] == 100

    async def test_top_up_uses_suggestion_and_top_up_amount(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT, top_up_amount="0.0005")
        await method.create_credential(CredentialParams(challenge=make_challenge()))
        log: list[httpx.Request] = []
        await method.create_credential(
            CredentialParams(
                challenge=make_challenge(suggested_deposit="900"),
                request=httpx.Request("GET", "http://api.test/paid"),
                fetch=_topup_fetch(log),
            )
        )
        assert payload_of(log[0].headers["authorization"])["additionalDeposit"] == "500"

    async def test_insufficient_deposit_without_request_fails(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT)
        await method.create_credential(CredentialParams(challenge=make_challenge()))
        with pytest.raises(ValueError, match="cannot cover the next voucher"):
            await method.create_credential(CredentialParams(challenge=make_challenge()))

    async def test_failed_top_up_post_raises(self, fake_chain: dict[str, list[Any]]) -> None:
        method = session(account=ACCOUNT)
        await method.create_credential(CredentialParams(challenge=make_challenge()))
        with pytest.raises(RuntimeError, match="Top-up POST failed with status 400"):
            await method.create_credential(
                CredentialParams(
                    challenge=make_challenge(),
                    request=httpx.Request("GET", "http://api.test/paid"),
                    fetch=_topup_fetch([], status=400),
                )
            )

    async def test_unknown_top_up_outcome_blocks_further_funding(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        store = create_channel_store()
        method = session(account=ACCOUNT, channel_store=store)
        await method.create_credential(CredentialParams(challenge=make_challenge()))

        async def broken(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        params = CredentialParams(
            challenge=make_challenge(),
            request=httpx.Request("GET", "http://api.test/paid"),
            fetch=broken,
        )
        from mpp.methods.tempo.session.client import UncertainFundingError

        with pytest.raises(UncertainFundingError):
            await method.create_credential(params)
        (entry,) = store._channels.values()  # pyright: ignore[reportPrivateUsage]
        assert entry.uncertain_top_up
        with pytest.raises(UncertainFundingError, match="reconcile"):
            await method.create_credential(params)

    async def test_concurrent_credentials_are_serialized_per_channel(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        method = session(account=ACCOUNT)
        results = await asyncio.gather(
            *(
                method.create_credential(
                    CredentialParams(challenge=make_challenge(suggested_deposit="100000"))
                )
                for _ in range(10)
            )
        )
        payloads = [payload_of(result) for result in results]
        assert len(fake_chain["open"]) == 1
        assert sorted(int(p["cumulativeAmount"]) for p in payloads) == list(range(100, 1100, 100))
        assert len({p["channelId"] for p in payloads}) == 1

    async def test_manual_close_marks_channel_closed(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        store = create_channel_store()
        updates: list[ChannelEntry] = []
        method = SessionMethod(
            account=ACCOUNT, channel_store=store, on_channel_update=updates.append
        )
        await method.create_session_credential(make_challenge())
        entry = updates[-1]
        close = payload_of(
            await method.create_session_credential(
                make_challenge(),
                SessionContext(
                    action="close",
                    channel_id=entry.channel_id,
                    descriptor=entry.descriptor,
                    cumulative_amount_raw="100",
                ),
            )
        )
        assert close["action"] == "close" and close["closeSignature"].startswith("0x")
        assert not updates[-1].opened
        assert (
            store.get(
                channel_key(payee=PAYEE, token=TOKEN, escrow=ESCROW_ADDRESS, chain_id=CHAIN_ID)
            )
            is None
        )

    async def test_lazy_exports(self) -> None:
        assert tempo_client.session is session
        assert tempo_client.session_manager is session_manager


def _signed(payload: dict[str, Any]) -> Any:
    from mpp.methods.tempo.session.protocol import SignedVoucher

    return SignedVoucher(
        channel_id=payload["channelId"],
        cumulative_amount=int(payload["cumulativeAmount"]),
        signature=payload["signature"],
    )


# ── HTTP: Mpp and the session manager (SessionManager.ts) ─────────


class FakeSessionServer:
    """A minimal mppx-like session server: 402 then accept, 204 for management POSTs."""

    def __init__(self, *, suggested_deposit: str | None = None) -> None:
        self.suggested_deposit = suggested_deposit
        self.requests: list[httpx.Request] = []
        self.spent = 0
        self.accepted = 0
        self.last_challenge: Challenge | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        authorization = request.headers.get("authorization")
        if authorization is None:
            challenge = make_challenge(suggested_deposit=self.suggested_deposit)
            self.last_challenge = challenge
            return httpx.Response(
                402, headers={"WWW-Authenticate": challenge.to_www_authenticate("api.test")}
            )
        credential = Credential.from_authorization(authorization)
        payload = credential.payload
        action = payload["action"]
        if action in ("open", "voucher"):
            self.accepted = int(payload["cumulativeAmount"])
            self.spent += 100
        receipt = create_session_receipt(
            challenge_id=credential.challenge.id,
            channel_id=payload["channelId"],
            accepted_cumulative=self.accepted
            if action != "close"
            else int(payload["cumulativeAmount"]),
            spent=self.spent,
            tx_hash="0x" + "ee" * 32 if action in ("topUp", "close") else None,
        )
        headers = {"Payment-Receipt": serialize_session_receipt(receipt)}
        if request.method == "POST":
            return httpx.Response(204, headers=headers)
        return httpx.Response(200, headers=headers, json={"paid": True})


class TestHttp:
    async def test_mpp_pays_session_challenges_with_top_ups(
        self, fake_chain: dict[str, list[Any]]
    ) -> None:
        server = FakeSessionServer()
        async with Mpp(
            methods=[session(account=ACCOUNT, max_deposit="1")],
        ) as mpp:
            mpp.payment_transport._inner = httpx.MockTransport(server.handler)  # pyright: ignore[reportPrivateUsage]
            for _ in range(3):
                response = await mpp.fetch("http://api.test/paid")
                assert response.status_code == 200
        actions = [
            (r.method, payload_of(r.headers["authorization"])["action"])
            for r in server.requests
            if "authorization" in r.headers
        ]
        assert actions == [
            ("GET", "open"),
            ("POST", "topUp"),
            ("GET", "voucher"),
            ("POST", "topUp"),
            ("GET", "voucher"),
        ]
        assert all(
            r.headers["accept-payment"] == "tempo/session"
            for r in server.requests
            if r.method == "GET" and "authorization" not in r.headers
        )

    async def test_manager_fetch_top_up_close(self, fake_chain: dict[str, list[Any]]) -> None:
        server = FakeSessionServer(suggested_deposit="1000")
        async with SessionManager(
            account=ACCOUNT, max_deposit="1", transport=httpx.MockTransport(server.handler)
        ) as manager:
            with pytest.raises(ValueError, match="no open channel"):
                await manager.top_up("1")
            first = await manager.fetch("http://api.test/paid")
            assert first.status_code == 200 and first.json() == {"paid": True}
            assert first.receipt is not None and first.receipt.accepted_cumulative == "100"
            second = await manager.fetch("http://api.test/paid")
            assert second.cumulative == 200 == manager.cumulative
            assert manager.deposit == 1000
            assert manager.spent == 200
            hinted = [r for r in server.requests if r.method == "GET"][2]
            assert hinted.headers["payment-session"] == manager.channel_id

            receipt = await manager.top_up("0.0005")
            assert receipt is not None
            assert manager.deposit == 1500
            post = server.requests[-1]
            assert payload_of(post.headers["authorization"])["additionalDeposit"] == "500"

            channel_id = manager.channel_id
            closed = await manager.close()
            assert closed is not None and closed.channel_id == channel_id
            close_payload = payload_of(server.requests[-1].headers["authorization"])
            assert close_payload["action"] == "close" and close_payload["cumulativeAmount"] == "200"
            assert not manager.opened

    async def test_manager_rejects_concurrent_fetch(self, fake_chain: dict[str, list[Any]]) -> None:
        gate = asyncio.Event()
        server = FakeSessionServer()

        async def handler(request: httpx.Request) -> httpx.Response:
            await gate.wait()
            return server.handler(request)

        manager = session_manager(account=ACCOUNT, transport=httpx.MockTransport(handler))
        first = asyncio.create_task(manager.fetch("http://api.test/paid"))
        await asyncio.sleep(0)
        with pytest.raises(RuntimeError, match="already in flight"):
            await manager.fetch("http://api.test/paid")
        gate.set()
        assert (await first).status_code == 200
        await manager.aclose()

    async def test_manager_rolls_back_rejected_open(self, fake_chain: dict[str, list[Any]]) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "authorization" not in request.headers:
                challenge = make_challenge()
                return httpx.Response(
                    402, headers={"WWW-Authenticate": challenge.to_www_authenticate("api.test")}
                )
            return httpx.Response(400, json={"error": "rejected"})

        store = create_channel_store()
        async with SessionManager(
            account=ACCOUNT, channel_store=store, transport=httpx.MockTransport(handler)
        ) as manager:
            response = await manager.fetch("http://api.test/paid")
            assert response.status_code == 400
            assert manager.channel_id is None
            assert not store._channels  # pyright: ignore[reportPrivateUsage]
