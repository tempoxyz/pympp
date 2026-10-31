"""Session bootstrap and snapshots: proofs, snapshot codec, preflight, hints, client recovery.

Ports mppx Snapshot.test.ts, the bootstrap cases of server/Session.test.ts and RequestState.test.ts,
and client CredentialState hydrateSessionSnapshot / SessionManager bootstrap cases.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp.errors import InvalidChallengeError, PaymentExpiredError
from mpp.methods.tempo import server as tempo_server
from mpp.methods.tempo.account import TempoAccount
from mpp.methods.tempo.session import _chain as chain
from mpp.methods.tempo.session._channel import compute_channel_id
from mpp.methods.tempo.session._proof import (
    parse_pkh_source,
    proof_digest,
    proof_source,
    sign_proof,
    verify_proof,
)
from mpp.methods.tempo.session._protocol import (
    ESCROW_ADDRESS,
    ZERO_ADDRESS,
    ChannelDescriptor,
    SignedVoucher,
)
from mpp.methods.tempo.session._snapshot import (
    SessionSnapshot,
    deserialize_snapshot,
    hydrate_session_snapshot,
    serialize_snapshot,
)
from mpp.methods.tempo.session.client import SessionManager, session_manager
from mpp.methods.tempo.session.server import ResolveSessionChannelIdParameters
from mpp.methods.tempo.session.server import _bootstrap as bootstrap
from mpp.methods.tempo.session.server._request_state import (
    SnapshotPaymentFields,
    resolve_session_channel_id,
    resolve_session_snapshot,
)
from mpp.methods.tempo.session.server._store import ChannelState, from_store
from mpp.server import Mpp, PaymentRequired, PreflightContext, Request, Response, compose
from mpp.server.verify import (
    _create_challenge,  # pyright: ignore[reportPrivateUsage]
    _requests_match,  # pyright: ignore[reportPrivateUsage]
)
from mpp.store import MemoryStore
from tests import http_request, server_method
from tests.session_helpers import sign
from tests.test_session_chain import CHAIN_ID, CURRENCY, OTHER_TOKEN, PAYEE, PAYER, RPC

DESCRIPTOR = ChannelDescriptor(
    payer=PAYER.address,
    payee=PAYEE.address,
    operator=ZERO_ADDRESS,
    token=CURRENCY,
    salt="0x" + "01" * 32,
    authorized_signer=ZERO_ADDRESS,
    expiring_nonce_hash="0x" + "ab" * 32,
)
CHANNEL_ID = compute_channel_id(DESCRIPTOR, chain_id=CHAIN_ID)
URL = "https://api.test/paid"
REALM = "api.test"
SECRET = "secret"
SOURCE = proof_source(PAYER.address, CHAIN_ID)


def stored(**overrides: Any) -> ChannelState:
    fields: dict[str, Any] = {
        "channel_id": CHANNEL_ID,
        "authorized_signer": PAYER.address,
        "chain_id": CHAIN_ID,
        "escrow_contract": ESCROW_ADDRESS,
        "payer": PAYER.address,
        "payee": PAYEE.address,
        "token": CURRENCY,
        "deposit": 1_000,
        "settled_on_chain": 50,
        "highest_voucher_amount": 300,
        "highest_voucher": SignedVoucher(
            channel_id=CHANNEL_ID, cumulative_amount=300, signature=sign(CHANNEL_ID, 300)
        ),
        "spent": 100,
        "units": 2,
        "close_requested_at": 0,
        "finalized": False,
        "created_at": "t",
        "backend": "precompile",
        "descriptor": DESCRIPTOR,
    }
    fields.update(overrides)
    return ChannelState(**fields)


async def channel_store(state: ChannelState | None = None) -> Any:
    store = from_store(MemoryStore())
    if state is not None:
        await store.update_channel(state.channel_id, lambda _: state)
    return store


def snapshot(**overrides: Any) -> SessionSnapshot:
    fields: dict[str, Any] = {
        "accepted_cumulative": 300,
        "chain_id": CHAIN_ID,
        "channel_id": CHANNEL_ID,
        "deposit": 1_000,
        "descriptor": DESCRIPTOR,
        "escrow": ESCROW_ADDRESS,
        "required_cumulative": 100,
        "settled": 50,
        "spent": 100,
        "highest_voucher": SignedVoucher(
            channel_id=CHANNEL_ID, cumulative_amount=300, signature=sign(CHANNEL_ID, 300)
        ),
        "units": 2,
    }
    fields.update(overrides)
    return SessionSnapshot(**fields)


# --------------------------------------------------------------------------------------------
# Proofs
# --------------------------------------------------------------------------------------------


class TestProof:
    def test_digest_and_signature_match_eip712_typed_data(self) -> None:
        account = Account.create()
        typed = encode_typed_data(
            full_message={
                "types": {
                    "EIP712Domain": [
                        {"name": "name", "type": "string"},
                        {"name": "version", "type": "string"},
                        {"name": "chainId", "type": "uint256"},
                    ],
                    "Proof": [
                        {"name": "account", "type": "address"},
                        {"name": "challengeId", "type": "string"},
                        {"name": "realm", "type": "string"},
                    ],
                },
                "primaryType": "Proof",
                "domain": {"name": "MPP", "version": "3", "chainId": 4217},
                "message": {"account": account.address, "challengeId": "c", "realm": "r"},
            }
        )
        expected = account.sign_message(typed).signature.hex()
        signature = sign_proof(account, chain_id=4217, challenge_id="c", realm="r")
        assert signature.removeprefix("0x") == expected.removeprefix("0x")
        assert verify_proof(
            signature, account=account.address, chain_id=4217, challenge_id="c", realm="r"
        )
        assert proof_digest(account=account.address, chain_id=4217, challenge_id="c", realm="r")

    def test_rejects_other_accounts_challenges_and_malformed_input(self) -> None:
        signature = sign_proof(PAYER, chain_id=CHAIN_ID, challenge_id="c", realm="r")
        verify = {"chain_id": CHAIN_ID, "challenge_id": "c", "realm": "r"}
        assert verify_proof(signature, account=PAYER.address, **verify)
        assert not verify_proof(signature, account=PAYEE.address, **verify)
        assert not verify_proof(signature, account=PAYER.address, **{**verify, "realm": "x"})
        assert not verify_proof("0xzz", account=PAYER.address, **verify)
        assert not verify_proof(signature, account="not-an-address", **verify)

    def test_pkh_sources(self) -> None:
        assert parse_pkh_source(SOURCE) == (PAYER.address, CHAIN_ID)
        for bad in ("did:pkh:eip155:01:" + PAYER.address, "did:pkh:eip155:1:0x12", "x"):
            assert parse_pkh_source(bad) is None


# --------------------------------------------------------------------------------------------
# Snapshot codec
# --------------------------------------------------------------------------------------------


class TestSnapshotCodec:
    def test_round_trips_as_base64_json(self) -> None:
        value = snapshot(close_requested_at=7)
        header = serialize_snapshot(value)
        decoded = json.loads(base64.b64decode(header))
        assert decoded["acceptedCumulative"] == "300" and decoded["closeRequestedAt"] == "7"
        assert decoded["descriptor"]["authorizedSigner"] == ZERO_ADDRESS
        assert deserialize_snapshot(header) == value
        # Unpadded and URL-safe encodings decode too.
        assert deserialize_snapshot(header.rstrip("=").replace("+", "-").replace("/", "_")) == value

    def test_optional_fields_are_omitted(self) -> None:
        value = snapshot(highest_voucher=None, units=None)
        wire = value.to_wire()
        assert "highestVoucher" not in wire and "units" not in wire
        assert "closeRequestedAt" not in wire
        assert SessionSnapshot.from_wire(wire) == value

    @pytest.mark.parametrize(
        "change",
        [
            {"descriptor": None},
            {"chainId": "1"},
            {"chainId": True},
            {"escrow": "0x12"},
            {"channelId": "0x12"},
            {"spent": "-1"},
            {"spent": 5},
            {"units": "2"},
            {"highestVoucher": "x"},
            {
                "highestVoucher": {
                    "channelId": CHANNEL_ID,
                    "cumulativeAmount": "1",
                    "signature": "x",
                }
            },
            {"descriptor": {**DESCRIPTOR.to_wire(), "salt": "0x01"}},
            {"descriptor": {**DESCRIPTOR.to_wire(), "payer": "nope"}},
        ],
    )
    def test_rejects_invalid_fields(self, change: dict[str, Any]) -> None:
        wire = {**snapshot().to_wire(), **change}
        with pytest.raises(ValueError):
            SessionSnapshot.from_wire(wire)

    def test_rejects_missing_fields_and_bad_headers(self) -> None:
        wire = snapshot().to_wire()
        del wire["deposit"]
        with pytest.raises(ValueError, match="missing deposit"):
            SessionSnapshot.from_wire(wire)
        with pytest.raises(ValueError, match="must be an object"):
            SessionSnapshot.from_wire([])
        with pytest.raises(ValueError, match="Invalid base64 JSON header"):
            deserialize_snapshot("!!!")
        with pytest.raises(ValueError, match="Invalid base64 JSON header"):
            deserialize_snapshot(base64.b64encode(b"not json").decode())


# --------------------------------------------------------------------------------------------
# Server: channel resolution and snapshot hints
# --------------------------------------------------------------------------------------------

EXPECTED = SnapshotPaymentFields(
    chain_id=CHAIN_ID, currency=CURRENCY, escrow_contract=ESCROW_ADDRESS, recipient=PAYEE.address
)


class TestResolveSnapshot:
    async def test_advertises_a_reusable_channel(self) -> None:
        store = await channel_store(stored())
        result = await resolve_session_snapshot(
            amount=10,
            channel_id=CHANNEL_ID.upper().replace("0X", "0x"),
            store=store,
            expected=EXPECTED,
        )
        assert result == snapshot(required_cumulative=110)

    async def test_required_cumulative_covers_a_voucher_advance(self) -> None:
        store = await channel_store(stored())
        result = await resolve_session_snapshot(
            amount=0, channel_id=CHANNEL_ID, store=store, require_voucher_advance=True
        )
        assert result is not None and result.required_cumulative == 301
        result = await resolve_session_snapshot(
            amount=0,
            channel_id=CHANNEL_ID,
            store=store,
            require_voucher_advance=True,
            minimum_voucher_advance=50,
        )
        assert result is not None and result.required_cumulative == 350

    @pytest.mark.parametrize(
        "overrides",
        [
            {"backend": "contract"},
            {"descriptor": None},
            {"finalized": True},
            {"close_requested_at": 5},
            {"highest_voucher": None},
            {"highest_voucher_amount": 299},
            {"token": OTHER_TOKEN},
            {"payee": PAYER.address},
            {"chain_id": 1},
            {"escrow_contract": OTHER_TOKEN},
        ],
    )
    async def test_withholds_channels_it_cannot_advertise(self, overrides: dict[str, Any]) -> None:
        store = await channel_store(stored(**overrides))
        assert (
            await resolve_session_snapshot(
                amount=0, channel_id=CHANNEL_ID, store=store, expected=EXPECTED
            )
            is None
        )

    async def test_missing_channels(self) -> None:
        store = await channel_store()
        assert await resolve_session_snapshot(amount=0, channel_id=None, store=store) is None
        assert await resolve_session_snapshot(amount=0, channel_id=CHANNEL_ID, store=store) is None


class TestResolveChannelId:
    async def test_route_channel_id_wins(self) -> None:
        def never(_: ResolveSessionChannelIdParameters) -> str:
            raise AssertionError

        result = await resolve_session_channel_id(
            request=None,
            credential=None,
            payment_request={"channel_id": CHANNEL_ID.upper().replace("0X", "0x")},
            resolve_channel_id=never,
            store=None,
        )
        assert result == CHANNEL_ID

    async def test_resolver_sees_the_credential_only_with_a_source(self) -> None:
        seen: list[ResolveSessionChannelIdParameters] = []

        async def resolver(params: ResolveSessionChannelIdParameters) -> str | None:
            seen.append(params)
            return CHANNEL_ID if params.source else None

        credential = Credential(
            challenge=ChallengeEcho(
                id="i", realm="r", method="tempo", intent="charge", request="e30"
            ),
            payload={},
        )
        request = Request("HEAD", URL)
        common: dict[str, Any] = {
            "request": request,
            "credential": credential,
            "payment_request": {"amount": "1"},
            "resolve_channel_id": resolver,
            "store": "store",
        }
        assert await resolve_session_channel_id(**common) is None
        assert await resolve_session_channel_id(**common, source=SOURCE) == CHANNEL_ID
        assert seen[0].credential is None and seen[1].credential is credential
        assert seen[1].request is request and seen[1].store == "store"
        assert await resolve_session_channel_id(**{**common, "resolve_channel_id": None}) is None


def method(**options: Any) -> Any:
    return tempo_server.session(account=PAYEE, chain_id=CHAIN_ID, rpc_url=RPC, **options)


class TestChallengeSnapshot:
    async def test_challenges_carry_the_resolved_channel_snapshot(self) -> None:
        raw = MemoryStore()
        store = from_store(raw)
        await store.update_channel(CHANNEL_ID, lambda _: stored())
        handler = Mpp(
            methods=[method(store=raw, resolve_channel_id=lambda _: CHANNEL_ID)],
            realm=REALM,
            secret_key=SECRET,
        ).session(amount="0.0001", unit_type="request")
        first = await handler(Request("GET", URL))
        assert isinstance(first, PaymentRequired)
        issued = Challenge.from_www_authenticate(first.challenge.headers["www-authenticate"])
        details = issued.request["methodDetails"]
        # A GET is content: the next voucher must advance past the accepted amount.
        assert details["sessionSnapshot"]["requiredCumulative"] == "301"
        assert details["sessionSnapshot"]["channelId"] == CHANNEL_ID
        # A bare POST is management: nothing is due.
        post = await handler(Request("POST", URL))
        assert isinstance(post, PaymentRequired)
        posted = Challenge.from_www_authenticate(post.challenge.headers["www-authenticate"])
        assert posted.request["methodDetails"]["sessionSnapshot"]["requiredCumulative"] == "100"
        # The snapshot moves with the spend, but an echoed older one still binds the route.
        await store.update_channel(CHANNEL_ID, lambda _: stored(spent=200))
        second = await handler(Request("GET", URL))
        assert isinstance(second, PaymentRequired)
        reissued = Challenge.from_www_authenticate(second.challenge.headers["www-authenticate"])
        assert reissued.request != issued.request
        binding = handler.methods[0].stable_binding
        assert _requests_match(dict(issued.request), dict(reissued.request), binding)

    async def test_no_snapshot_without_a_resolved_channel(self) -> None:
        handler = Mpp(
            methods=[method(store=MemoryStore(), resolve_channel_id=lambda _: None)],
            realm=REALM,
            secret_key=SECRET,
        ).session(amount="1", unit_type="request")
        result = await handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        issued = Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])
        assert "sessionSnapshot" not in issued.request["methodDetails"]


# --------------------------------------------------------------------------------------------
# Server: bootstrap preflight
# --------------------------------------------------------------------------------------------


class Bootstrap:
    def __init__(self, resolve: Any = None, **server: Any) -> None:
        self.raw = MemoryStore()
        self.sources: list[str | None] = []

        def resolver(params: ResolveSessionChannelIdParameters) -> str | None:
            self.sources.append(params.source)
            return CHANNEL_ID

        self.handler = Mpp(
            methods=[
                method(store=self.raw, bootstrap=True, resolve_channel_id=resolve or resolver)
            ],
            realm=REALM,
            secret_key=SECRET,
            **server,
        ).session(amount="1", unit_type="request")

    async def seed(self, **overrides: Any) -> None:
        state = stored(**overrides)
        await from_store(self.raw).update_channel(CHANNEL_ID, lambda _: state)

    async def challenge(self) -> Challenge:
        result = await self.handler(Request("HEAD", URL))
        assert isinstance(result, PaymentRequired) and result.status == 402
        return Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])

    async def prove(
        self,
        challenge: Challenge | None = None,
        *,
        account: Any = PAYER,
        source: str | None = SOURCE,
        payload: dict[str, Any] | None = None,
        header: str = "Authorization",
    ) -> Response:
        challenge = challenge or await self.challenge()
        signature = sign_proof(
            account, chain_id=CHAIN_ID, challenge_id=challenge.id, realm=challenge.realm
        )
        credential = Credential(
            challenge=challenge.to_echo(),
            payload=payload or {"signature": signature, "type": "proof"},
            source=source,
        ).to_authorization()
        result = await self.handler(Request("HEAD", URL, headers={header: credential}))
        assert isinstance(result, PaymentRequired)
        return result.challenge


def problem(response: Response) -> dict[str, Any]:
    return json.loads(response.body or b"")


class TestBootstrapPreflight:
    async def test_head_without_a_credential_gets_a_zero_amount_charge_challenge(self) -> None:
        boot = Bootstrap()
        result = await boot.handler(Request("HEAD", URL))
        assert isinstance(result, PaymentRequired) and result.status == 402
        assert result.challenge.headers["cache-control"] == "no-store"
        issued = Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])
        assert (issued.method, issued.intent, issued.realm) == ("tempo", "charge", REALM)
        assert issued.request == {
            "amount": "0",
            "currency": CURRENCY.lower(),
            "recipient": PAYEE.address,
            "methodDetails": {"chainId": CHAIN_ID},
        }
        assert issued.expires

    async def test_other_methods_get_the_session_challenge(self) -> None:
        result = await Bootstrap().handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        issued = Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])
        assert issued.intent == "session"

    async def test_a_valid_proof_returns_the_snapshot(self) -> None:
        boot = Bootstrap()
        await boot.seed()
        response = await boot.prove()
        assert response.status == 204
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["payment-session"] == CHANNEL_ID
        assert deserialize_snapshot(response.headers["payment-session-snapshot"]) == snapshot()
        assert boot.sources == [SOURCE]

    async def test_a_proof_is_accepted_once(self) -> None:
        boot = Bootstrap()
        issued = await boot.challenge()
        assert (await boot.prove(issued)).status == 204
        replayed = await boot.prove(issued)
        assert replayed.status == 403
        assert "www-authenticate" not in replayed.headers
        assert "already been used" in problem(replayed)["detail"]

    async def test_no_snapshot_without_a_reusable_channel(self) -> None:
        boot = Bootstrap(resolve=lambda _: None)
        response = await boot.prove()
        assert response.status == 204
        assert "payment-session" not in response.headers

    @pytest.mark.parametrize(
        ("prove", "detail"),
        [
            ({"account": PAYEE}, "does not match source"),
            ({"source": None}, "must include a source"),
            ({"source": proof_source(PAYER.address, 1)}, "source is invalid"),
            ({"source": "did:web:x"}, "source is invalid"),
            ({"payload": {"type": "transaction", "signature": "0x00"}}, "proof credential"),
        ],
    )
    async def test_rejects_invalid_proofs_with_a_fresh_challenge(
        self, prove: dict[str, Any], detail: str
    ) -> None:
        response = await Bootstrap().prove(**prove)
        assert response.status == 402
        assert "www-authenticate" in response.headers
        assert response.headers["content-type"] == "application/problem+json"
        assert detail in problem(response)["detail"]

    async def test_rejects_challenges_this_route_did_not_issue(self) -> None:
        boot = Bootstrap()
        request = dict((await boot.challenge()).request)
        foreign = _create_challenge("tempo", "charge", request, REALM, "other-secret")
        rejected = await boot.prove(foreign)
        assert rejected.status == 402 and "invalid" in problem(rejected)["detail"]
        for change, reason in (
            ({"amount": "1"}, "amount mismatch"),
            ({"currency": OTHER_TOKEN}, "currency mismatch"),
            ({"recipient": PAYER.address}, "recipient mismatch"),
            ({"methodDetails": {"chainId": 1}}, "chain mismatch"),
        ):
            issued = _create_challenge("tempo", "charge", {**request, **change}, REALM, SECRET)
            response = await boot.prove(issued)
            assert response.status == 402 and reason in problem(response)["detail"]
        expired = _create_challenge(
            "tempo",
            "charge",
            request,
            REALM,
            SECRET,
            expires=(datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        )
        assert "expired" in problem(await boot.prove(expired))["detail"]

    async def test_session_credentials_on_head_continue_to_verification(self) -> None:
        boot = Bootstrap()
        result = await boot.handler(Request("GET", URL))
        assert isinstance(result, PaymentRequired)
        issued = Challenge.from_www_authenticate(result.challenge.headers["www-authenticate"])
        credential = Credential(
            challenge=issued.to_echo(), payload={"action": "voucher"}, source=SOURCE
        ).to_authorization()
        verified = await boot.handler(Request("HEAD", URL, headers={"Authorization": credential}))
        assert isinstance(verified, PaymentRequired)
        rejected = Challenge.from_www_authenticate(verified.challenge.headers["www-authenticate"])
        assert rejected.intent == "session"

    async def test_requires_auth_servers_bind_the_proof_header(self) -> None:
        boot = Bootstrap(requires_auth=True)
        issued = await boot.challenge()
        assert issued.credential_header == "Payment-Authorization"
        assert (await boot.prove(issued, header="Payment-Authorization")).status == 204

    async def test_unexpected_failures_are_internal_errors(self) -> None:
        class BrokenStore(MemoryStore):
            async def put_if_absent_until(self, key: str, value: Any, expires_at: float) -> bool:
                raise RuntimeError("down")

        boot = Bootstrap()
        boot.raw.__class__ = BrokenStore
        response = await boot.prove()
        assert response.status == 500
        assert "www-authenticate" in response.headers


class TestBootstrapInternals:
    def context(self, credential: Credential | None, **request: Any) -> PreflightContext:
        return PreflightContext(
            input=Request("HEAD", URL),
            request={"currency": CURRENCY, "recipient": PAYEE.address, **request},
            credential=credential,
            realm=REALM,
            secret_key=SECRET,
        )

    async def test_non_head_requests_continue(self) -> None:
        context = replace(self.context(None), input=Request("GET", URL))
        assert (
            await bootstrap.handle_bootstrap_preflight(
                context,
                chain_id=CHAIN_ID,
                escrow_contract=None,
                resolve_channel_id=None,
                store=None,
                proof_store=MemoryStore(),
            )
            is None
        )

    @pytest.mark.parametrize(
        ("request_fields", "detail"),
        [
            ({"currency": "usd"}, "missing bootstrap currency"),
            ({"recipient": None}, "missing bootstrap recipient"),
        ],
    )
    async def test_requires_a_currency_and_recipient(
        self, request_fields: dict[str, Any], detail: str
    ) -> None:
        echo = ChallengeEcho(id="i", realm=REALM, method="tempo", intent="charge", request="e30")
        context = self.context(Credential(challenge=echo, payload={}), **request_fields)
        response = await bootstrap.handle_bootstrap_preflight(
            context,
            chain_id=CHAIN_ID,
            escrow_contract=None,
            resolve_channel_id=None,
            store=None,
            proof_store=MemoryStore(),
        )
        assert response is not None and detail in problem(response)["detail"]

    async def test_route_chain_and_escrow_override_the_defaults(self) -> None:
        context = self.context(None, chain_id=7, escrow_contract=OTHER_TOKEN)
        response = await bootstrap.handle_bootstrap_preflight(
            context,
            chain_id=CHAIN_ID,
            escrow_contract=None,
            resolve_channel_id=None,
            store=None,
            proof_store=MemoryStore(),
        )
        assert response is not None
        issued = Challenge.from_www_authenticate(response.headers["www-authenticate"])
        assert issued.request["methodDetails"] == {"chainId": 7}

    def test_expiry_checks_fail_closed(self) -> None:
        echo = ChallengeEcho(id="i", realm=REALM, method="tempo", intent="charge", request="e30")
        for expires in (None, "soon", "2030-01-01T00:00:00"):
            with pytest.raises(InvalidChallengeError):
                bootstrap._assert_not_expired(replace(echo, expires=expires))  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(PaymentExpiredError):
            bootstrap._assert_not_expired(replace(echo, expires="2000-01-01T00:00:00Z"))  # pyright: ignore[reportPrivateUsage]

    async def test_plain_stores_claim_proofs_without_expiry(self) -> None:
        class PlainStore:
            def __init__(self) -> None:
                self.keys: set[str] = set()

            async def get(self, key: str) -> Any:
                return None

            async def put(self, key: str, value: Any) -> None: ...

            async def delete(self, key: str) -> None: ...

            async def put_if_absent(self, key: str, value: Any) -> bool:
                if key in self.keys:
                    return False
                self.keys.add(key)
                return True

        store: Any = PlainStore()
        claim = bootstrap._claim_proof  # pyright: ignore[reportPrivateUsage]
        assert await claim(store, "c", "2030-01-01T00:00:00Z")
        assert not await claim(store, "c", "2030-01-01T00:00:00Z")
        assert store.keys == {"mppx:charge:proof:c"}


# --------------------------------------------------------------------------------------------
# Engine preflight hook
# --------------------------------------------------------------------------------------------


async def _paid(_: Any) -> Receipt:
    return Receipt.success("0xabc")


class TestPreflightHook:
    async def test_a_response_handles_the_request(self) -> None:
        seen: list[PreflightContext] = []

        def preflight(context: PreflightContext) -> Response | None:
            seen.append(context)
            return Response(204) if context.input.method == "HEAD" else None

        server = Mpp(
            methods=server_method(verify=_paid, preflight=preflight),
            realm="example.com",
            secret_key="secret",
        )
        handler = server.charge(amount="1", expires_in=timedelta(minutes=1))
        handled = await handler(http_request(method="HEAD"))
        assert isinstance(handled, PaymentRequired) and handled.status == 204
        assert seen[0].request["amount"] == "1" and seen[0].credential is None
        assert seen[0].realm == "example.com" and seen[0].secret_key == "secret"
        assert seen[0].expires is not None and seen[0].header is None
        unpaid = await handler(http_request())
        assert isinstance(unpaid, PaymentRequired) and unpaid.status == 402

    async def test_mcp_calls_skip_preflight_and_bad_returns_raise(self) -> None:
        async def preflight(_: PreflightContext) -> Any:
            return "not a response"

        server = Mpp(
            methods=server_method(verify=_paid, preflight=preflight),
            realm="example.com",
            secret_key="secret",
        )
        handler = server.charge(amount="1")
        mcp = await handler(http_request(url="mcp:tool"))
        assert isinstance(mcp, PaymentRequired) and mcp.status == 402
        with pytest.raises(TypeError, match="preflight must return"):
            await handler(http_request())

    async def test_composed_offers_dropped_by_can_offer_skip_preflight(self) -> None:
        calls: list[str] = []

        def preflight_for(name: str) -> Any:
            def preflight(context: PreflightContext) -> Response | None:
                calls.append(name)
                return Response(204) if context.input.method == "HEAD" else None

            return preflight

        hidden = Mpp(
            methods=server_method(
                verify=_paid, preflight=preflight_for("hidden"), can_offer=lambda _: False
            ),
            realm="example.com",
            secret_key="secret",
        )
        shown = Mpp(
            methods=server_method(verify=_paid, preflight=preflight_for("shown")),
            realm="example.com",
            secret_key="secret",
        )
        handler = compose(hidden.charge(amount="1"), shown.charge(amount="2"))
        handled = await handler(http_request(method="HEAD"))
        assert isinstance(handled, PaymentRequired) and handled.status == 204
        assert calls == ["shown"]

    def test_preflight_must_be_callable(self) -> None:
        with pytest.raises(ValueError, match="preflight must be callable"):
            server_method(verify=_paid, preflight="x")


# --------------------------------------------------------------------------------------------
# Client: snapshot hydration and manager bootstrap
# --------------------------------------------------------------------------------------------


def on_chain(
    monkeypatch: pytest.MonkeyPatch, *, settled: int = 50, deposit: int = 1_000, closing: int = 0
) -> None:
    async def get_channel_state(*_: Any, **__: Any) -> chain.ChannelState:
        return chain.ChannelState(settled=settled, deposit=deposit, close_requested_at=closing)

    monkeypatch.setattr(chain, "get_channel_state", get_channel_state)


class TestHydrate:
    async def test_returns_the_entry_and_spend(self, monkeypatch: pytest.MonkeyPatch) -> None:
        on_chain(monkeypatch, settled=400)
        entry, spent = await hydrate_session_snapshot(PAYER, snapshot(), rpc_url=RPC)
        assert spent == 100
        assert (entry.channel_id, entry.cumulative_amount, entry.deposit) == (CHANNEL_ID, 400, 1000)
        assert entry.opened and entry.descriptor == DESCRIPTOR and entry.chain_id == CHAIN_ID

    @pytest.mark.parametrize(
        ("change", "message"),
        [
            ({"highest_voucher": None}, "missing its highest signed voucher"),
            (
                {
                    "highest_voucher": SignedVoucher(
                        channel_id="0x" + "00" * 32, cumulative_amount=300, signature="0x00"
                    )
                },
                "voucher channelId",
            ),
            ({"accepted_cumulative": 200}, "voucher amount does not match"),
            ({"spent": 400}, "spent exceeds"),
            ({"settled": 2000}, "settled amount exceeds"),
            (
                {
                    "highest_voucher": SignedVoucher(
                        channel_id=CHANNEL_ID,
                        cumulative_amount=300,
                        signature=sign(CHANNEL_ID, 300, PAYEE),
                    )
                },
                "signature is invalid",
            ),
            ({"required_cumulative": 2000}, "exceeds on-chain channel deposit"),
        ],
    )
    async def test_rejects_inconsistent_snapshots(
        self, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any], message: str
    ) -> None:
        on_chain(monkeypatch)
        with pytest.raises(ValueError, match=message):
            await hydrate_session_snapshot(PAYER, snapshot(**change), rpc_url=RPC)

    async def test_rejects_channels_of_other_accounts_or_ids(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        on_chain(monkeypatch)
        with pytest.raises(ValueError, match="payer does not match"):
            await hydrate_session_snapshot(PAYEE, snapshot(), rpc_url=RPC)
        other = "0x" + "77" * 32
        mislabeled = snapshot(
            channel_id=other,
            highest_voucher=SignedVoucher(
                channel_id=other, cumulative_amount=300, signature=sign(other, 300)
            ),
        )
        with pytest.raises(ValueError, match="channelId does not match descriptor"):
            await hydrate_session_snapshot(PAYER, mislabeled, rpc_url=RPC)
        delegate = TempoAccount.from_key("0x" + "44" * 32)
        descriptor = replace(DESCRIPTOR, authorized_signer=delegate.address)
        channel_id = compute_channel_id(descriptor, chain_id=CHAIN_ID)
        delegated = snapshot(
            descriptor=descriptor,
            channel_id=channel_id,
            highest_voucher=SignedVoucher(
                channel_id=channel_id,
                cumulative_amount=300,
                signature=sign(channel_id, 300, delegate),
            ),
        )
        with pytest.raises(ValueError, match="authorizedSigner does not match"):
            await hydrate_session_snapshot(PAYER, delegated, rpc_url=RPC)

    @pytest.mark.parametrize(
        ("state", "message"),
        [({"deposit": 0}, "closed or not found"), ({"closing": 5}, "pending close")],
    )
    async def test_rejects_channels_that_are_not_reusable_on_chain(
        self, monkeypatch: pytest.MonkeyPatch, state: dict[str, int], message: str
    ) -> None:
        on_chain(monkeypatch, **state)
        with pytest.raises(ValueError, match=message):
            await hydrate_session_snapshot(PAYER, snapshot(), rpc_url=RPC)


class FakeServer:
    """A scripted bootstrap server for the manager's ``HEAD`` probes and paid requests."""

    def __init__(
        self,
        *,
        realm: str = REALM,
        amount: str = "0",
        details: dict[str, Any] | None = None,
        prove_status: int = 204,
        first_status: int = 402,
        header: str | None = None,
    ) -> None:
        self.realm = realm
        self.amount = amount
        self.details = {"chainId": CHAIN_ID} if details is None else details
        self.prove_status = prove_status
        self.first_status = first_status
        self.header = serialize_snapshot(snapshot()) if header is None else header
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method != "HEAD":
            return httpx.Response(200, json={"ok": True})
        authorization = request.headers.get("authorization")
        if authorization is None:
            if self.first_status != 402:
                return httpx.Response(
                    self.first_status, headers={"Payment-Session-Snapshot": self.header}
                )
            issued = _create_challenge(
                "tempo",
                "charge",
                {"amount": self.amount, "currency": CURRENCY, "methodDetails": self.details},
                self.realm,
                SECRET,
            )
            return httpx.Response(
                402,
                headers=[
                    ("WWW-Authenticate", 'Payment id="x", realm="r", method="tempo"'),
                    ("WWW-Authenticate", issued.to_www_authenticate(self.realm)),
                ],
            )
        credential = Credential.from_authorization(authorization)
        assert credential.payload["type"] == "proof" and credential.source == SOURCE
        echo = credential.challenge
        assert verify_proof(
            credential.payload["signature"],
            account=PAYER.address,
            chain_id=CHAIN_ID,
            challenge_id=echo.id,
            realm=echo.realm,
        )
        return httpx.Response(self.prove_status, headers={"Payment-Session-Snapshot": self.header})


def manager(server: FakeServer, monkeypatch: pytest.MonkeyPatch, **options: Any) -> SessionManager:
    on_chain(monkeypatch)
    created = session_manager(
        account=PAYER,
        transport=httpx.MockTransport(server.handle),
        bootstrap=options.pop("bootstrap", True),
        **options,
    )

    async def resolve_rpc(requested: int | None) -> tuple[str, int]:
        return RPC, CHAIN_ID if requested is None else requested

    monkeypatch.setattr(created._method, "_resolve_rpc", resolve_rpc)  # pyright: ignore[reportPrivateUsage]
    return created


def heads(server: FakeServer) -> list[bool]:
    """Whether each HEAD probe carried a credential."""
    return ["authorization" in r.headers for r in server.requests if r.method == "HEAD"]


class TestManagerBootstrap:
    async def test_recovers_the_channel_before_the_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer()
        async with manager(server, monkeypatch) as client:
            response = await client.fetch(URL, headers={"X-App": "1"}, content=b"body")
            assert response.status_code == 200
            assert client.channel_id == CHANNEL_ID and client.spent == 100
            assert client.cumulative == 300
            assert heads(server) == [False, True]
            head = server.requests[0]
            assert head.headers["accept-payment"] == "tempo/charge"
            assert head.headers["x-app"] == "1" and head.content == b""
            # The recovered channel is named on the paid request, and probed only once.
            assert server.requests[2].headers["payment-session"] == CHANNEL_ID
            await client.fetch(URL)
            assert heads(server) == [False, True]

    async def test_probes_keep_cookies_and_query_parameters(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer()
        async with manager(server, monkeypatch) as client:
            await client.fetch(URL, params={"user": "7"}, cookies={"sid": "abc"}, json={"q": 1})
            probes = [r for r in server.requests if r.method == "HEAD"]
            assert len(probes) == 2
            for probe in probes:
                assert probe.url.params["user"] == "7"
                assert probe.headers["cookie"] == "sid=abc" and probe.content == b""

    async def test_a_snapshot_on_the_first_response_is_used_directly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer(first_status=204)
        async with manager(server, monkeypatch) as client:
            await client.fetch(URL)
            assert client.channel_id == CHANNEL_ID and heads(server) == [False]

    async def test_realms_the_origin_does_not_own_get_no_proof(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer(realm="other.test")
        async with manager(server, monkeypatch) as client:
            await client.fetch(URL)
            assert client.channel_id is None and heads(server) == [False]
        server = FakeServer(realm="other.test")
        trusted = {"https://api.test": "other.test"}
        async with manager(server, monkeypatch, trusted_tempo_realms=trusted) as client:
            await client.fetch(URL)
            assert client.channel_id == CHANNEL_ID and heads(server) == [False, True]

    @pytest.mark.parametrize(
        "options",
        [
            {"amount": "1"},
            {"prove_status": 401},
            {"header": "!!!"},
            {"details": {"chainId": 99}},
            {"details": {}, "allowed_chain_ids": [99]},
        ],
    )
    async def test_failures_leave_the_manager_to_open_a_channel(
        self, monkeypatch: pytest.MonkeyPatch, options: dict[str, Any]
    ) -> None:
        allowed = options.pop("allowed_chain_ids", [CHAIN_ID])
        server = FakeServer(**options)
        async with manager(server, monkeypatch, allowed_chain_ids=allowed) as client:
            response = await client.fetch(URL)
            assert response.status_code == 200 and client.channel_id is None

    async def test_a_chainless_challenge_uses_the_rpc_chain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer(details={})
        async with manager(server, monkeypatch) as client:
            await client.fetch(URL)
            assert client.channel_id == CHANNEL_ID

    async def test_a_snapshot_on_another_rpc_chain_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer()
        client = manager(server, monkeypatch)

        async def resolve_rpc(_: int | None) -> tuple[str, int]:
            return RPC, 1

        monkeypatch.setattr(client._method, "_resolve_rpc", resolve_rpc)  # pyright: ignore[reportPrivateUsage]
        async with client:
            await client.fetch(URL)
            assert client.channel_id is None

    async def test_disabled_or_opened_managers_do_not_probe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = FakeServer()
        async with manager(server, monkeypatch, bootstrap=False) as client:
            await client.fetch(URL)
            assert heads(server) == []

    async def test_responses_without_a_charge_challenge_are_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "HEAD":
                return httpx.Response(402, headers={"WWW-Authenticate": 'Payment id="x"'})
            return httpx.Response(200)

        on_chain(monkeypatch)
        async with session_manager(
            account=PAYER, transport=httpx.MockTransport(handle), bootstrap=True
        ) as client:
            assert (await client.fetch(URL)).status_code == 200
            assert client.channel_id is None

    def test_trusted_realms_must_be_origins(self) -> None:
        with pytest.raises(ValueError, match="trusted_tempo_realms"):
            session_manager(account=PAYER, trusted_tempo_realms={"https://a.test/path": "r"})
