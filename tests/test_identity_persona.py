"""Persona KYC: wallet linking, inquiries, and the payment check on a paid retry (mppx#1264)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from mpp import Credential, Receipt
from mpp.client.transport import PaymentTransport
from mpp.extensions.identity import persona
from mpp.extensions.identity.persona import VerifiedInquiry, did, normalize
from mpp.extensions.identity.persona.server import Persona, PersonaError, create, verify_wallet
from mpp.identity import PaymentCheck, PaymentCheckInput, Rejected, Rejection, Route, Valid
from mpp.server import Mpp, PaymentRequired, PaymentVerified, VerifyContext
from mpp.store import MemoryStore
from tests import challenges, http_request, server_method

ACCOUNT = Account.from_key("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
PAYER = did(ACCOUNT.address, 4217)
OTHER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
API = "https://api.withpersona.com"


def sign(message: str) -> str:
    signed = ACCOUNT.sign_message(encode_defunct(text=message))
    return "0x" + bytes(signed.signature).hex()


def template(template_id: str) -> dict[str, Any]:
    return {"inquiry-template": {"data": {"id": template_id, "type": "inquiry-template"}}}


def approved(
    inquiry_id: str, reference: str = PAYER, decisioned_at: str | None = None
) -> dict[str, Any]:
    at = decisioned_at or datetime.now(UTC).isoformat()
    attributes = {"status": "approved", "reference-id": reference, "decisioned-at": at}
    return {"id": inquiry_id, "attributes": attributes}


class FakePersona:
    """A fake Persona API: lists inquiries as the real endpoint filters them, and starts some."""

    def __init__(
        self,
        inquiries: list[dict[str, Any]] | None = None,
        *,
        status: int | None = None,
        page_size: int | None = None,
    ) -> None:
        self.inquiries = inquiries if inquiries is not None else []
        self.status = status
        self.page_size = page_size
        self.calls: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self.handle)

    def bodies(self) -> list[Any]:
        return [json.loads(call.content) if call.content else None for call in self.calls]

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.status is not None:
            return httpx.Response(self.status, text="upstream error")
        url = request.url
        if request.method == "POST" and url.path == "/api/v1/inquiries":
            attributes = json.loads(request.content)["data"]["attributes"]
            inquiry_id = f"inq_{len(self.inquiries) + 1}"
            self.inquiries.append(
                {
                    "id": inquiry_id,
                    "attributes": {"status": "created", "reference-id": attributes["reference-id"]},
                    "relationships": template(attributes["inquiry-template-id"]),
                }
            )
            return httpx.Response(200, json={"data": {"id": inquiry_id, "type": "inquiry"}})
        if request.method == "POST" and url.path.endswith("/generate-one-time-link"):
            return httpx.Response(
                200, json={"meta": {"one-time-link": "https://withpersona.com/verify?code=abc"}}
            )
        reference = url.params.get("filter[reference-id]")
        statuses = (url.params.get("filter[status]") or "").split(",")
        matches = [
            inquiry
            for inquiry in self.inquiries
            if inquiry["attributes"].get("reference-id") == reference
            and inquiry["attributes"].get("status") in statuses
        ]
        size = self.page_size or len(matches)
        start = int(url.params.get("page[after]", "0"))
        following = start + size if start + size < len(matches) else None
        next_link = None
        if following is not None:
            next_link = str(url.copy_set_param("page[after]", str(following)).raw_path, "ascii")
        return httpx.Response(
            200, json={"data": matches[start : start + size], "links": {"next": next_link}}
        )


def responder(*bodies: Any) -> tuple[list[httpx.Request], httpx.MockTransport]:
    """A transport answering each call with the next body (the last one repeats)."""
    calls: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        body = bodies[min(len(calls), len(bodies)) - 1]
        return body if isinstance(body, httpx.Response) else httpx.Response(200, json=body)

    return calls, httpx.MockTransport(handle)


def from_source(input: PaymentCheckInput) -> str | None:
    """Reads the payer from the Credential's source: safe here, where the test method trusts it."""
    return normalize(input.credential.source) if input.credential.source else None


class Settlements:
    count = 0


async def _verify(context: VerifyContext) -> Receipt:
    Settlements.count += 1
    return Receipt.success("test-payment")


METHOD = server_method(name="test", request={"amount": "1"}, verify=_verify)


class Paid:
    def __init__(self, offered: PaymentRequired, result: Any, check: PaymentCheck[Any]) -> None:
        self.offered = offered
        self.result = result
        self.response = result.challenge if isinstance(result, PaymentRequired) else None
        self.value = result.identity.get(check) if isinstance(result, PaymentVerified) else None
        self.rejection: Rejection | None = (
            result.rejection if isinstance(result, PaymentRequired) else None
        )

    @property
    def status(self) -> int:
        return self.response.status if self.response is not None else 200


async def pay(check: PaymentCheck[Any], source: str | None = None) -> Paid:
    mpp = Mpp(methods=METHOD, realm="localhost", secret_key="test-secret-key-test-secret-key-32")
    handler = mpp.charge(identity=Route(payment=check))
    offered = await handler(http_request(url="https://api.example/resource"))
    assert isinstance(offered, PaymentRequired)
    [issued] = challenges(offered)
    credential = Credential(challenge=issued.to_echo(), payload={"token": "paid"}, source=source)
    result = await handler(
        http_request(credential.to_authorization(), url="https://api.example/resource")
    )
    return Paid(offered, result, check)


async def test_links_a_wallet_starts_an_inquiry_and_accepts_the_payer_once_approved() -> None:
    api = FakePersona()
    client = create(api_key="persona_key", transport=api.transport, template_id="itmpl_1")

    nonce = "n-123"
    message = f"Link {PAYER} to KYC on api.example. Nonce: {nonce}"
    reference_id = await verify_wallet(
        address=ACCOUNT.address,
        chain_id=4217,
        message=message,
        nonce=nonce,
        signature=sign(message),
    )
    assert reference_id == PAYER

    started = await client.start_inquiry(reference_id)
    assert (started.inquiry_id, started.url) == ("inq_1", "https://withpersona.com/verify?code=abc")
    assert api.bodies()[0] == {
        "data": {"attributes": {"inquiry-template-id": "itmpl_1", "reference-id": PAYER}}
    }
    assert api.bodies()[1] == {}
    first = api.calls[0].headers
    assert first["Authorization"] == "Bearer persona_key"
    assert first["Persona-Version"] == "2023-01-05"
    assert first["Accept"] == "application/json"
    assert first["Content-Type"] == "application/json"
    assert api.calls[1].url.path == "/api/v1/inquiries/inq_1/generate-one-time-link"

    kyc = client.payment_check(onboarding="https://api.example/kyc", reference_id=from_source)
    pending = await pay(kyc, PAYER)
    assert pending.status == 403
    assert pending.response is not None
    assert pending.response.headers.get("Link") == '<https://api.example/kyc>; rel="kyc"'

    api.inquiries[0] = {**api.inquiries[0], "attributes": approved("inq_1")["attributes"]}
    before = Settlements.count
    # The Credential's source checksums the address; the check normalizes it.
    paid = await pay(kyc, f"did:pkh:eip155:4217:{ACCOUNT.address}")
    assert (
        paid.offered.challenge.headers.get("Identity-Required")
        == 'kyc;issuer="https://api.withpersona.com"'
    )
    assert paid.status == 200
    assert isinstance(paid.value, VerifiedInquiry)
    assert (paid.value.inquiry_id, paid.value.reference_id, paid.value.status) == (
        "inq_1",
        PAYER,
        "approved",
    )
    assert paid.value.verified_at is not None
    assert Settlements.count == before + 1
    lookup = api.calls[-1]
    assert "Content-Type" not in lookup.headers
    assert lookup.url.params["filter[inquiry-template-id]"] == "itmpl_1"
    assert lookup.url.params["filter[status]"] == "approved"
    assert lookup.url.params["page[size]"] == "25"


async def test_rejects_a_wallet_signature_without_the_nonce_for_another_chain_or_address() -> None:
    message = f"Link {PAYER} and {did(OTHER, 4217)}. Nonce: n-1"
    base: dict[str, Any] = {
        "address": ACCOUNT.address,
        "chain_id": 4217,
        "message": message,
        "nonce": "n-1",
        "signature": sign(message),
    }
    with pytest.raises(ValueError, match="nonce"):
        await verify_wallet(**{**base, "nonce": "n-2"})
    with pytest.raises(ValueError, match="nonce"):
        await verify_wallet(**{**base, "nonce": ""})
    # The signer committed to chain 4217 only.
    with pytest.raises(ValueError, match="wallet's DID"):
        await verify_wallet(**{**base, "chain_id": 1})
    with pytest.raises(ValueError, match="does not match"):
        await verify_wallet(**{**base, "address": OTHER})
    with pytest.raises(ValueError, match="does not match"):
        await verify_wallet(**{**base, "signature": "0xnothex"})

    chains: list[int] = []

    async def custom(*, address: str, chain_id: int, message: str, signature: str) -> bool:
        chains.append(chain_id)
        return True

    assert await verify_wallet(**base, verify=custom) == PAYER
    assert chains == [4217]
    with pytest.raises(ValueError, match="does not match"):
        await verify_wallet(**base, verify=lambda **_: False)


async def test_verify_wallet_without_eth_account_names_the_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = f"Link {PAYER}. Nonce: n-1"
    monkeypatch.setitem(sys.modules, "eth_account", None)
    with pytest.raises(ImportError, match=r"pympp\[evm\]"):
        await verify_wallet(
            address=ACCOUNT.address, chain_id=4217, message=message, nonce="n-1", signature="0x"
        )


async def test_never_follows_a_pagination_link_to_another_origin() -> None:
    calls, transport = responder(
        {"data": [], "links": {"next": "https://evil.example/api/v1/inquiries"}}
    )
    await pay(
        create(api_key="k", transport=transport).payment_check(reference_id=from_source), PAYER
    )
    assert [call.url.host for call in calls] == ["api.withpersona.com"]


async def test_never_follows_a_protocol_relative_pagination_path_to_another_origin() -> None:
    page = {"data": [], "links": {"next": f"{API}//evil.example/x"}}
    relative = {"data": [], "links": {"next": "//evil.example/x"}}
    calls, transport = responder(page, page, {"data": [], "links": {"next": None}})
    await pay(
        create(api_key="k", transport=transport).payment_check(reference_id=from_source), PAYER
    )
    assert len(calls) == 3
    assert {call.url.host for call in calls} == {"api.withpersona.com"}

    calls, transport = responder(relative)
    await pay(
        create(api_key="k", transport=transport).payment_check(reference_id=from_source), PAYER
    )
    assert [call.url.host for call in calls] == ["api.withpersona.com"]


async def test_follows_a_relative_pagination_path_on_the_api_origin() -> None:
    calls, transport = responder(
        {"data": [], "links": {"next": "/api/v1/inquiries?page[after]=1"}},
        {"data": [approved("inq_1")], "links": {}},
    )
    paid = await pay(
        create(api_key="k", transport=transport).payment_check(reference_id=from_source), PAYER
    )
    assert paid.status == 200
    assert str(calls[1].url).startswith(f"{API}/api/v1/inquiries?page")


async def test_rejects_without_settling_as_missing_or_forbidden_with_the_onboarding_link() -> None:
    api = FakePersona(
        [{"id": "inq_1", "attributes": {"status": "declined", "reference-id": PAYER}}]
    )
    client = create(api_key="k", transport=api.transport)

    async def onboarding(request: Any, reference_id: str | None) -> str:
        return f"/kyc?for={reference_id or ''}"

    kyc = client.payment_check(reference_id=from_source, onboarding=onboarding)
    before = Settlements.count

    declined = await pay(kyc, PAYER)
    assert declined.rejection == Rejection(
        stage="payment", status="forbidden", reason="The payer has not passed Persona KYC."
    )
    assert declined.response is not None
    assert declined.response.headers.get("Link") == f'</kyc?for={PAYER}>; rel="kyc"'

    calls = len(api.calls)
    anonymous = await pay(kyc)
    assert anonymous.status == 401
    assert anonymous.rejection is not None
    assert anonymous.rejection.reason == "Persona KYC requires a payer."
    assert anonymous.response is not None
    assert anonymous.response.headers.get("Link") == '</kyc?for=>; rel="kyc"'
    assert len(api.calls) == calls
    assert Settlements.count == before


async def test_maps_a_persona_api_failure_to_unavailable_without_its_body() -> None:
    api = FakePersona(status=500)
    client = create(api_key="k", transport=api.transport)
    paid = await pay(
        client.payment_check(reference_id=from_source, onboarding="https://api.example/kyc"),
        PAYER,
    )
    assert paid.rejection == Rejection(
        stage="payment", status="unavailable", reason="Persona KYC verification is unavailable."
    )
    assert paid.status == 503
    assert paid.response is not None
    assert "upstream error" not in (paid.response.body or b"").decode()
    assert paid.response.headers.get("Link") is None
    with pytest.raises(PersonaError, match="returned 500") as error:
        await client.start_inquiry("ref", template_id="itmpl_1")
    assert "upstream error" not in str(error.value)


@pytest.mark.parametrize(
    "body",
    [
        httpx.Response(200, text="not json"),
        {"data": "nope"},
        ["not", "an", "object"],
    ],
)
async def test_maps_a_malformed_lookup_to_unavailable(body: Any) -> None:
    _, transport = responder(body)
    paid = await pay(
        create(api_key="k", transport=transport).payment_check(reference_id=from_source), PAYER
    )
    assert paid.status == 503


async def test_a_slow_persona_api_is_unavailable() -> None:
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={"data": []})

    client = create(api_key="k", transport=httpx.MockTransport(slow), timeout=0.05)
    paid = await pay(client.payment_check(reference_id=from_source), PAYER)
    assert paid.status == 503


async def test_start_inquiry_rejects_malformed_responses_and_missing_inputs() -> None:
    _, no_id = responder({"data": {}})
    with pytest.raises(PersonaError, match="malformed"):
        await create(api_key="k", transport=no_id, template_id="t").start_inquiry("ref")
    _, no_link = responder({"data": {"id": "inq_1"}}, {"meta": {}})
    with pytest.raises(PersonaError, match="malformed"):
        await create(api_key="k", transport=no_link, template_id="t").start_inquiry("ref")
    client = create(api_key="k", transport=no_id)
    with pytest.raises(ValueError, match="reference_id"):
        await client.start_inquiry("", template_id="t")
    with pytest.raises(ValueError, match="template_id"):
        await client.start_inquiry("ref")


async def test_start_inquiry_overrides_the_template_and_sends_the_redirect() -> None:
    api = FakePersona()
    client = create(api_key="k", transport=api.transport, template_id="itmpl_1")
    await client.start_inquiry(
        "ref", template_id="itmpl_2", redirect_uri="https://app.example/done"
    )
    assert api.bodies()[0] == {
        "data": {
            "attributes": {
                "inquiry-template-id": "itmpl_2",
                "reference-id": "ref",
                "redirect-uri": "https://app.example/done",
            }
        }
    }


async def test_caches_approvals_only() -> None:
    api = FakePersona([approved("inq_1")])
    store = MemoryStore()
    kyc = create(api_key="k", transport=api.transport).payment_check(
        cache=store, reference_id=from_source
    )
    assert (await pay(kyc, PAYER)).status == 200
    cached = (await pay(kyc, PAYER)).value
    assert isinstance(cached, VerifiedInquiry)
    assert (cached.inquiry_id, cached.reference_id, cached.status) == ("inq_1", PAYER, "approved")
    assert cached.verified_at is not None
    assert len(api.calls) == 1

    # Stored as JSON, the form mppx and string-only stores keep.
    [key] = list(store._data)  # pyright: ignore[reportPrivateUsage]
    scope = hashlib.sha256(f"{API}\nk".encode()).digest()[:16].hex()
    assert key == f"mppx:persona:{scope}::{PAYER}"
    stored = json.loads(str(await store.get(key)))
    assert set(stored) == {"cachedAt", "inquiryId", "status", "verifiedAt"}
    assert stored["verifiedAt"].endswith("Z")

    other = did(OTHER, 4217)
    await pay(kyc, other)
    await pay(kyc, other)
    assert len(api.calls) == 3


async def test_does_not_share_cached_approvals_across_persona_organizations() -> None:
    cache = MemoryStore()
    approved_api = FakePersona([approved("inq_1")])
    empty_api = FakePersona()
    a = create(api_key="org-a", transport=approved_api.transport).payment_check(
        cache=cache, reference_id=from_source
    )
    b = create(api_key="org-b", transport=empty_api.transport).payment_check(
        cache=cache, reference_id=from_source
    )
    assert (await pay(a, PAYER)).status == 200
    assert (await pay(b, PAYER)).status == 403
    assert len(empty_api.calls) == 1


async def test_applies_each_checks_own_cache_ttl_to_a_shared_cache() -> None:
    cache = MemoryStore()
    api = FakePersona([approved("inq_1")])
    client = create(api_key="k", transport=api.transport)
    lenient = client.payment_check(cache=cache, cache_ttl=3600, reference_id=from_source)
    strict = client.payment_check(cache=cache, cache_ttl=0, reference_id=from_source)
    needs_review = client.payment_check(
        cache=cache, statuses=["needs_review"], reference_id=from_source
    )
    assert (await pay(lenient, PAYER)).status == 200
    api.inquiries.clear()
    assert (await pay(lenient, PAYER)).status == 200
    assert (await pay(strict, PAYER)).status == 403
    # A cached approval does not satisfy a check that accepts other statuses.
    assert (await pay(needs_review, PAYER)).status == 403


@pytest.mark.parametrize("entry", ["not json", json.dumps({"cachedAt": True}), 42])
async def test_ignores_a_malformed_cache_entry(entry: Any) -> None:
    api = FakePersona([approved("inq_1")])
    client = create(api_key="k", transport=api.transport)

    class Spy(MemoryStore):
        async def get(self, key: str) -> Any:
            return entry

    kyc = client.payment_check(cache=Spy(), reference_id=from_source)
    assert (await pay(kyc, PAYER)).status == 200
    assert len(api.calls) == 1


async def test_applies_max_age_across_pages_and_a_custom_reference_id() -> None:
    old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    api = FakePersona(
        [
            approved("inq_a", "customer-1", old),
            approved("inq_b", "customer-1", old),
            approved("inq_c", "customer-1"),
        ],
        page_size=1,
    )
    client = create(api_key="k", transport=api.transport)

    async def customer(input: PaymentCheckInput) -> str:
        return "customer-1"

    paid = await pay(client.payment_check(reference_id=customer, max_age=3600), PAYER)
    assert isinstance(paid.value, VerifiedInquiry)
    assert (paid.value.inquiry_id, paid.value.reference_id) == ("inq_c", "customer-1")
    assert len(api.calls) == 3


async def test_max_age_uses_completed_at_and_rejects_an_undated_inquiry() -> None:
    now = datetime.now(UTC).replace(tzinfo=None).isoformat()  # naive: read as UTC
    completed = {
        "id": "inq_1",
        "attributes": {"status": "approved", "reference-id": PAYER, "completed-at": now},
    }
    undated = {
        "id": "inq_2",
        "attributes": {"status": "approved", "reference-id": PAYER, "decisioned-at": "garbage"},
    }
    _, transport = responder({"data": [undated, completed]})
    paid = await pay(
        create(api_key="k", transport=transport).payment_check(
            reference_id=from_source, max_age=60
        ),
        PAYER,
    )
    assert isinstance(paid.value, VerifiedInquiry)
    assert paid.value.inquiry_id == "inq_1"

    cache = MemoryStore()
    _, transport = responder({"data": [undated]})
    client = create(api_key="k", transport=transport)
    assert (
        await pay(client.payment_check(reference_id=from_source, cache=cache), PAYER)
    ).status == 200
    # An undated cached approval fails a check with max_age.
    calls, empty = responder({"data": []})
    strict = create(api_key="k", transport=empty).payment_check(
        reference_id=from_source, cache=cache, max_age=60
    )
    assert (await pay(strict, PAYER)).status == 403
    assert len(calls) == 1


async def test_accepts_only_inquiries_from_the_configured_template() -> None:
    other = {**approved("inq_2"), "relationships": template("itmpl_other")}
    untagged = approved("inq_3")
    _, transport = responder({"data": [other, untagged], "links": {"next": None}})
    kyc = create(api_key="k", transport=transport, template_id="itmpl_1").payment_check(
        reference_id=from_source
    )
    assert (await pay(kyc, PAYER)).status == 403

    matching = {**approved("inq_1"), "relationships": template("itmpl_1")}
    _, ok = responder({"data": [other, matching], "links": {"next": None}})
    accepted = create(api_key="k", transport=ok, template_id="itmpl_1").payment_check(
        reference_id=from_source
    )
    paid = await pay(accepted, PAYER)
    assert isinstance(paid.value, VerifiedInquiry)
    assert paid.value.inquiry_id == "inq_1"


async def test_ignores_inquiries_the_api_returns_outside_its_filters() -> None:
    _, transport = responder(
        {
            "data": [
                approved("inq_wrong", "someone-else"),
                {"id": 7, "attributes": approved("x")["attributes"]},
                {"id": "inq_declined", "attributes": {"status": "declined", "reference-id": PAYER}},
                "not an inquiry",
            ]
        }
    )
    paid = await pay(
        create(api_key="k", transport=transport).payment_check(reference_id=from_source), PAYER
    )
    assert paid.rejection is not None
    assert paid.rejection.status == "forbidden"


async def test_requires_kyc_before_any_402_with_a_request_stage_verifier() -> None:
    api = FakePersona([approved("inq_1", "customer-1")])
    verifier = create(api_key="k", transport=api.transport).verifier(
        reference_id=lambda request: request.headers.get("X-Customer"),
        onboarding="https://api.example/kyc",
    )
    missing = await verifier.verify(http_request(url="https://api.example"))
    assert isinstance(missing, Rejected)
    assert missing.status == "missing"
    assert missing.headers == (("Link", '<https://api.example/kyc>; rel="kyc"'),)
    valid = await verifier.verify(
        http_request(url="https://api.example", headers={"X-Customer": "customer-1"})
    )
    assert isinstance(valid, Valid)
    assert isinstance(valid.value, VerifiedInquiry)
    assert valid.value.inquiry_id == "inq_1"

    # It runs before any Challenge, through the server.
    mpp = Mpp(methods=METHOD, realm="localhost", secret_key="test-secret-key-test-secret-key-32")
    handler = mpp.charge(identity=[verifier])
    result = await handler(http_request(url="https://api.example/resource"))
    assert isinstance(result, PaymentRequired)
    assert result.challenge.status == 401


def test_normalizes_dids_per_chain() -> None:
    assert did("0xAbC", 4217) == "did:pkh:eip155:4217:0xabc"
    assert (
        did("So1AnaBase58", "mainnet", namespace="solana") == "did:pkh:solana:mainnet:So1AnaBase58"
    )
    assert normalize("DID:PKH:EIP155:1:0xAbC") == "did:pkh:eip155:1:0xabc"
    assert normalize("did:web:example.com") == "did:web:example.com"
    assert normalize("did:pkh:eip155:1") == "did:pkh:eip155:1"


async def test_calls_persona_through_the_unwrapped_transport_never_a_payment_aware_one() -> None:
    api = FakePersona([approved("inq_1")])

    class Counting(PaymentTransport):
        wrapped = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            Counting.wrapped += 1
            return await super().handle_async_request(request)

    wrapper = Counting(methods=[], inner=api.transport)
    kyc = create(api_key="k", transport=wrapper).payment_check(reference_id=from_source)
    assert (await pay(kyc, PAYER)).status == 200
    assert len(api.calls) == 1
    assert Counting.wrapped == 0


async def test_treats_a_persona_redirect_as_unavailable_without_following_it() -> None:
    calls, transport = responder(httpx.Response(302, headers={"Location": "https://evil.example/"}))
    kyc = create(api_key="k", transport=transport).payment_check(reference_id=from_source)
    assert (await pay(kyc, PAYER)).status == 503
    assert len(calls) == 1


def test_validates_its_config() -> None:
    with pytest.raises(ValueError, match="needs an api_key"):
        create(api_key="")
    for timeout in (0, -1, float("nan"), float("inf"), 2**31, True):
        with pytest.raises(ValueError, match="timeout"):
            create(api_key="k", timeout=timeout)
    assert isinstance(create(api_key="k", timeout=1.5), Persona)

    client = create(api_key="k")
    with pytest.raises(ValueError, match="at least one accepted status"):
        client.payment_check(reference_id=from_source, statuses=[])
    for max_age in (0, -1, 1.5, True):
        with pytest.raises(ValueError, match="max_age"):
            client.verifier(reference_id=lambda _: None, max_age=max_age)  # pyright: ignore[reportArgumentType]
    for ttl in (-1, float("nan"), True):
        with pytest.raises(ValueError, match="cache_ttl"):
            client.payment_check(reference_id=from_source, cache_ttl=ttl)
    # A bare status string is one status, not its characters.
    check = client.payment_check(reference_id=from_source, statuses="approved")  # pyright: ignore[reportArgumentType]
    assert check.requires[0].type == "kyc"


def test_the_package_exposes_its_constants_and_server_lazily() -> None:
    assert (persona.TYPE, persona.ISSUER, persona.REL) == ("kyc", API, "kyc")
    assert (persona.API_VERSION, persona.STATUSES) == ("2023-01-05", ("approved",))
    assert (persona.TIMEOUT, persona.CACHE_TTL, persona.MAX_PAGES) == (5.0, 300, 3)
    assert persona.server.create is create
    with pytest.raises(AttributeError):
        _ = persona.nope  # pyright: ignore[reportAttributeAccessIssue]
