"""Ported from mppx src/client/Mpp.test.ts (prepare_payment, prepare_request, create_credential)."""

import asyncio
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from mpp import (
    Challenge,
    ClientMethod,
    Credential,
    CredentialParams,
    Method,
    PaymentExpiredError,
    expires,
)
from mpp.client import Mpp, http_transport

REALM = "api.example.com"


class Anything(BaseModel):
    pass


def payment_method(
    name: str = "test", intent: str = "charge"
) -> tuple[ClientMethod, list[Challenge]]:
    calls: list[Challenge] = []

    async def create(params: CredentialParams[Any]) -> str:
        calls.append(params.challenge)
        return Credential(
            challenge=params.challenge, payload={"signature": "0xsig", "type": "transaction"}
        ).serialize()

    method = ClientMethod(
        method=Method(name=name, intent=intent, request_model=Anything, payload_model=Anything),
        create_credential=create,
    )
    return method, calls


def challenge(id: str, name: str = "test", **kwargs: Any) -> Challenge:
    return Challenge.create(
        id=id,
        expires=kwargs.pop("expires", expires.seconds(60)),
        intent="charge",
        method=name,
        realm=REALM,
        request={"amount": "100", "currency": "0x1"},
        **kwargs,
    )


def payment_required(*challenges: Challenge) -> httpx.Response:
    return httpx.Response(
        402, headers={"WWW-Authenticate": ", ".join(c.serialize() for c in challenges)}
    )


class TestPreparePayment:
    async def test_inspects_without_signing_and_memoizes(self) -> None:
        method, calls = payment_method()
        mppx = Mpp(methods=[method])
        events: list[str] = []
        mppx.on_challenge_received(lambda p: events.append(f"challenge:{p.challenge.id}"))
        mppx.on_credential_created(lambda p: events.append(f"credential:{p.challenge.id}"))
        selected = challenge("selected")
        prepared = await mppx.prepare_payment(payment_required(selected))
        assert calls == []
        assert events == []
        assert prepared.challenge == selected
        assert prepared.challenge is prepared.challenges[0]
        assert prepared.method.name == "test"
        first, second = await asyncio.gather(
            prepared.create_credential(), prepared.create_credential()
        )
        assert first == second
        assert len(calls) == 1
        assert events == ["challenge:selected", "credential:selected"]

    async def test_request_local_policy(self) -> None:
        method, calls = payment_method()
        mppx = Mpp(methods=[method])
        prepared = await mppx.prepare_payment(
            payment_required(challenge("first"), challenge("selected")),
            order_challenges=lambda candidates: [
                c for c in candidates if c.challenge.id == "selected"
            ],
        )
        assert prepared.challenge.id == "selected"
        assert [c.id for c in prepared.challenges] == ["first", "selected"]
        assert calls == []

    async def test_after_body_consumed(self) -> None:
        method, _ = payment_method()
        response = httpx.Response(
            402, headers={"WWW-Authenticate": challenge("consumed").serialize()}, json={"m": 1}
        )
        response.read()
        prepared = await Mpp(methods=[method]).prepare_payment(response)
        assert prepared.challenge.id == "consumed"
        assert isinstance(await prepared.create_credential(), str)

    async def test_set_credential_uses_challenge_header(self) -> None:
        method, _ = payment_method()
        prepared = await Mpp(methods=[method]).prepare_payment(
            payment_required(challenge("c", header="Payment-Authorization"))
        )
        request = prepared.set_credential(
            httpx.Request("GET", "https://x.example/r", headers={"Authorization": "Bearer app"}),
            "Payment abc",
        )
        assert request.headers["Payment-Authorization"] == "Payment abc"
        assert request.headers["Authorization"] == "Bearer app"
        plain = await Mpp(methods=[method]).prepare_payment(payment_required(challenge("d")))
        assert (
            plain.set_credential(httpx.Request("GET", "https://x.example"), "Payment abc").headers[
                "Authorization"
            ]
            == "Payment abc"
        )

    async def test_rechecks_expiry_before_deferred_creation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        method, calls = payment_method()
        prepared = await Mpp(methods=[method]).prepare_payment(
            payment_required(challenge("soon", expires=expires.seconds(1)))
        )
        from datetime import timedelta

        real_now = expires.now()
        monkeypatch.setattr(expires, "now", lambda: real_now + timedelta(seconds=5))
        with pytest.raises(PaymentExpiredError):
            await prepared.create_credential()
        assert calls == []

    async def test_no_method(self) -> None:
        method, _ = payment_method()
        failures: list[Any] = []
        mppx = Mpp(methods=[method])
        mppx.on_payment_failed(failures.append)
        with pytest.raises(
            ValueError,
            match=r"No method found for challenges: other.charge. Available: test.charge",
        ):
            await mppx.prepare_payment(payment_required(challenge("x", "other")))
        assert len(failures) == 1

    async def test_custom_transport(self) -> None:
        method, calls = payment_method()

        class Custom:
            name = "custom"

            async def is_payment_required(self, response: Any, request: Any) -> bool:
                return bool(response["challenges"])

            async def get_challenges(self, response: Any, request: Any) -> list[Challenge]:
                return response["challenges"]

            def set_credential(self, request: Any, credential: str, challenge: Any) -> Any:
                return {**request, "credential": credential}

        mppx = Mpp(methods=[method], transport=Custom())
        prepared = await mppx.prepare_payment({"challenges": [challenge("immutable")]})
        credential = await prepared.create_credential()
        assert calls[0] is prepared.challenge
        assert prepared.set_credential({}, credential) == {"credential": credential}


class TestPrepareRequest:
    def setup(self, handler: Any) -> tuple[Mpp, list[httpx.Request]]:
        requests: list[httpx.Request] = []

        def record(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return handler(request, len(requests))

        method, _ = payment_method()
        return Mpp(methods=[method], inner=httpx.MockTransport(record)), requests

    async def test_redirects_and_pinned_delivery(self) -> None:
        def handler(request: httpx.Request, n: int) -> httpx.Response:
            if n == 1:
                return httpx.Response(303, headers={"location": "/checkout"})
            if n == 2:
                return payment_required(challenge("prepared-request", header="Payment-Credential"))
            return httpx.Response(307, headers={"location": "/elsewhere"})

        mppx, requests = self.setup(handler)
        prepared = await mppx.prepare_request(
            "https://shop.example/start",
            method="POST",
            content="item=book",
            headers={
                "Authorization": "Bearer caller",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert str(prepared.request.url) == "https://shop.example/checkout"
        assert prepared.request.method == "GET"
        assert "content-type" not in prepared.request.headers
        assert prepared.request.headers["authorization"] == "Bearer caller"
        assert [(r.from_url, r.status, r.to_url) for r in prepared.redirects] == [
            ("https://shop.example/start", 303, "https://shop.example/checkout")
        ]
        assert prepared.payment is not None
        response = await prepared.payment.pay()
        assert response.status_code == 307
        assert len(requests) == 3
        assert str(requests[2].url) == "https://shop.example/checkout"
        assert requests[2].headers["Payment-Credential"].startswith("Payment ")

    async def test_strips_credentials_cross_origin(self) -> None:
        def handler(request: httpx.Request, n: int) -> httpx.Response:
            return (
                httpx.Response(307, headers={"location": "https://pay.example/resource"})
                if n == 1
                else payment_required(challenge("x"))
            )

        mppx, _ = self.setup(handler)
        prepared = await mppx.prepare_request(
            "https://shop.example/start",
            headers={
                "Authorization": "Bearer secret",
                "Cookie": "session=secret",
                "Payment-Authorization": "secret",
                "PAYMENT-SIGNATURE": "secret",
                "X-Alternate-Credential": "Payment secret",
                "X-PAYMENT": "secret",
                "X-Public": "value",
            },
        )
        headers = prepared.request.headers
        for name in (
            "authorization",
            "cookie",
            "payment-authorization",
            "payment-signature",
            "x-alternate-credential",
            "x-payment",
        ):
            assert name not in headers
        assert headers["x-public"] == "value"

    async def test_accept_payment_policy_per_hop(self) -> None:
        requests: list[httpx.Request] = []

        def record(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return (
                httpx.Response(307, headers={"location": "https://pay.example/resource"})
                if len(requests) == 1
                else payment_required(challenge("x"))
            )

        method, _ = payment_method()
        mppx = Mpp(
            methods=[method],
            inner=httpx.MockTransport(record),
            accept_payment_policy=["https://shop.example"],
        )
        await mppx.prepare_request("https://shop.example/resource")
        assert requests[0].headers["accept-payment"] == "test/charge"
        assert "accept-payment" not in requests[1].headers

    async def test_runs_method_preparation(self) -> None:
        prepared_with: list[Any] = []
        mppx, _ = self.setup(lambda r, n: payment_required(challenge("x")))
        from dataclasses import replace

        mppx.methods = (
            replace(mppx.methods[0], prepare=lambda params: prepared_with.append(params.request)),
        )
        prepared = await mppx.prepare_request("https://shop.example/resource")
        assert prepared.payment is not None
        await prepared.payment.create_credential()
        assert len(prepared_with) == 1
        assert isinstance(prepared_with[0], httpx.Request)

    async def test_free_responses_and_errors(self) -> None:
        mppx, _ = self.setup(lambda r, n: httpx.Response(200, text="available"))
        prepared = await mppx.prepare_request("https://shop.example/resource")
        assert prepared.payment is None
        assert prepared.response.status_code == 200
        with pytest.raises(ValueError, match=r"Response does not require payment."):
            await mppx.prepare_request("https://shop.example/resource", require_payment=True)
        with pytest.raises(ValueError, match="non-negative integer"):
            await mppx.prepare_request("https://shop.example/start", max_redirects=-1)

    async def test_https_downgrade(self) -> None:
        mppx, requests = self.setup(
            lambda r, n: httpx.Response(302, headers={"location": "http://shop.example/resource"})
        )
        with pytest.raises(ValueError, match="HTTPS downgrade"):
            await mppx.prepare_request("https://shop.example/start")
        assert len(requests) == 1

    async def test_redirect_limit(self) -> None:
        mppx, _ = self.setup(lambda r, n: httpx.Response(302, headers={"location": "/again"}))
        with pytest.raises(ValueError, match="exceeded 2 redirects"):
            await mppx.prepare_request("https://shop.example/start", max_redirects=2)


class TestCreateCredential:
    async def test_routes_to_matching_method(self) -> None:
        alpha, alpha_calls = payment_method("alpha")
        beta, beta_calls = payment_method("beta")
        mppx = Mpp(methods=[alpha, beta])
        credential = await mppx.create_credential(payment_required(challenge("b", "beta")))
        assert Credential.deserialize(credential).challenge.id == "b"
        assert alpha_calls == []
        assert len(beta_calls) == 1

    async def test_duplicate_methods_routed_by_predicate(self) -> None:
        def predicate_method(protocol: str) -> tuple[ClientMethod, list[Challenge]]:
            method, calls = payment_method()
            from dataclasses import replace

            return replace(method, can_handle_challenge=lambda c: c.description == protocol), calls

        v1, v1_calls = predicate_method("v1")
        v2, v2_calls = predicate_method("v2")
        mppx = Mpp(methods=[v1, v2])
        await mppx.create_credential(payment_required(challenge("x", description="v2")))
        assert v1_calls == []
        assert len(v2_calls) == 1
        with pytest.raises(ValueError, match="No method found"):
            await mppx.create_credential(payment_required(challenge("y", description="v3")))

    async def test_events_and_runtime_handlers(self) -> None:
        method, calls = payment_method()
        mppx = Mpp(methods=[method])
        events: list[str] = []
        mppx.on("*", lambda env: events.append(env.name))
        mppx.on_challenge_received(lambda p: "Payment from-handler")
        assert (
            await mppx.create_credential(payment_required(challenge("x"))) == "Payment from-handler"
        )
        assert calls == []
        assert events == ["challenge.received", "credential.created"]

    async def test_validates_event_credentials(self) -> None:
        method, _ = payment_method()
        mppx = Mpp(methods=[method])
        mppx.on_challenge_received(lambda p: "bad\nvalue")
        failures: list[Any] = []
        mppx.on_payment_failed(failures.append)
        with pytest.raises(ValueError, match="illegal newline"):
            await mppx.create_credential(payment_required(challenge("x")))
        assert len(failures) == 1

    async def test_rejects_expired(self) -> None:
        method, calls = payment_method()
        with pytest.raises(PaymentExpiredError):
            await Mpp(methods=[method]).create_credential(
                payment_required(challenge("x", expires=expires.seconds(-5)))
            )
        assert calls == []

    async def test_accept_payment_override(self) -> None:
        alpha, alpha_calls = payment_method("alpha")
        beta, beta_calls = payment_method("beta")
        mppx = Mpp(methods=[alpha, beta])
        response = payment_required(challenge("a", "alpha"), challenge("b", "beta"))
        await mppx.create_credential(response, accept_payment="beta/charge, alpha/charge;q=0.1")
        assert alpha_calls == []
        assert len(beta_calls) == 1

    async def test_context(self) -> None:
        class Ctx(BaseModel):
            account: str

        seen: list[Any] = []

        async def create(params: CredentialParams[Any]) -> str:
            seen.append(params.context)
            return "Payment x"

        method = ClientMethod(
            method=Method(
                name="test", intent="charge", request_model=Anything, payload_model=Anything
            ),
            create_credential=create,
            context=Ctx,
        )
        await Mpp(methods=[method]).create_credential(
            payment_required(challenge("x")), {"account": "0x1"}
        )
        assert seen == [Ctx(account="0x1")]


def test_default_transport_protocols() -> None:
    transport = http_transport()
    names = [p.name for p in transport.protocols]
    assert names[0] == "mpp"


async def test_prepare_request_skips_payment_for_disallowed_origins() -> None:
    method, calls = payment_method()

    def handler(request: httpx.Request) -> httpx.Response:
        return payment_required(challenge("c"))

    mppx = Mpp(
        methods=[method],
        inner=httpx.MockTransport(handler),
        allowed_origins=["https://allowed.example"],
    )
    prepared = await mppx.prepare_request("https://shop.example/start")
    assert prepared.response.status_code == 402
    assert prepared.payment is None
    with pytest.raises(ValueError, match="Payment origin is not allowed"):
        await mppx.prepare_request("https://shop.example/start", require_payment=True)
    assert calls == []
    allowed = await mppx.prepare_request("https://allowed.example/start")
    assert allowed.payment is not None
