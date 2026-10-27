"""Payment events emitted by the real Mpp engine, not just the dispatcher.

Mirrors mppx src/server/Mppx.test.ts event tests: listener failures never change
payment control flow, every listener runs, success payloads are not shared
mutable state, and rejected credentials report payment.failed.

pympp has no authorize hook (mppx Mppx.test.ts:1484, access granted without a
credential), so that case has no counterpart here.
"""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any

import pytest

from mpp import Challenge, ChallengeEcho, Credential, Receipt
from mpp.errors import InvalidChallengeError, MalformedCredentialError
from mpp.events import PaymentEvent
from mpp.server import Mpp, PaymentRequired, PaymentVerified, compose
from mpp.x402 import decode_payment_required
from tests import challenge, challenges, http_request, server_method

REALM = "api.example.com"
SECRET = "test-secret"


class Recorder:
    """A method whose verify hook records calls and returns a fixed receipt."""

    def __init__(self, reference: str = "tx-original") -> None:
        self.reference = reference
        self.calls = 0

    async def verify(self, _context: Any) -> Receipt:
        self.calls += 1
        return Receipt(
            status="success",
            timestamp=datetime.now(UTC),
            reference=self.reference,
            method="tempo",
            extra={"note": "original"},
        )


def make_server(recorder: Recorder | None = None) -> Mpp:
    recorder = recorder or Recorder()
    return Mpp(
        methods=server_method(request={"amount": "1"}, verify=recorder.verify),
        realm=REALM,
        secret_key=SECRET,
    )


def authorization(issued: Challenge, payload: dict[str, Any] | None = None) -> str:
    credential = Credential(challenge=issued.to_echo(), payload=payload or {"token": "valid"})
    return credential.to_authorization()


async def pay(server: Mpp) -> Any:
    handler = server.charge()
    issued = challenge(await handler(http_request()))
    return await handler(http_request(authorization(issued)))


def raise_error(label: str, events: list[str]) -> Any:
    def listener(_payload: Any) -> None:
        events.append(label)
        raise RuntimeError(f"{label} listener failed")

    return listener


class TestThrowingListeners:
    async def test_do_not_alter_payment_control_flow(self) -> None:
        events: list[str] = []
        recorder = Recorder("tx-event-error")
        server = make_server(recorder)

        async def wildcard(event: PaymentEvent) -> None:
            events.append(f"*:{event.name}")
            raise RuntimeError("wildcard listener failed")

        server.on("*", wildcard)
        server.on_challenge_created(raise_error("challenge.created", events))
        server.on_payment_failed(raise_error("payment.failed", events))
        server.on_payment_success(raise_error("payment.success", events))
        handler = server.charge()

        unpaid = await handler(http_request())
        issued = challenge(unpaid)
        paid = await handler(http_request(authorization(issued)))
        rejected = await handler(http_request("Payment invalid"))

        assert isinstance(paid, PaymentVerified)
        assert paid.receipt.reference == "tx-event-error"
        assert recorder.calls == 1
        assert isinstance(rejected, PaymentRequired)
        assert rejected.status == 402
        assert len(challenges(rejected)) == 1
        assert events == [
            "challenge.created",
            "*:challenge.created",
            "payment.success",
            "*:payment.success",
            "challenge.created",
            "*:challenge.created",
            "payment.failed",
            "*:payment.failed",
        ]

    async def test_later_listeners_still_run(self) -> None:
        events: list[str] = []
        server = make_server()
        for name in ("challenge.created", "payment.success", "payment.failed"):
            server.on(name, raise_error(f"{name}:first", events))
            server.on(name, lambda _payload, name=name: events.append(f"{name}:second"))

        paid = await pay(server)
        await server.charge()(http_request("Payment invalid"))

        assert isinstance(paid, PaymentVerified)
        assert events == [
            "challenge.created:first",
            "challenge.created:second",
            "payment.success:first",
            "payment.success:second",
            "challenge.created:first",
            "challenge.created:second",
            "payment.failed:first",
            "payment.failed:second",
        ]

    async def test_async_throwing_listener_does_not_fail_broadcast(self) -> None:
        server = make_server()
        issued = challenge(await server.charge()(http_request()))

        async def fail(_payload: Any) -> None:
            raise RuntimeError("listener failed")

        server.on_payment_success(fail)

        receipt = await server.broadcast_credential(authorization(issued))

        assert receipt.reference == "tx-original"


class TestSuccessPayloads:
    async def test_receipt_cannot_be_mutated_by_listeners(self) -> None:
        server = make_server()

        blocked: list[bool] = []

        def tamper(payload: dict[str, Any]) -> None:
            try:
                payload["receipt"].reference = "tx-mutated"
            except FrozenInstanceError:
                blocked.append(True)

        server.on_payment_success(tamper)

        paid = await pay(server)

        assert blocked == [True]
        assert isinstance(paid, PaymentVerified)
        assert paid.receipt.reference == "tx-original"
        header = paid.receipt.to_payment_receipt()
        assert Receipt.from_payment_receipt(header).reference == "tx-original"

    async def test_replacing_payload_entries_does_not_change_the_result(self) -> None:
        server = make_server()

        def replace(payload: dict[str, Any]) -> None:
            payload["receipt"] = Receipt.success("tx-replaced")
            payload["credential"] = None

        server.on_payment_success(replace)

        paid = await pay(server)

        assert isinstance(paid, PaymentVerified)
        assert paid.receipt.reference == "tx-original"
        assert paid.credential.payload == {"token": "valid"}

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "BUG: every payment.success listener gets the same payload dict, so one "
            "listener's edits are visible to the next (mppx snapshots payloads)"
        ),
    )
    async def test_listeners_do_not_share_payload_mutations(self) -> None:
        server = make_server()
        seen: list[tuple[Any, Any]] = []

        def tamper(payload: dict[str, Any]) -> None:
            payload["receipt"] = None
            payload["request"]["amount"] = "mutated"

        server.on_payment_success(tamper)
        server.on_payment_success(
            lambda payload: seen.append((payload["receipt"], payload["request"]["amount"]))
        )

        await pay(server)

        [(receipt, amount)] = seen
        assert receipt is not None
        assert receipt.reference == "tx-original"
        assert amount == "1"

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "BUG: payment.success listeners get the live Credential, so mutating "
            "credential.payload changes PaymentVerified.credential returned to the app"
        ),
    )
    async def test_listener_cannot_mutate_the_returned_credential(self) -> None:
        server = make_server()
        server.on_payment_success(
            lambda payload: payload["credential"].payload.update(token="mutated")
        )

        paid = await pay(server)

        assert isinstance(paid, PaymentVerified)
        assert paid.credential.payload == {"token": "valid"}


class TestFailureEvents:
    async def test_malformed_credential_reports_failure_without_credential(self) -> None:
        recorder = Recorder()
        server = make_server(recorder)
        events: list[str] = []
        server.on_payment_success(lambda payload: events.append("success"))
        server.on_payment_failed(
            lambda payload: events.append(
                f"failed:{type(payload['error']).__name__}:{payload['credential']}"
            )
        )

        result = await server.charge()(http_request("Payment invalid"))

        assert isinstance(result, PaymentRequired)
        assert result.status == 402
        assert events == ["failed:MalformedCredentialError:None"]
        assert recorder.calls == 0

    @pytest.mark.xfail(
        strict=True,
        raises=RecursionError,
        reason=(
            "BUG: a 64 KiB Authorization holding deeply nested JSON raises RecursionError "
            "out of the route instead of a 402 with payment.failed"
        ),
    )
    async def test_deeply_nested_credential_reports_failure(self) -> None:
        server = make_server()
        failures: list[Exception] = []
        server.on_payment_failed(lambda payload: failures.append(payload["error"]))
        nested = b'{"a":' + b"[" * 20_000 + b"]" * 20_000 + b"}"
        value = base64.urlsafe_b64encode(nested).decode().rstrip("=")

        result = await server.charge()(http_request(f"Payment {value}"))

        assert isinstance(result, PaymentRequired)
        assert [type(error) for error in failures] == [MalformedCredentialError]

    async def test_forged_hmac_on_a_route_reports_failure(self) -> None:
        recorder = Recorder()
        server = make_server(recorder)
        handler = server.charge()
        issued = challenge(await handler(http_request()))
        forged = Credential(
            challenge=ChallengeEcho(
                id="forged-id",
                realm=issued.realm,
                method=issued.method,
                intent=issued.intent,
                request=issued.request_b64,
                expires=issued.expires,
                opaque=issued.to_echo().opaque,
            ),
            payload={"token": "valid"},
        )
        failures: list[dict[str, Any]] = []
        successes: list[Any] = []
        server.on_payment_failed(failures.append)
        server.on_payment_success(successes.append)

        result = await handler(http_request(forged.to_authorization()))

        assert isinstance(result, PaymentRequired)
        assert result.status == 402
        assert recorder.calls == 0
        assert successes == []
        [failure] = failures
        assert isinstance(failure["error"], InvalidChallengeError)
        assert failure["credential"] == forged

    async def test_forged_hmac_on_broadcast_reports_failure(self) -> None:
        recorder = Recorder()
        server = make_server(recorder)
        forged = Credential(
            challenge=Challenge(
                id="forged-id",
                method="tempo",
                intent="charge",
                realm=REALM,
                request={"amount": {"$ne": "1"}},
                request_b64=base64.urlsafe_b64encode(b'{"amount":{"$ne":"1"}}')
                .decode()
                .rstrip("="),
            ).to_echo(),
            payload={"token": "valid"},
        )
        failures: list[dict[str, Any]] = []
        server.on_payment_failed(failures.append)

        with pytest.raises(InvalidChallengeError):
            await server.broadcast_credential(forged)

        assert recorder.calls == 0
        [failure] = failures
        assert failure["challenge"].id == "forged-id"
        assert failure["request"] == {"amount": {"$ne": "1"}}
        assert failure["credential"] == forged
        assert isinstance(failure["error"], InvalidChallengeError)


class TestComposedX402Requirements:
    async def test_each_challenge_gets_its_own_servers_requirements(self) -> None:
        """compose.py _x402_accepts matches the issuing offer by realm too."""
        from tests.test_x402_server import evm_method, payment_required, x402_request

        first = Mpp(
            methods=evm_method(max_timeout_seconds=60), realm="a.example.com", secret_key="k"
        )
        second = Mpp(
            methods=evm_method(max_timeout_seconds=600), realm="b.example.com", secret_key="k"
        )

        result = await compose(first.charge(amount="0.01"), second.charge(amount="0.01"))(
            x402_request()
        )

        assert [issued.realm for issued in challenges(result)] == [
            "a.example.com",
            "b.example.com",
        ]
        header = payment_required(result)
        assert header is not None
        accepts = decode_payment_required(header)["accepts"]
        assert [accepted["maxTimeoutSeconds"] for accepted in accepts] == [60, 600]
