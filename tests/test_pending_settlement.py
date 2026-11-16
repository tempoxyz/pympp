"""Credential creation retries the same Challenge while a Zone withdrawal settles (mppx)."""

from __future__ import annotations

import asyncio
import sys
from contextlib import suppress
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from mpp import Challenge
from mpp._pending_settlement import resume
from mpp.client.transport import PaymentTransport
from mpp.errors import PaymentExpiredError, ZoneSettlementPendingError
from mpp.extensions.mcp.client import McpClient
from mpp.methods import Method
from mpp.runtime import ClientMethod, CredentialParams
from tests import make_credential
from tests.test_client import MockTransport
from tests.test_mcp_client import FakeCallToolResult, FakeMcpError, _make_challenge_dict


def pending() -> ZoneSettlementPendingError:
    return ZoneSettlementPendingError(challenge_id="abc", zone_id=3)


class TestResume:
    @pytest.mark.asyncio
    async def test_creates_the_credential_again_while_it_settles(self) -> None:
        create = AsyncMock(side_effect=[pending(), pending(), "credential"])
        assert await resume(create, 3) == "credential"
        assert create.await_count == 3
        # Only the first attempt checks expiry: later ones resume a payment already made.
        assert [call.args for call in create.await_args_list] == [(True,), (False,), (False,)]

    @pytest.mark.asyncio
    async def test_raises_the_pending_error_after_the_last_attempt(self) -> None:
        create = AsyncMock(side_effect=pending())
        with pytest.raises(ZoneSettlementPendingError):
            await resume(create, 2)
        assert create.await_count == 2

    @pytest.mark.asyncio
    async def test_raises_other_errors_at_once(self) -> None:
        create = AsyncMock(side_effect=ValueError("declined"))
        with pytest.raises(ValueError, match="declined"):
            await resume(create, 3)
        assert create.await_count == 1

    @pytest.mark.asyncio
    async def test_stops_when_cancelled(self) -> None:
        attempts = 0
        started = asyncio.Event()

        async def create(check_expiry: bool) -> str:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise pending()
            started.set()
            await asyncio.Event().wait()
            return "unreachable"

        task = asyncio.ensure_future(resume(create, 5))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert attempts == 2


def challenge() -> Challenge:
    return Challenge(id="zone-id", method="tempo", intent="charge", request={"amount": "1000"})


class TestTransportRetriesTheSameChallenge:
    @pytest.mark.asyncio
    async def test_retries_the_challenge_without_requesting_again(self) -> None:
        issued = challenge()
        inner = MockTransport(
            [
                httpx.Response(
                    402, headers={"www-authenticate": issued.to_www_authenticate("example.com")}
                ),
                httpx.Response(200),
            ]
        )
        seen: list[CredentialParams] = []

        async def create(params: CredentialParams) -> str:
            seen.append(params)
            if len(seen) == 1:
                raise pending()
            return make_credential({"hash": "0xabc"}, challenge_id=issued.id).to_authorization()

        method = ClientMethod(
            method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
            create_credential=create,
        )
        transport = PaymentTransport(methods=[method], inner=inner)

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        assert response.status_code == 200
        assert len(inner.requests) == 2
        assert [params.challenge.id for params in seen] == [issued.id, issued.id]

    @pytest.mark.asyncio
    async def test_gives_up_after_the_retry_limit(self) -> None:
        issued = challenge()
        inner = MockTransport(
            [
                httpx.Response(
                    402, headers={"www-authenticate": issued.to_www_authenticate("example.com")}
                )
            ]
        )
        create = AsyncMock(side_effect=pending())
        method = ClientMethod(
            method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
            create_credential=create,
        )
        transport = PaymentTransport(methods=[method], inner=inner, max_payment_retries=2)

        with pytest.raises(ZoneSettlementPendingError):
            await transport.handle_async_request(httpx.Request("GET", "https://example.com"))
        assert create.await_count == 2
        assert len(inner.requests) == 1

    @pytest.mark.asyncio
    async def test_resumes_an_expired_challenge_after_the_first_attempt(self) -> None:
        issued = Challenge(
            id="zone-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires="2000-01-01T00:00:00Z",
        )
        inner = MockTransport(
            [
                httpx.Response(
                    402, headers={"www-authenticate": issued.to_www_authenticate("example.com")}
                ),
                httpx.Response(200),
            ]
        )
        runtime_checks: list[bool] = []
        method = ClientMethod(
            method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
            create_credential=AsyncMock(),
        )
        transport = PaymentTransport(methods=[method], inner=inner)

        async def create_credential(*args: Any, check_expiry: bool = True, **kwargs: Any) -> Any:
            runtime_checks.append(check_expiry)
            if len(runtime_checks) == 1:
                raise pending()
            return make_credential({"hash": "0xabc"}, challenge_id=issued.id)

        transport._runtime.create_credential = create_credential  # type: ignore[method-assign]  # pyright: ignore[reportPrivateUsage]
        transport._credential_keywords = frozenset({"check_expiry"})  # pyright: ignore[reportPrivateUsage]

        response = await transport.handle_async_request(httpx.Request("GET", "https://example.com"))

        # The retry resumes the withdrawal the method started: the method, not the
        # runtime's expiry check, decides whether it can still be redeemed.
        assert response.status_code == 200
        assert runtime_checks == [True, False]

    @pytest.mark.asyncio
    async def test_an_expired_challenge_is_never_paid(self) -> None:
        issued = Challenge(
            id="zone-id",
            method="tempo",
            intent="charge",
            request={"amount": "1000"},
            expires="2000-01-01T00:00:00Z",
        )
        inner = MockTransport(
            [
                httpx.Response(
                    402, headers={"www-authenticate": issued.to_www_authenticate("example.com")}
                )
            ]
        )
        create = AsyncMock(side_effect=pending())
        method = ClientMethod(
            method=Method(name="tempo", intent="charge", request_model=dict, payload_model=dict),
            create_credential=create,
        )
        transport = PaymentTransport(methods=[method], inner=inner)

        # An expired Challenge is never paid: it is refused before the method runs.
        with suppress(PaymentExpiredError):
            response = await transport.handle_async_request(
                httpx.Request("GET", "https://example.com")
            )
            assert response.status_code == 402
        assert create.await_count == 0


class TestMcpClientRetriesTheSameChallenge:
    @pytest.mark.asyncio
    async def test_retries_the_challenge_without_calling_the_tool_again(self) -> None:
        mcp_mock = MagicMock()
        mcp_mock.shared.exceptions.McpError = FakeMcpError
        names = ["mcp", "mcp.shared", "mcp.shared.exceptions"]
        original = {name: sys.modules.get(name) for name in names}
        sys.modules["mcp"] = mcp_mock
        sys.modules["mcp.shared"] = mcp_mock.shared
        sys.modules["mcp.shared.exceptions"] = mcp_mock.shared.exceptions
        try:
            session = AsyncMock()
            session.call_tool = AsyncMock(
                side_effect=[
                    FakeMcpError(-32042, data={"challenges": [_make_challenge_dict()]}),
                    FakeCallToolResult(content=[{"type": "text", "text": "paid"}]),
                ]
            )
            ids: list[str] = []

            async def create(params: CredentialParams) -> str:
                ids.append(params.challenge.id)
                if len(ids) == 1:
                    raise pending()
                return make_credential(
                    {"hash": "0xabc"}, challenge_id=params.challenge.id
                ).to_authorization()

            method: Any = ClientMethod(
                method=Method(
                    name="tempo", intent="charge", request_model=dict, payload_model=dict
                ),
                create_credential=create,
            )
            result = await McpClient(session, methods=[method]).call_tool("premium", {})
            assert result.content[0]["text"] == "paid"
            assert ids == ["ch_test123", "ch_test123"]
            assert session.call_tool.call_count == 2
        finally:
            for name, module in original.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
