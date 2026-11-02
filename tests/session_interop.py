"""Run mppx's session server and client (tests/interop/mppx_session) from pytest.

``mppx_session_server`` starts ``server.mjs`` (an mppx ``tempo.session`` server) and waits for its
``READY`` line; ``run_mppx_session_client`` runs ``client.mjs`` (an mppx session client) against
any URL, such as a pympp server. Both skip the calling test when Node or the npm dependencies
(``npm ci`` in tests/interop/mppx_session) are missing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

MPPX_SESSION_DIR = Path(__file__).parent / "interop" / "mppx_session"


def require_mppx() -> str:
    """Return the ``node`` executable, or skip when Node or the harness's npm deps are missing."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    if not (MPPX_SESSION_DIR / "node_modules" / "mppx" / "package.json").exists():
        pytest.skip(f"mppx interop deps missing: run npm ci in {MPPX_SESSION_DIR}")
    return node


def _env(values: Mapping[str, Any]) -> dict[str, str]:
    env = dict(os.environ)
    for key, value in values.items():
        if value is None:
            env.pop(key, None)
        elif isinstance(value, bool):
            env[key] = "1" if value else "0"
        elif isinstance(value, dict | list):
            env[key] = json.dumps(value)
        else:
            env[key] = str(value)
    return env


def _parse(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


@dataclass
class MppxServer:
    """A running mppx session server.

    ``info`` is its ready line (port, payee, feePayer, currency, chainId, amount, unitType,
    suggestedDeposit); ``lines`` collects every JSON line it printed since: ``{"request": ...}``
    per HTTP request and ``{"settlement": ...}`` per settlement.
    """

    port: int
    info: dict[str, Any]
    process: asyncio.subprocess.Process
    lines: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])
    output: list[str] = field(default_factory=list[str])

    @property
    def url(self) -> str:
        """The paid route."""
        return f"http://127.0.0.1:{self.port}/paid"

    @property
    def payee(self) -> str:
        return self.info["payee"]

    def requests(self) -> list[dict[str, Any]]:
        """The requests the server handled, with headers, credential, status and receipt."""
        return [line["request"] for line in self.lines if "request" in line]

    def settlements(self) -> list[dict[str, Any]]:
        """The server's ``onSessionSettlement`` events."""
        return [line["settlement"] for line in self.lines if "settlement" in line]


@contextlib.asynccontextmanager
async def mppx_session_server(
    *,
    rpc_url: str,
    chain_id: int = 1337,
    currency: str | None = None,
    payee_key: str | None = None,
    fee_payer_key: str | None = None,
    settlement_schedule: Mapping[str, Any] | None = None,
    amount: str = "0.0001",
    unit_type: str = "request",
    suggested_deposit: str | None = None,
    secret_key: str | None = None,
    fund: bool = True,
    port: int = 0,
    bootstrap: bool = False,
    timeout: float = 90.0,
) -> AsyncIterator[MppxServer]:
    """Start server.mjs and yield it once it prints ``READY``; stop it on exit.

    ``bootstrap`` enables HEAD recovery, resolving each payer source to the channel it last paid on.
    """
    node = require_mppx()
    env = _env(
        {
            "MPPX_RPC_URL": rpc_url,
            "MPPX_CHAIN_ID": chain_id,
            "MPPX_CURRENCY": currency,
            "MPPX_PAYEE_KEY": payee_key,
            "MPPX_FEE_PAYER_KEY": fee_payer_key,
            "MPPX_SETTLEMENT_SCHEDULE": dict(settlement_schedule) if settlement_schedule else None,
            "MPPX_AMOUNT": amount,
            "MPPX_UNIT_TYPE": unit_type,
            "MPPX_SUGGESTED_DEPOSIT": suggested_deposit,
            "MPPX_SECRET_KEY": secret_key,
            "MPPX_FUND": fund,
            "MPPX_PORT": port,
            "MPPX_BOOTSTRAP": bootstrap,
        }
    )
    process = await asyncio.create_subprocess_exec(
        node,
        "server.mjs",
        cwd=MPPX_SESSION_DIR,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert process.stdout is not None
    stdout = process.stdout
    output: list[str] = []
    info: dict[str, Any] = {}

    async def wait_ready() -> int:
        while True:
            raw = await stdout.readline()
            if not raw:
                raise RuntimeError("mppx session server exited:\n" + "\n".join(output))
            line = raw.decode().rstrip("\n")
            output.append(line)
            parsed = _parse(line)
            if parsed is not None and parsed.get("ready"):
                info.update(parsed)
            if line.startswith("READY "):
                return int(line.split()[1])

    try:
        try:
            ready_port = await asyncio.wait_for(wait_ready(), timeout)
        except TimeoutError as error:
            raise RuntimeError(
                "mppx session server not ready in time:\n" + "\n".join(output)
            ) from error
        server = MppxServer(port=ready_port, info=info, process=process, output=output)

        async def drain() -> None:
            while raw := await stdout.readline():
                line = raw.decode().rstrip("\n")
                output.append(line)
                if (parsed := _parse(line)) is not None:
                    server.lines.append(parsed)

        reader = asyncio.create_task(drain())
        try:
            yield server
        finally:
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                process.kill()
                await process.wait()


@dataclass
class MppxClientResult:
    """What client.mjs printed: one entry per call, the management actions and the final line."""

    returncode: int
    lines: list[dict[str, Any]]
    stderr: str

    @property
    def calls(self) -> list[dict[str, Any]]:
        """Per paid call: status, receipt (decoded Payment-Receipt), body and HTTP exchanges."""
        return [line for line in self.lines if "call" in line]

    @property
    def top_up(self) -> dict[str, Any] | None:
        return next((line["topUp"] for line in self.lines if "topUp" in line), None)

    @property
    def close(self) -> dict[str, Any] | None:
        return next((line["close"] for line in self.lines if "close" in line), None)

    @property
    def final(self) -> dict[str, Any]:
        """Channel info: mode, payer, channelId, cumulative, opened, lastReceipt, balances, ok."""
        return next(line["final"] for line in self.lines if "final" in line)

    @property
    def http(self) -> list[dict[str, Any]]:
        """Every HTTP exchange, when run with ``trace=True``."""
        return [line["http"] for line in self.lines if "http" in line]


async def run_mppx_session_client(
    url: str,
    *,
    rpc_url: str,
    chain_id: int = 1337,
    currency: str | None = None,
    payer_key: str | None = None,
    calls: int = 3,
    max_deposit: str = "1",
    top_up: str | None = None,
    close: bool = False,
    mode: str | None = None,
    method: str = "GET",
    trace: bool = False,
    fund: bool = True,
    bootstrap: bool = False,
    trusted_realms: Mapping[str, str] | None = None,
    timeout: float = 180.0,
) -> MppxClientResult:
    """Run client.mjs against ``url`` and return its parsed output.

    ``mode`` is ``"fetch"`` (mppx client fetch with ``tempo.session``) or ``"manager"``
    (``tempo.session.manager``); it defaults to the manager when ``top_up`` or ``close`` is set.
    ``bootstrap`` runs the manager with HEAD recovery (``trusted_realms`` is its
    ``trustedTempoProofRealms``).
    """
    node = require_mppx()
    env = _env(
        {
            "MPPX_RPC_URL": rpc_url,
            "MPPX_CHAIN_ID": chain_id,
            "MPPX_CURRENCY": currency,
            "MPPX_PAYER_KEY": payer_key,
            "MPPX_CALLS": calls,
            "MPPX_MAX_DEPOSIT": max_deposit,
            "MPPX_TOP_UP": top_up,
            "MPPX_CLOSE": close,
            "MPPX_MODE": mode,
            "MPPX_METHOD": method,
            "MPPX_TRACE": trace,
            "MPPX_FUND": fund,
            "MPPX_BOOTSTRAP": bootstrap,
            "MPPX_TRUSTED_REALMS": dict(trusted_realms) if trusted_realms else None,
        }
    )
    process = await asyncio.create_subprocess_exec(
        node,
        "client.mjs",
        url,
        cwd=MPPX_SESSION_DIR,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise
    lines = [
        parsed for line in stdout.decode().splitlines() if (parsed := _parse(line)) is not None
    ]
    return MppxClientResult(returncode=process.returncode or 0, lines=lines, stderr=stderr.decode())
