"""Methods without a store refuse the in-memory fallback in production, as in mppx."""

from __future__ import annotations

import logging

import pytest

from mpp import _replay_store
from mpp.methods.evm import intents as evm_intents
from mpp.methods.tempo import intents as tempo_intents
from mpp.methods.tempo import server as tempo
from mpp.methods.tempo.session.server import _session as session
from mpp.server import Mpp
from mpp.store import MemoryStore

pytest.importorskip("eth_account")
from mpp.methods.evm import BASE_USDC  # noqa: E402
from mpp.methods.evm import server as evm  # noqa: E402

RECIPIENT = "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00"
SECRET = "test-secret-0123456789abcdef0123456789abcdef"
PRODUCTION = [
    ("AWS_LAMBDA_FUNCTION_NAME", "handler"),
    ("DYNO", "web.1"),
    ("FLY_APP_NAME", "api"),
    ("K_SERVICE", "api"),
    ("MPP_ENV", "production"),
    ("NETLIFY", "true"),
    ("NODE_ENV", "Production"),
    ("RAILWAY_ENVIRONMENT", "production"),
    ("RENDER", "true"),
    ("VERCEL", "1"),
]


def _tempo_charge(**options: object) -> list:
    return tempo.charge(recipient=RECIPIENT, rpc_url="https://rpc.test", **options)  # type: ignore[arg-type]


async def _never_settle(*args: object) -> str:
    raise AssertionError("not settled")


def _evm_charge(**options: object) -> object:
    return evm.charge(currency=BASE_USDC, recipient=RECIPIENT, settle=_never_settle, **options)  # type: ignore[arg-type]


def _tempo_session(**options: object) -> object:
    return tempo.session(recipient=RECIPIENT, chain_id=4217, **options)  # type: ignore[arg-type]


METHODS = {
    "tempo.charge": _tempo_charge,
    "evm.charge": _evm_charge,
    "tempo.session": _tempo_session,
}


@pytest.mark.parametrize(("name", "value"), PRODUCTION)
def test_production_runtime_detects_platforms_and_environments(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    assert _replay_store.production_runtime() in (name, f"{name}=production")


@pytest.mark.parametrize(("name", "value"), [("MPP_ENV", "development"), ("NODE_ENV", "test")])
def test_production_runtime_ignores_other_environments(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)
    assert _replay_store.production_runtime() is None


@pytest.mark.parametrize("method", METHODS)
def test_development_keeps_the_fallback_with_a_warning(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    monkeypatch.setattr(tempo_intents, "_warned_fallback_stores", set())
    monkeypatch.setattr(evm_intents, "_warned_fallback_store", False)
    monkeypatch.setattr(session, "_warned_fallback_store", False)
    Mpp(methods=METHODS[method](), secret_key=SECRET)
    with caplog.at_level(logging.WARNING):
        store = {
            "evm.charge": evm_intents._fallback_store,  # pyright: ignore[reportPrivateUsage]
            "tempo.charge": lambda: tempo_intents._fallback_store("tempo.charge"),  # pyright: ignore[reportPrivateUsage]
            "tempo.session": session._fallback_store,  # pyright: ignore[reportPrivateUsage]
        }[method]()
    assert isinstance(store, MemoryStore)
    assert [r.getMessage().startswith(f"{method} has no store") for r in caplog.records] == [True]


@pytest.mark.parametrize("method", METHODS)
def test_production_raises_at_construction_without_a_store(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    monkeypatch.setenv("VERCEL", "1")
    with pytest.raises(
        RuntimeError, match=rf"{method} has no store configured.*\(VERCEL\)"
    ) as error:
        Mpp(methods=METHODS[method](), secret_key=SECRET)
    assert "mpp.stores.RedisStore" in str(error.value)
    assert "mpp.stores.MemoryStore() explicitly" in str(error.value)


@pytest.mark.parametrize(
    "fallback",
    [
        lambda: tempo_intents._fallback_store("tempo.charge"),  # pyright: ignore[reportPrivateUsage]
        lambda: evm_intents._fallback_store("Negotiator(store=...)"),  # pyright: ignore[reportPrivateUsage]
        session._fallback_store,  # pyright: ignore[reportPrivateUsage]
    ],
    ids=["tempo.charge", "x402", "tempo.session"],
)
def test_production_refuses_the_fallback_without_mpp(
    monkeypatch: pytest.MonkeyPatch, fallback: object
) -> None:
    monkeypatch.setenv("MPP_ENV", "production")
    with pytest.raises(RuntimeError, match=r"MPP_ENV=production"):
        fallback()  # type: ignore[operator]


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("where", ["method", "mpp"])
def test_production_accepts_an_explicit_memory_store(
    monkeypatch: pytest.MonkeyPatch, method: str, where: str
) -> None:
    monkeypatch.setenv("FLY_APP_NAME", "api")
    if where == "method":
        mpp = Mpp(methods=METHODS[method](store=MemoryStore()), secret_key=SECRET)
    else:
        mpp = Mpp(methods=METHODS[method](), secret_key=SECRET, store=MemoryStore())
    assert all(m._has_store is None or m._has_store() for m in mpp.methods)


@pytest.mark.asyncio
async def test_production_refuses_a_direct_intent_before_challenging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A direct intent without a store refuses before a payer can pay, not at verification."""
    from mpp.server.verify import verify_or_challenge

    monkeypatch.setenv("K_SERVICE", "api")
    with pytest.raises(RuntimeError, match=r"tempo.charge has no store configured.*\(K_SERVICE\)"):
        await verify_or_challenge(
            authorization=None,
            intent=tempo_intents.ChargeIntent(rpc_url="https://rpc.test"),
            request={"amount": "1000", "currency": RECIPIENT, "recipient": RECIPIENT},
            realm="api.example.com",
            secret_key=SECRET,
        )
