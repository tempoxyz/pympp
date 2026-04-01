"""Tempo payment method for HTTP 402 authentication.

Example:
    # Client-side
    from mpp.client import get
    from mpp.methods.tempo import tempo, TempoAccount, ChargeIntent

    account = TempoAccount.from_key("0x...")
    response = await get(
        "https://api.example.com/resource",
        methods=[tempo(
            account=account,
            intents={"charge": ChargeIntent()},
        )],
    )

    # Server-side
    from mpp.server import Mpp
    from mpp.methods.tempo import tempo, ChargeIntent

    server = Mpp.create(
        method=tempo(
            chain_id=42431,
            intents={"charge": ChargeIntent()},
        ),
    )
"""

from mpp.methods.tempo._defaults import (
    CHAIN_ID,
    ESCROW_CONTRACTS,
    PATH_USD,
    TESTNET_CHAIN_ID,
    USDC,
    default_currency_for_chain,
    escrow_contract_for_chain,
)

_EXTRA_INSTALL_HINT = 'Install the "tempo" extra to use this module: pip install "pympp[tempo]"'

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TempoAccount": ("mpp.methods.tempo.account", "TempoAccount"),
    "TempoMethod": ("mpp.methods.tempo.client", "TempoMethod"),
    "TransactionError": ("mpp.methods.tempo.client", "TransactionError"),
    "tempo": ("mpp.methods.tempo.client", "tempo"),
    "ChargeIntent": ("mpp.methods.tempo.intents", "ChargeIntent"),
    "Transfer": ("mpp.methods.tempo.intents", "Transfer"),
    "get_transfers": ("mpp.methods.tempo.intents", "get_transfers"),
    "Split": ("mpp.methods.tempo.schemas", "Split"),
}

__all__ = [
    "CHAIN_ID",
    "ESCROW_CONTRACTS",
    "PATH_USD",
    "TESTNET_CHAIN_ID",
    "USDC",
    "default_currency_for_chain",
    "escrow_contract_for_chain",
    *_LAZY_IMPORTS,
]


def __getattr__(name: str):  # type: ignore[reportReturnType]
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        try:
            import importlib

            mod = importlib.import_module(module_path)
        except ImportError as exc:
            raise ImportError(
                f"Cannot import {name!r} from mpp.methods.tempo: {exc}. {_EXTRA_INSTALL_HINT}"
            ) from exc
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
