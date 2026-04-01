"""Tests that optional extras fail gracefully with clear install hints.

Verifies that importing modules behind optional extras produces actionable
error messages instead of cryptic ImportError tracebacks.
"""

import subprocess
import sys
import textwrap

import pytest


def test_base_import_no_extras():
    """Core mpp module imports with only httpx (the sole base dep)."""
    script = textwrap.dedent("""\
        import mpp
        print("ok")
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Base import failed:\n{result.stderr.strip()}"
    assert result.stdout.strip() == "ok"


def test_tempo_module_import_succeeds():
    """Importing mpp.methods.tempo itself should not crash (lazy loading)."""
    script = textwrap.dedent("""\
        import mpp.methods.tempo
        # Access a non-lazy attribute that has no external deps
        print(mpp.methods.tempo.CHAIN_ID)
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Tempo module import failed:\n{result.stderr.strip()}"


def test_tempo_lazy_attr_error_message():
    """Accessing a lazy tempo attr with missing deps gives a helpful message.

    Uses ChargeIntent which imports ``attrs`` at module level, so blocking
    ``attrs`` reliably triggers the lazy-import guard.
    """
    script = textwrap.dedent("""\
        import sys

        # Block packages by inserting None into sys.modules.
        blocked = [
            "eth_account", "eth_account.signers", "eth_account.signers.local",
            "eth_hash", "eth_hash.auto",
            "attrs",
            "rlp",
            "pytempo", "pytempo.models",
            "web3",
        ]
        for mod_name in blocked:
            sys.modules.pop(mod_name, None)
            sys.modules[mod_name] = None  # type: ignore

        # Clear cached mpp.methods.tempo submodules so they re-import
        for key in list(sys.modules):
            if key.startswith("mpp.methods.tempo") and key != "mpp.methods.tempo._defaults":
                del sys.modules[key]
        if "mpp.methods.tempo" in sys.modules:
            del sys.modules["mpp.methods.tempo"]

        import mpp.methods.tempo

        try:
            _ = mpp.methods.tempo.ChargeIntent
            print("ERROR: should have raised ImportError")
            sys.exit(1)
        except ImportError as e:
            msg = str(e)
            if 'pympp[tempo]' in msg:
                print("ok")
            else:
                print(f"ERROR: missing install hint in: {msg}")
                sys.exit(1)
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Test failed:\n{result.stderr.strip()}\n{result.stdout.strip()}"
    assert result.stdout.strip() == "ok"


def test_stores_lazy_import():
    """RedisStore and SQLiteStore use lazy imports in stores/__init__.py."""
    script = textwrap.dedent("""\
        from mpp.stores import MemoryStore
        print(MemoryStore.__name__)
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Store import failed:\n{result.stderr.strip()}"
    assert result.stdout.strip() == "MemoryStore"
