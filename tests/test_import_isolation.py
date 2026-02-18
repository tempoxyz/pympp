"""Tests that client-only imports don't pull in server-only modules.

The pympp[tempo] extra must work without the [server] extra installed.
Rather than blocking individual packages, we assert the real invariant:
client/method imports must never cause mpp.server to be loaded.
"""

import subprocess
import sys
import textwrap

import pytest

# Modules that a client-only install should be able to import.
CLIENT_MODULES = [
    "mpp",
    "mpp.client",
    "mpp.methods.tempo",
    "mpp.methods.tempo.client",
    "mpp.methods.tempo.intents",
]

# Modules that must NOT be loaded as a side-effect of the above imports.
# mpp.server pulls in python-dotenv, pydantic, starlette, etc.
SERVER_ONLY_MODULES = [
    "mpp.server",
    "mpp.server.mpp",
    "mpp.server.decorator",
    "mpp.server._defaults",
]


@pytest.mark.parametrize("client_module", CLIENT_MODULES)
def test_client_import_does_not_load_server(client_module: str) -> None:
    """Importing a client module must not transitively load mpp.server.*."""
    script = textwrap.dedent(f"""\
        import importlib, sys, json
        importlib.import_module("{client_module}")
        leaked = [m for m in {SERVER_ONLY_MODULES!r} if m in sys.modules]
        print(json.dumps(leaked))
    """)
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Import of {client_module} crashed:\n{result.stderr.strip()}"
    import json

    leaked = json.loads(result.stdout.strip())
    assert leaked == [], f"Importing {client_module} pulled in server modules: {leaked}"
