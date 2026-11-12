"""Helpers for package-level lazy exports."""

from __future__ import annotations

import importlib
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from typing import Any


def extra_install_hint(extra: str) -> str:
    """The message telling users to install ``pympp[extra]``."""
    return f'Install the "{extra}" extra to use this module: pip install "pympp[{extra}]"'


@contextmanager
def install_hint(extra: str) -> Generator[None]:
    """Name the ``pympp[extra]`` to install when a module's extra-only imports fail.

    Wraps the imports of a module imported directly, such as
    ``from mpp.methods.tempo import server``, which bypasses the package's lazy exports.
    """
    hint = extra_install_hint(extra)
    try:
        yield
    except ImportError as exc:
        if hint in str(exc):
            raise
        message = f"{exc}. {hint}"
        # Keep the original class (such as ModuleNotFoundError) and its name and path,
        # so callers that catch or inspect them still can.
        try:
            hinted = type(exc)(message, name=exc.name, path=exc.path)
        except Exception:
            hinted = ImportError(message, name=exc.name, path=exc.path)
        raise hinted from exc


def load_lazy_attr(
    module_name: str,
    name: str,
    lazy_exports: Mapping[str, tuple[str, ...]],
    namespace: dict[str, Any],
    extra_install_hint: str,
) -> Any:
    """Load and cache a lazily exported attribute.

    Raises:
        AttributeError: If the name is not a known lazy export.
        ImportError: If the target module cannot be imported.
    """
    module_path = next(
        (module_path for module_path, names in lazy_exports.items() if name in names),
        None,
    )
    if module_path is None:
        raise AttributeError(f"module {module_name!r} has no attribute {name!r}")

    try:
        mod = importlib.import_module(module_path)
    except ImportError as exc:
        raise ImportError(
            f"Cannot import {name!r} from {module_name}: {exc}. {extra_install_hint}"
        ) from exc

    value = getattr(mod, name)
    namespace[name] = value
    return value
