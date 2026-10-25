"""Helpers for package-level lazy exports."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any


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
