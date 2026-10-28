"""Type guards for values decoded from JSON or passed by untyped callers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeGuard


def is_dict(value: object) -> TypeGuard[dict[Any, Any]]:
    """Return whether ``value`` is a dict, typing its keys and values as ``Any``."""
    return isinstance(value, dict)


def is_mapping(value: object) -> TypeGuard[Mapping[Any, Any]]:
    """Return whether ``value`` is a mapping, typing its keys and values as ``Any``."""
    return isinstance(value, Mapping)


def is_list(value: object) -> TypeGuard[list[Any]]:
    """Return whether ``value`` is a list, typing its items as ``Any``."""
    return isinstance(value, list)
