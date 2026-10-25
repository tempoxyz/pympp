"""Clear errors when an optional dependency group is not installed."""

from importlib.util import find_spec


def require(extra: str, *modules: str) -> None:
    """Raises ``ModuleNotFoundError`` naming the ``pympp[extra]`` install when a module is missing."""
    for module in modules:
        if find_spec(module) is None:
            raise ModuleNotFoundError(
                f"{module!r} is required for this feature. Install it with: "
                f'pip install "pympp[{extra}]"',
                name=module,
            )
