"""Dump pympp's public API to api/public-api.txt, or check that the file is current.

Every public module (no `_`-prefixed part) of `mpp` lists the names it exports:
`__all__` when defined, otherwise the names its source binds at top level (in a
package `__init__`, also what it imports from `mpp`) and its lazy exports. Each
name shows its signature, class attributes, dataclass and pydantic fields, enum
members, or constant value. A name defined in another public module that also
exports it is listed as an alias. Run with every extra installed (`make install`).

    uv run python scripts/public_api.py          # regenerate (make api)
    uv run python scripts/public_api.py --check  # fail on drift (make api-check)
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import difflib
import enum
import functools
import importlib
import inspect
import pkgutil
import re
import sys
import types
import typing
from pathlib import Path
from typing import Any

import pydantic

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "api" / "public-api.txt"
_ADDRESS = re.compile(r" at 0x[0-9a-fA-F]+")
_SIMPLE = (str, int, float, bool, bytes, type(None))
_DUNDERS = {"__init__", "__call__"}


def public_modules() -> list[str]:
    import mpp

    names = ["mpp"]
    for info in pkgutil.walk_packages(mpp.__path__, "mpp."):
        if not any(part.startswith("_") for part in info.name.split(".")):
            names.append(info.name)
    return sorted(names)


def _bound_names(body: list[ast.stmt], module: str, is_package: bool) -> list[str]:
    names: list[str] = []
    for node in body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.append(node.name)
        elif isinstance(node, ast.Assign):
            names += [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
        elif sys.version_info >= (3, 12) and isinstance(node, ast.TypeAlias):
            names.append(node.name.id)  # type: ignore[union-attr]
        elif isinstance(node, ast.ImportFrom) and is_package:
            base = node.module or ""
            if node.level:
                parts = module.split(".")[: len(module.split(".")) - node.level + 1]
                base = ".".join([*parts, *([base] if base else [])])
            if base == "mpp" or base.startswith("mpp."):
                names += [a.asname or a.name for a in node.names if a.name != "*"]
        elif isinstance(node, ast.If) and "TYPE_CHECKING" not in ast.unparse(node.test):
            names += _bound_names(node.body + node.orelse, module, is_package)
        elif isinstance(node, ast.Try):
            names += _bound_names(node.body, module, is_package)
    return names


def exported_names(module: types.ModuleType) -> list[str]:
    if hasattr(module, "__all__"):
        return list(dict.fromkeys(module.__all__))
    is_package = hasattr(module, "__path__")
    tree = ast.parse(Path(inspect.getfile(module)).read_text())
    names = _bound_names(tree.body, module.__name__, is_package)
    for lazy in getattr(module, "_LAZY_EXPORTS", {}).values():
        names += list(lazy)
    public = [n for n in dict.fromkeys(names) if not n.startswith("_")]
    return [n for n in public if not isinstance(getattr(module, n), types.ModuleType)]


class _Annotation(str):
    """A string annotation that formats without quotes."""

    def __repr__(self) -> str:
        return str(self)


def _plain(annotation: Any) -> Any:
    return _Annotation(annotation) if isinstance(annotation, str) else annotation


def fmt_annotation(annotation: Any) -> str:
    if isinstance(annotation, typing.ForwardRef):
        return annotation.__forward_arg__
    return inspect.formatannotation(_plain(annotation))


def fmt_signature(obj: Any) -> str:
    try:
        sig = inspect.signature(obj)
    except (TypeError, ValueError):
        return "(...)"
    params = [p.replace(annotation=_plain(p.annotation)) for p in sig.parameters.values()]
    sig = sig.replace(parameters=params, return_annotation=_plain(sig.return_annotation))
    return str(sig)


def stable_repr(value: Any) -> str:
    """repr() with set members sorted, so the snapshot doesn't depend on hash seeds."""
    if isinstance(value, set | frozenset):
        items = ", ".join(sorted(stable_repr(item) for item in value))
        return f"{type(value).__name__}({{{items}}})" if value else f"{type(value).__name__}()"
    return repr(value)


def fmt_value(value: Any) -> str:
    text = stable_repr(value)
    if isinstance(value, _SIMPLE) or (
        isinstance(value, tuple | frozenset | list | dict) and len(text) <= 200
    ):
        return f" = {text}"
    if type(value).__module__ in ("typing", "types", "typing_extensions"):
        return f" = {text}"
    return f": {fmt_type(type(value))}"


def fmt_type(cls: type) -> str:
    if cls.__module__ == "builtins":
        return cls.__qualname__
    return f"{cls.__module__}.{cls.__qualname__}"


def _generated(func: Any) -> bool:
    code = getattr(func, "__code__", None)
    return code is not None and code.co_filename == "<string>"


def render_function(name: str, func: Any, prefix: str = "") -> str:
    kind = "async def" if inspect.iscoroutinefunction(func) else "def"
    return f"{prefix}{kind} {name}{fmt_signature(func)}"


def _fmt_base(base: Any) -> str:
    if isinstance(base, type):
        return fmt_type(base)
    if isinstance(base, types.FunctionType):  # TypedDict and NamedTuple
        return base.__name__
    return repr(base)


def render_class(name: str, cls: type, indent: str) -> list[str]:
    bases = getattr(cls, "__orig_bases__", None) or cls.__bases__
    shown = [_fmt_base(b) for b in bases if b is not object]
    lines = [f"{indent}class {name}" + (f"({', '.join(shown)})" if shown else "")]
    inner = indent + "    "
    own = cls.__dict__
    annotations = own.get("__annotations__", {})

    if dataclasses.is_dataclass(cls):
        frozen = cls.__dataclass_params__.frozen  # type: ignore[attr-defined]
        lines.append(f"{inner}@dataclass(frozen={frozen}, slots={'__slots__' in own})")
        for field in dataclasses.fields(cls):
            if field.name.startswith("_"):
                continue
            default = ""
            if field.default is not dataclasses.MISSING:
                default = f" = {stable_repr(field.default)}"
            elif field.default_factory is not dataclasses.MISSING:
                default = f" = <factory {getattr(field.default_factory, '__name__', '?')}>"
            kw = "kw_only " if field.kw_only is True else ""
            lines.append(f"{inner}field {kw}{field.name}: {fmt_annotation(field.type)}{default}")
    elif isinstance(cls, type) and issubclass(cls, pydantic.BaseModel):
        for field_name, info in cls.model_fields.items():
            default = "" if info.is_required() else f" = {stable_repr(info.get_default())}"
            alias = f" (alias {info.alias!r})" if info.alias else ""
            annotation = fmt_annotation(info.annotation)
            lines.append(f"{inner}field {field_name}: {annotation}{default}{alias}")
    elif issubclass(cls, enum.Enum):
        for member in cls:
            lines.append(f"{inner}{member.name} = {stable_repr(member.value)}")
    else:
        for attr, annotation in annotations.items():
            if not attr.startswith("_"):
                value = fmt_value(own[attr]).removeprefix(":") if attr in own else ""
                value = value if value.startswith(" =") else ""
                lines.append(f"{inner}{attr}: {fmt_annotation(annotation)}{value}")

    for attr, value in sorted(own.items()):
        if attr.startswith("_") and attr not in _DUNDERS:
            continue
        if issubclass(cls, enum.Enum) and isinstance(value, cls):
            continue
        if isinstance(value, property | functools.cached_property):
            getter = value.fget if isinstance(value, property) else value.func
            returns = inspect.signature(getter).return_annotation if getter else None
            empty = returns in (None, inspect.Signature.empty)
            text = "" if empty else f": {fmt_annotation(returns)}"
            lines.append(f"{inner}property {attr}{text}")
        elif isinstance(value, staticmethod | classmethod):
            decorator = "@staticmethod " if isinstance(value, staticmethod) else "@classmethod "
            lines.append(render_function(attr, value.__func__, f"{inner}{decorator}"))
        elif inspect.isfunction(value):
            if not _generated(value):
                lines.append(render_function(attr, value, inner))
        elif inspect.isclass(value):
            lines += render_class(attr, value, inner)
        elif not (attr in annotations or callable(value) or inspect.isdatadescriptor(value)):
            if not (issubclass(cls, pydantic.BaseModel) and attr in cls.model_fields):
                lines.append(f"{inner}{attr}{fmt_value(value)}")
    return lines


def render_module(name: str, exports: dict[str, list[str]]) -> list[str]:
    module = importlib.import_module(name)
    lines = [f"module {name}"]
    for export in exports[name]:
        obj = getattr(module, export)
        origin = getattr(obj, "__module__", None)
        if (
            (inspect.isclass(obj) or inspect.isfunction(obj))
            and origin != name
            and export in exports.get(origin or "", [])
        ):
            lines.append(f"    {export} -> {origin}.{obj.__qualname__}")
        elif inspect.isclass(obj):
            lines += render_class(export, obj, "    ")
        elif inspect.isfunction(obj) or inspect.isbuiltin(obj):
            lines.append(render_function(export, obj, "    "))
        else:
            lines.append(f"    {export}{fmt_value(obj)}")
    return lines


def dump() -> str:
    modules = public_modules()
    exports = {name: exported_names(importlib.import_module(name)) for name in modules}
    lines: list[str] = []
    for name in modules:
        lines += render_module(name, exports)
        lines.append("")
    return _ADDRESS.sub("", "\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump or check the public API snapshot.")
    parser.add_argument("--check", action="store_true", help="fail if the snapshot is stale")
    args = parser.parse_args()

    current = dump()
    if not args.check:
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(current)
        print(f"Wrote {SNAPSHOT.relative_to(ROOT)}")
        return 0

    recorded = SNAPSHOT.read_text() if SNAPSHOT.exists() else ""
    if current == recorded:
        print(f"{SNAPSHOT.relative_to(ROOT)} is up to date")
        return 0
    sys.stdout.writelines(
        difflib.unified_diff(
            recorded.splitlines(keepends=True),
            current.splitlines(keepends=True),
            str(SNAPSHOT.relative_to(ROOT)),
            "current",
        )
    )
    print(
        f"\nThe public API changed. If intended, regenerate {SNAPSHOT.relative_to(ROOT)} "
        "with `make api` (uv run python scripts/public_api.py) and commit it.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
