"""Mutation testing helpers for CI (``make mutation``, ``mutation.yml``).

``changed BASE`` prints mutmut mutant-name globs for the functions in the
``[tool.mutmut] only_mutate`` modules that the diff from BASE touches, so a pull
request only runs the mutants of the code it changes. ``report`` writes the
surviving mutants, with their diffs, as Markdown after ``mutmut run``.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

HUNK_RE = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
# Diffs of survivors past this many are left out of the report; the list keeps all.
MAX_DIFFS = 200


def mutated_modules() -> list[str]:
    config = tomllib.loads(Path("pyproject.toml").read_text())["tool"]["mutmut"]
    return config["only_mutate"]


def changed_lines(base: str, path: str) -> set[int]:
    diff = subprocess.run(
        ["git", "diff", "--unified=0", f"{base}...HEAD", "--", path],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    lines: set[int] = set()
    for match in HUNK_RE.finditer(diff):
        start, count = int(match[1]), int(match[2] or 1)
        # A pure deletion (count 0) starts after line ``start``: mark the lines on
        # both sides, so deleting a function's leading decorator marks its def.
        lines.update(range(start, start + max(count, 2)))
    return lines


def mutable(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether mutmut generates mutants for ``function``.

    mutmut 3.8 skips decorated functions, except ones decorated only with a bare
    ``@staticmethod`` or ``@classmethod``.
    """
    decorators = function.decorator_list
    return not decorators or (
        len(decorators) == 1
        and isinstance(decorators[0], ast.Name)
        and decorators[0].id in ("staticmethod", "classmethod")
    )


def function_globs(path: str, lines: set[int]) -> list[str]:
    """Return mutmut's mutant-name globs for the functions that span ``lines``.

    mutmut names a function's mutants ``<module>.x_<function>__mutmut_<n>`` and a
    method's ``<module>.xǁ<Class>ǁ<method>__mutmut_<n>``.
    """
    module = ".".join(Path(path).relative_to("src").with_suffix("").parts)
    globs = []
    tree = ast.parse(Path(path).read_text())
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions = [(f"x_{node.name}", node)]
        elif isinstance(node, ast.ClassDef):
            functions = [
                (f"xǁ{node.name}ǁ{child.name}", child)
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
        else:
            continue
        for mangled, function in functions:
            if not mutable(function):
                continue
            start = min([function.lineno, *(d.lineno for d in function.decorator_list)])
            if lines & set(range(start, (function.end_lineno or start) + 1)):
                globs.append(f"{module}.{mangled}__mutmut_*")
    return globs


def changed(base: str) -> None:
    for path in mutated_modules():
        if lines := changed_lines(base, path):
            for glob in function_globs(path, lines):
                print(glob)


def mutmut(*args: str) -> str:
    return subprocess.run(
        [sys.executable, "-m", "mutmut", *args], check=True, capture_output=True, text=True
    ).stdout


def report(output: Path) -> None:
    mutmut("export-cicd-stats")
    stats = json.loads(Path("mutants/mutmut-cicd-stats.json").read_text())
    results = [line.strip().rsplit(": ", 1) for line in mutmut("results").splitlines()]
    survivors = sorted(name for name, status in results if status == "survived")
    others = sorted(
        f"{name} ({status})"
        for name, status in results
        if status not in ("survived", "not checked", "timeout")
    )
    tested = stats["killed"] + stats["timeout"] + stats["survived"]
    score = 100 * (stats["killed"] + stats["timeout"]) / tested if tested else 0.0

    lines = [
        "## Mutation testing",
        "",
        f"Score **{score:.1f}%**: {stats['killed']} killed, {stats['timeout']} timed out, "
        f"{stats['survived']} survived, {stats['no_tests']} without tests, "
        f"{stats['suspicious']} suspicious, {stats['skipped']} skipped, "
        f"{stats['total']} mutants in total.",
        "",
    ]
    if stats.get("check_was_interrupted_by_user"):
        lines += ["The run hit its time limit, so some mutants were not tested.", ""]
    if survivors:
        lines += ["### Surviving mutants", ""]
        for name in survivors[:MAX_DIFFS]:
            lines += ["```diff", mutmut("show", name).rstrip(), "```", ""]
        if len(survivors) > MAX_DIFFS:
            lines += [f"{len(survivors) - MAX_DIFFS} more survived:", ""]
            lines += [f"- `{name}`" for name in survivors[MAX_DIFFS:]] + [""]
    if others:
        lines += ["### Mutants without a verdict", ""]
        lines += [f"- `{name}`" for name in others] + [""]
    output.write_text("\n".join(lines))
    print(f"Mutation score {score:.1f}% ({stats['survived']} survived); report in {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("changed").add_argument("base", help="git ref the change is based on")
    commands.add_parser("report").add_argument("output", type=Path, help="Markdown file to write")
    args = parser.parse_args()
    if args.command == "changed":
        changed(args.base)
    else:
        report(args.output)


if __name__ == "__main__":
    main()
