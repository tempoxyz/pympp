"""Mutation testing report for ``make mutation`` and the weekly ``mutation.yml``.

``report`` writes the surviving mutants, with their diffs, as Markdown after
``mutmut run``.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path

# Diffs of survivors past this many are left out of the report; the list keeps all.
MAX_DIFFS = 200


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
    # mutmut records no verdict for mutants a time-boxed (SIGINT) run never
    # reached; they stay "not checked" and are left out of the score. When
    # ``make mutation MUTANTS=...`` selected some, only those count.
    selected = os.environ.get("MUTANTS", "").split()
    unchecked = sum(
        1
        for name, status in results
        if status == "not checked"
        and (not selected or any(fnmatch.fnmatchcase(name, glob) for glob in selected))
    )
    if unchecked or stats.get("check_was_interrupted_by_user"):
        lines += [
            f"**Incomplete run:** {unchecked} mutants were not tested (time limit), "
            "so the score covers only the tested ones.",
            "",
        ]
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
    commands.add_parser("report").add_argument("output", type=Path, help="Markdown file to write")
    args = parser.parse_args()
    report(args.output)


if __name__ == "__main__":
    main()
