"""Fail when total branch coverage drops below the checked-in baseline.

Reads the JSON report of a full test run (`pytest --cov=mpp --cov-report=json`)
and compares its branch coverage, covered branches over all branches, with
`.coverage-baseline`. A drop of more than TOLERANCE points fails. When coverage
rises past the baseline, raise it with `--update` and commit the file.

    uv run python scripts/coverage_ratchet.py coverage.json
    uv run python scripts/coverage_ratchet.py coverage.json --update
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

BASELINE = Path(__file__).resolve().parent.parent / ".coverage-baseline"
TOLERANCE = 0.1


def branch_coverage(report: Path) -> float:
    totals = json.loads(report.read_text())["totals"]
    if not totals.get("num_branches"):
        raise SystemExit(f"{report} has no branch data: run coverage with branch = true")
    return 100 * totals["covered_branches"] / totals["num_branches"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check branch coverage against the baseline.")
    parser.add_argument("report", type=Path, nargs="?", default=Path("coverage.json"))
    parser.add_argument("--update", action="store_true", help="write the measured coverage")
    args = parser.parse_args()

    measured = math.floor(branch_coverage(args.report) * 100) / 100
    update_hint = (
        f"Run `uv run python scripts/coverage_ratchet.py {args.report} --update` "
        f"(or `make coverage-baseline` after a full run) and commit {BASELINE.name}."
    )
    if args.update:
        BASELINE.write_text(f"{measured:.2f}\n")
        print(f"{BASELINE.name}: {measured:.2f}%")
        return 0

    baseline = float(BASELINE.read_text())
    print(f"Branch coverage {measured:.2f}% (baseline {baseline:.2f}%, tolerance {TOLERANCE})")
    if measured < baseline - TOLERANCE:
        print(
            f"Branch coverage fell {baseline - measured:.2f} points below {BASELINE.name}. "
            "Cover the new or changed branches with tests. If the drop is intended, "
            f"update the baseline the same way: {update_hint}",
            file=sys.stderr,
        )
        return 1
    if measured > baseline + TOLERANCE:
        print(f"Branch coverage is above the baseline; raise it. {update_hint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
