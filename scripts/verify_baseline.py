#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import sys


def main() -> int:
    expected_path = Path("baseline/expected_findings.json")
    report_path = Path("security-reports/security-report.json")

    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))

    expected_ids = set(expected["expected_finding_ids"])
    actual_ids = {f["finding_id"] for f in report["findings"]}

    if report.get("target") != expected.get("target"):
        print(f"target mismatch: expected {expected.get('target')} got {report.get('target')}")
        return 2

    missing = sorted(expected_ids - actual_ids)
    unexpected = sorted(actual_ids - expected_ids)

    if missing:
        print("baseline changed: expected findings disappeared:", ", ".join(missing))
    if unexpected:
        print("baseline changed: new finding IDs appeared:", ", ".join(unexpected))

    if missing or unexpected:
        print("Review the upstream change and update the baseline deliberately.")
        return 3

    print("baseline verified:", ", ".join(sorted(actual_ids)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
