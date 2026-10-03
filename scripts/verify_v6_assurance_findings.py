#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

EXPECTED = {
    "WS-ASSURE-201",
    "WS-ASSURE-202",
    "WS-ASSURE-203",
    "WS-ASSURE-204",
    "WS-ASSURE-205",
}


def main() -> int:
    report = json.loads(Path("security-reports/security-report.json").read_text(encoding="utf-8"))
    actual = {f["finding_id"] for f in report["findings"] if f["finding_id"].startswith("WS-ASSURE-")}
    missing = sorted(EXPECTED - actual)
    unexpected = sorted(actual - EXPECTED)
    if missing or unexpected:
        if missing:
            print("V6 expected findings disappeared:", ", ".join(missing))
        if unexpected:
            print("V6 new assurance findings appeared:", ", ".join(unexpected))
        print("Review WAM assurance changes before updating the V6 baseline.")
        return 2
    print("V6 current WAM independent-assurance findings verified:", ", ".join(sorted(actual)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
