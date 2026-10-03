#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

EXPECTED = {
    "WS-SC-101",
    "WS-SC-102",
    "WS-SC-103",
    "WS-SC-104",
    "WS-SC-105",
    "WS-SC-106",
    "WS-SC-107",
    "WS-SC-108",
    "WS-SC-109",
}


def main() -> int:
    report = json.loads(Path("security-reports/security-report.json").read_text(encoding="utf-8"))
    actual = {f["finding_id"] for f in report["findings"] if f["finding_id"].startswith("WS-SC-1")}
    missing = sorted(EXPECTED - actual)
    unexpected = sorted(actual - EXPECTED)
    if missing or unexpected:
        if missing:
            print("V5 expected findings disappeared:", ", ".join(missing))
        if unexpected:
            print("V5 new supply-chain findings appeared:", ", ".join(unexpected))
        print("Review WAM release changes and update the V5 baseline deliberately.")
        return 2
    print("V5 current WAM supply-chain findings verified:", ", ".join(sorted(actual)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
