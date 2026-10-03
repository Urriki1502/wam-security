#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

EXPECTED = {
    "WS-MONEY-101",
    "WS-MONEY-102",
    "WS-MONEY-103",
    "WS-MONEY-104",
    "WS-MONEY-105",
    "WS-MONEY-106",
}

def main() -> int:
    report = json.loads(Path("security-reports/security-report.json").read_text(encoding="utf-8"))
    money = {f["finding_id"] for f in report["findings"] if f["finding_id"].startswith("WS-MONEY-")}
    missing = sorted(EXPECTED - money)
    unexpected = sorted(money - EXPECTED)
    if missing or unexpected:
        if missing:
            print("V4 expected findings disappeared:", ", ".join(missing))
        if unexpected:
            print("V4 new money findings appeared:", ", ".join(unexpected))
        print("Review the current WAM money path deliberately before changing the V4 baseline.")
        return 2
    print("V4 current WAM money-path findings verified:", ", ".join(sorted(money)))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
