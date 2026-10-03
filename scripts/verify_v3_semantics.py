#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    report = json.loads(Path("security-reports/security-report.json").read_text(encoding="utf-8"))
    drift = [
        f for f in report["findings"]
        if f["finding_id"] in {"WS-CONS-101", "WS-CONS-102", "WS-CONS-103"}
    ]
    if drift:
        for f in drift:
            print(f"consensus semantic drift: {f['finding_id']} {f['title']}")
        return 2
    print("V3 pinned consensus semantics: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
