#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    report = json.loads(Path("security-reports/security-report.json").read_text(encoding="utf-8"))
    runtime = [f for f in report["findings"] if f["finding_id"].startswith("WS-RUNTIME-")]
    if runtime:
        for finding in runtime:
            print(f"runtime regression: {finding['finding_id']} {finding['title']}")
        return 2
    print("runtime-control baseline: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
