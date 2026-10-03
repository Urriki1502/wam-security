#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("status", type=Path)
    p.add_argument("--block-red", action="store_true")
    args = p.parse_args()

    payload = json.loads(args.status.read_text(encoding="utf-8"))
    if payload.get("schema") != "wam-security-status/v1":
        raise SystemExit("unsupported security status schema")

    overall = payload.get("overall")
    blocked = bool(payload.get("release_blocked"))
    if overall not in {"GREEN", "YELLOW", "RED"}:
        raise SystemExit("invalid overall status")

    print(f"security status: {overall}; release_blocked={str(blocked).lower()}")
    if args.block_red and (overall == "RED" or blocked):
        print("V7 release gate: BLOCKED")
        return 2
    print("V7 release gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
