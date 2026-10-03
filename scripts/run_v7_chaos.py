#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

from wam_security.fabric.core import Check, build_status


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        red = build_status(
            generated_at="2026-10-03T00:00:00Z",
            fabric_version="0.7.0-chaos",
            target_repository="https://github.com/wamcoin-core-dev/wam-coin",
            target_head="1" * 40,
            audited_head="1" * 40,
            checks=[
                Check(
                    "chaos.synthetic-supply-breach",
                    "chaos",
                    "FAIL",
                    True,
                    "Synthetic critical invariant failure.",
                    {"injected": True},
                )
            ],
        )
        red_path = root / "red.json"
        red_path.write_text(json.dumps(red), encoding="utf-8")

        blocked = subprocess.run(
            [
                sys.executable,
                "scripts/verify_v7_release_gate.py",
                str(red_path),
                "--block-red",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if blocked.returncode == 0:
            raise AssertionError("RED chaos status failed to block release")

        yellow = build_status(
            generated_at="2026-10-03T00:00:00Z",
            fabric_version="0.7.0-chaos",
            target_repository="https://github.com/wamcoin-core-dev/wam-coin",
            target_head="1" * 40,
            audited_head="1" * 40,
            checks=[
                Check(
                    "chaos.synthetic-endpoint-loss",
                    "chaos",
                    "UNKNOWN",
                    False,
                    "Synthetic monitoring endpoint outage.",
                    {"injected": True},
                )
            ],
        )
        yellow_path = root / "yellow.json"
        yellow_path.write_text(json.dumps(yellow), encoding="utf-8")
        allowed = subprocess.run(
            [
                sys.executable,
                "scripts/verify_v7_release_gate.py",
                str(yellow_path),
                "--block-red",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if allowed.returncode != 0:
            raise AssertionError("YELLOW chaos status incorrectly blocked release")

        print(blocked.stdout.strip())
        print(allowed.stdout.strip())
        print("V7 chaos exercise: PASS (RED blocks, YELLOW degrades)")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
