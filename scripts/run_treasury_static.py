#!/usr/bin/env python3
"""Bind the treasury regression model to the exact reviewed WAM source."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

WAM_COMMIT = "bd71b0bd645286a3867dad6b2bfefd911ec8a5b6"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/treasury-static.json"),
    )
    args = ap.parse_args()
    root = args.wam_root.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {head}, expected {args.expected_commit}")

    script = (root / "scripts/treasury_spend.py").read_text(encoding="utf-8")
    params = (root / "src/wam/chainparams.cpp").read_text(encoding="utf-8")
    checks = {
        "mempool_is_consulted": 'rpc.call("getrawmempool")' in script,
        "current_mempool_lookup_can_continue_on_unknown_tx":
            "except Exception:\n            continue" in script,
        "current_wif_check_is_checksum_only":
            "def _wif_looks_whole" in script
            and "WIF carries its own base58check checksum" in script,
        "current_file_combines_online_and_offline_roles":
            all(x in script for x in ("def cmd_plan", "def cmd_sign", "def cmd_broadcast")),
        "current_broadcaster_does_not_recheck_gettxout": '"gettxout"' not in script,
        "wam_mainnet_wif_prefix_is_190":
            "base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 190)"
            in params,
    }
    if not all(checks.values()):
        raise AssertionError(
            "locked treasury source contract changed: "
            + json.dumps(checks, sort_keys=True)
        )

    evidence = {
        "schema": "wam-security-treasury-static/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "commit": head,
        },
        "checks": checks,
        "reference_refactor": {
            "online": "src/wam_security/treasury/online.py",
            "offline": "src/wam_security/treasury/offline.py",
            "common": "src/wam_security/treasury/common.py",
        },
        "result": "PASS",
        "classification": "LOCKED_UPSTREAM_GAPS_CAPTURED_AND_REGRESSION_MODELLED",
    }
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("treasury locked-source contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
