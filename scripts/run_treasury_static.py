#!/usr/bin/env python3
"""Bind treasury regressions to the exact reviewed WAM source."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

WAM_COMMIT = "bb6d5214f2f5de3b7464587cc1b2949d221dcd18"


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
    upstream_test = (root / "scripts/test/test_treasury_spend.py").read_text(
        encoding="utf-8"
    )

    checks = {
        "mempool_is_consulted":
            'rpc.call("getrawmempool")' in script,
        "mempool_lookup_fails_closed":
            "cannot read mempool transaction" in script
            and "Nothing was planned." in script,
        "wif_validates_checksum_network_shape_and_scalar":
            all(
                token in script
                for token in (
                    "def _wif_problem",
                    "WAM_WIF_VERSION = 190",
                    "SECP256K1_N =",
                    "another network",
                    "compressed-key marker",
                    "valid secp256k1 private key",
                )
            ),
        "plan_records_exact_input_set":
            '"inputSet": inputs' in script,
        "signer_decodes_and_verifies_unsigned_transaction":
            "def _offline_decode" in script
            and '_verify_against_plan(plan, decoded, "the unsigned transaction")'
            in script,
        "broadcaster_verifies_signed_transaction":
            '_verify_against_plan(signed, tx, "the signed transaction")' in script,
        "broadcaster_rechecks_inputs_with_mempool":
            'rpc.call("gettxout", [txid, vout, True])' in script,
        "roles_are_explicit_plan_sign_broadcast_commands":
            all(
                x in script
                for x in ("def cmd_plan", "def cmd_sign", "def cmd_broadcast")
            ),
        "upstream_regression_suite_covers_wif_and_plan_mismatch":
            "a key for another network is refused" in upstream_test
            and "different inputs with the same count are refused" in upstream_test,
        "wam_mainnet_wif_prefix_is_190":
            "base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 190)"
            in params,
    }
    if not all(checks.values()):
        raise AssertionError(
            "current treasury source contract changed: "
            + json.dumps(checks, sort_keys=True)
        )

    evidence = {
        "schema": "wam-security-treasury-static/v2",
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
        "classification": "CURRENT_UPSTREAM_TREASURY_HARDENING_CAPTURED",
    }
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("treasury current-source contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
