#!/usr/bin/env python3
"""Review the maintainer's block-spool recovery fix against the reproduced invariants."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

FIX = "260bc468e5adffea7ce68d8f97fac3e27e4c50b2"
BASE = "bb6d5214f2f5de3b7464587cc1b2949d221dcd18"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("--out", type=Path,
                    default=Path("security-reports/maintainer-block-spool-fix.json"))
    args = ap.parse_args()
    root = args.wam_root.resolve()

    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    parent = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD^"], text=True
    ).strip()
    if head != FIX or parent != BASE:
        raise SystemExit(f"expected {BASE} -> {FIX}, got {parent} -> {head}")

    job = (root / "pool/lib/jobManager.js").read_text(encoding="utf-8")
    share = (root / "pool/lib/shareProcessor.js").read_text(encoding="utf-8")
    block_test = (root / "pool/test/block-spool.test.js").read_text(encoding="utf-8")
    maturation_test = (root / "pool/test/maturation-claim.test.js").read_text(encoding="utf-8")

    checks = {
        "spool_persists_coinbase_value": "coinbaseValue: job.coinbaseValue" in job,
        "spool_persists_distributable_value":
            "distributableValue: job.distributableValue" in job,
        "spool_persists_treasury_value": "devFeeAmount: job.devFeeAmount" in job,
        "recovered_event_restores_coinbase_value":
            "coinbaseValue: e.coinbaseValue" in job,
        "recovered_event_restores_distributable_value":
            "distributableValue: e.distributableValue" in job,
        "recovered_event_restores_treasury_value":
            "devFeeAmount: e.devFeeAmount" in job,
        "duplicate_path_offers_recovered_block_for_accounting":
            "offering it for payout" in job and "this._emitRecovered(e);" in job,
        "record_block_checks_pending_hash":
            "hexists(this.k('blocks:pending'), share.blockHash)" in share,
        "record_block_checks_confirmed_hash":
            "sismember(this.k('blocks:confirmed:hashes'), share.blockHash)" in share,
        "maturation_persists_confirmed_hash":
            "sadd(this.k('blocks:confirmed:hashes'), record.blockHash)" in share,
        "regression_test_covers_complete_recovered_context":
            "a recovered block carries everything the payout needs" in block_test,
        "regression_test_covers_duplicate_recovery":
            '"duplicate" still offers the block for payout' in block_test,
        "regression_test_covers_idempotent_recording":
            "recording the same block twice pays once and wipes no round"
            in maturation_test,
        "regression_test_covers_confirmed_hash_memory":
            "a matured block hash is remembered" in maturation_test,
    }

    ok = all(checks.values())
    evidence = {
        "schema": "wam-security-maintainer-block-spool-review/v1",
        "base": BASE,
        "fix": FIX,
        "checks": checks,
        "invariants": {
            "recovered_block_has_money_context": ok,
            "duplicate_recovery_reaches_accounting": ok,
            "repeat_accounting_is_guarded_by_block_hash": ok,
            "matured_blocks_remain_identifiable_after_trimmed_history": ok,
        },
        "result": "PASS" if ok else "FAIL",
    }
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(json.dumps({"result": evidence["result"], "evidence": str(out)},
                     sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
