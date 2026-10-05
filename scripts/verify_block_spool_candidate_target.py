#!/usr/bin/env python3
"""Bind the block-spool recovery model to the exact reviewed WAM source."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

EXPECTED = "bb6d5214f2f5de3b7464587cc1b2949d221dcd18"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("--expected-commit", default=EXPECTED)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/block-spool-candidate-source.json"),
    )
    args = ap.parse_args()
    root = args.wam_root.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {head}, expected {args.expected_commit}")

    job = (root / "pool/lib/jobManager.js").read_text(encoding="utf-8")
    server = (root / "pool/server.js").read_text(encoding="utf-8")
    share = (root / "pool/lib/shareProcessor.js").read_text(encoding="utf-8")

    partial_spool = (
        "const spooled = { height: job.height, hash: blockHash, hex: blockHex,"
        in job
        and "worker: share.worker, foundAt: Date.now()" in job
    )
    accepted_emit = (
        "this.emit('block', { height: e.height, blockHash: e.hash," in job
        and "worker: e.worker, blockAccepted: true," in job
        and "fromSpool: true" in job
    )
    duplicate_like_settles_without_emit = (
        "/duplicate|inconclusive/i" in job
        and "await this._unspool(e.hash);" in job
    )
    drain_at = server.find("jobManager.drainSpool()")
    listener_at = server.find("jobManager.on('block'")
    drain_before_listener = (
        drain_at >= 0 and listener_at >= 0 and drain_at < listener_at
    )
    record_block_requires_money_context = all(
        token in share
        for token in (
            "blockValue: share.distributableValue",
            "coinbaseValue: share.coinbaseValue",
            "devFeeAmount: share.devFeeAmount",
        )
    )

    checks = {
        "current_spool_entry_is_partial": partial_spool,
        "accepted_recovery_emits_partial_block_event": accepted_emit,
        "duplicate_like_path_settles_spool": duplicate_like_settles_without_emit,
        "startup_drain_begins_before_block_listener_registration":
            drain_before_listener,
        "record_block_requires_original_money_context":
            record_block_requires_money_context,
    }
    if not all(checks.values()):
        raise AssertionError(
            "reviewed source shape changed: " + json.dumps(checks, sort_keys=True)
        )

    evidence = {
        "schema": "wam-security-block-spool-candidate-source/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "commit": head,
        },
        "checks": checks,
        "classification": "CURRENT_RECOVERY_SHAPE_BOUND_TO_REFERENCE_MODEL",
        "result": "PASS",
    }
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("block-spool candidate source binding: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
