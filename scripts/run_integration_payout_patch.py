#!/usr/bin/env python3
"""Review a WAM pool payout patch against WAM Security's money invariants.

This runner is intentionally non-exploitative. It executes local regression tests,
checks the released source contract, and emits machine-readable evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Iterable

PATCH_COMMIT = "260bc468e5adffea7ce68d8f97fac3e27e4c50b2"


def run(cmd: list[str], *, cwd: Path, timeout: int = 180, env: dict[str, str] | None = None) -> dict:
    started = time.time()
    p = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        env=env,
    )
    return {
        "command": cmd,
        "cwd": str(cwd),
        "returncode": p.returncode,
        "duration_ms": int((time.time() - started) * 1000),
        "output": p.stdout[-12000:],
    }


def require_tokens(text: str, required: Iterable[tuple[str, str]]) -> list[dict]:
    checks = []
    for name, token in required:
        ok = token in text
        checks.append({"name": name, "ok": ok})
        if not ok:
            raise AssertionError(f"source contract missing: {name}")
    return checks


def git_head(root: Path) -> str | None:
    try:
        p = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return p.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path, help="local wam-coin checkout")
    ap.add_argument("--expected-commit", default=PATCH_COMMIT)
    ap.add_argument("--allow-descendant", action="store_true",
                    help="accept a checkout that contains the expected commit")
    ap.add_argument("--cases", type=int, default=5000,
                    help="WAM Security payout fault cases")
    ap.add_argument("--out", type=Path,
                    default=Path("security-reports/integration-payout-patch.json"))
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[1]
    wam = args.wam_root.resolve()
    daemon = wam / "pool/lib/daemon.js"
    share = wam / "pool/lib/shareProcessor.js"
    job_manager = wam / "pool/lib/jobManager.js"
    daemon_test = wam / "pool/test/daemon-money-failover.test.js"
    payment_test = wam / "pool/test/payment-safety.test.js"
    payment_postponed_test = wam / "pool/test/payment-postponed.test.js"
    share_claim_test = wam / "pool/test/share-claim.test.js"
    winning_share_test = wam / "pool/test/winning-share.test.js"
    rewards_test = wam / "pool/test/rewards.test.js"
    verify_backpressure_test = wam / "pool/test/verify-backpressure.test.js"
    block_spool_test = wam / "pool/test/block-spool.test.js"
    maturation_claim_test = wam / "pool/test/maturation-claim.test.js"

    for p in (
        daemon, share, job_manager, daemon_test, payment_test, payment_postponed_test,
        share_claim_test, winning_share_test, rewards_test,
        verify_backpressure_test, block_spool_test, maturation_claim_test,
    ):
        if not p.is_file():
            raise SystemExit(f"missing required WAM patch file: {p}")

    head = git_head(wam)
    commit_ok = head == args.expected_commit
    if not commit_ok and args.allow_descendant and head:
        ancestry = run(
            ["git", "merge-base", "--is-ancestor", args.expected_commit, head],
            cwd=wam,
            timeout=30,
        )
        commit_ok = ancestry["returncode"] == 0
    if not commit_ok:
        raise SystemExit(
            f"WAM checkout is {head or 'not a git checkout'}, expected "
            f"{args.expected_commit}" + (" or a descendant" if args.allow_descendant else "")
        )

    source_checks = []
    source_checks += require_tokens(daemon.read_text(encoding="utf-8"), [
        ("money RPC guard exists", "DaemonInterface.MONEY_RPCS = new Set"),
        ("sendmany is guarded", "'sendmany'"),
        ("socket outcome is classified", "err.ambiguous"),
        ("ambiguous money RPC stops failover", "if (guarded && err.ambiguous)"),
    ])
    share_text = share.read_text(encoding="utf-8")
    source_checks += require_tokens(share_text, [
        ("unknown payout outcome fails closed", "if (err.ambiguous !== false)"),
        ("unknown payout pauses payments", "this.paused = true"),
        ("payment intent is durable", "payment:inflight"),
        ("accounting uses Redis transaction", "const pipe = this.redis.multi()"),
        ("transaction is created before broadcast", "createrawtransaction"),
        ("wallet funds the transaction before broadcast", "fundrawtransaction"),
        ("wallet signs before broadcast", "signrawtransactionwithwallet"),
        ("transaction identity exists before broadcast", "decoderawtransaction"),
        ("broadcast uses signed bytes", "sendrawtransaction"),
        ("unknown outcome is reconciled by txid", "getrawtransaction"),
    ])
    job_text = job_manager.read_text(encoding="utf-8")
    source_checks += require_tokens(job_text, [
        ("recovered block restores coinbase value", "coinbaseValue: e.coinbaseValue"),
        ("recovered block restores distributable value", "distributableValue: e.distributableValue"),
        ("recovered block restores dev fee value", "devFeeAmount: e.devFeeAmount"),
        ("duplicate-like recovery is offered to payout", "offering it for payout"),
        ("RandomX native admission is VM-slot bounded", "this._vmSlots = vms"),
        ("RandomX surplus waits in JavaScript", "this._waiting = []"),
        ("RandomX hashes through VM-slot gate", "this._hashWithOneVm(job.seedHash, header)"),
    ])
    source_checks += require_tokens(share_text, [
        ("block accounting checks pending idempotency", "this.redis.hexists(this.k('blocks:pending'), share.blockHash)"),
        ("block accounting checks confirmed idempotency", "this.redis.sismember(this.k('blocks:confirmed:hashes'), share.blockHash)"),
        ("matured block hashes are retained", "pipe.sadd(this.k('blocks:confirmed:hashes'), record.blockHash)"),
    ])

    intent_write = "await this.redis.set(this.k('payment:inflight'), JSON.stringify(intent));"
    broadcast = "await this.daemon.cmd('sendrawtransaction', [signedHex]);"
    write_at = share_text.find(intent_write)
    broadcast_at = share_text.find(broadcast)
    durable_before_broadcast = write_at >= 0 and broadcast_at >= 0 and write_at < broadcast_at
    source_checks.append({
        "name": "durable txid/raw intent precedes broadcast",
        "ok": durable_before_broadcast,
    })
    if not durable_before_broadcast:
        raise AssertionError("payment identity/raw bytes are not durably stored before broadcast")

    pyenv = os.environ.copy()
    pyenv["PYTHONPATH"] = str(repo / "src")
    commands = [
        ([sys.executable, "-m", "unittest", "discover", "-s", "tests",
          "-p", "test_money_safety.py", "-v"], repo, pyenv),
        ([sys.executable, "scripts/run_v4_money_faults.py", "--seed", "0x57414D",
          "--cases", str(args.cases)], repo, pyenv),
        (["node", str(daemon_test)], wam / "pool", None),
        (["node", str(payment_test)], wam / "pool", None),
        (["node", str(payment_postponed_test)], wam / "pool", None),
        (["node", str(share_claim_test)], wam / "pool", None),
        (["node", str(winning_share_test)], wam / "pool", None),
        (["node", str(rewards_test)], wam / "pool", None),
        (["node", str(verify_backpressure_test)], wam / "pool", None),
        (["node", str(block_spool_test)], wam / "pool", None),
        (["node", str(maturation_claim_test)], wam / "pool", None),
    ]

    results = []
    for cmd, cwd, env in commands:
        result = run(cmd, cwd=cwd, env=env)
        results.append(result)
        status = "PASS" if result["returncode"] == 0 else "FAIL"
        print(f"{status:4}  {' '.join(cmd)}")
        if result["returncode"] != 0:
            print(result["output"])
            break

    ok = len(results) == len(commands) and all(r["returncode"] == 0 for r in results)
    evidence = {
        "schema": "wam-security-integration-payout-patch/v2",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "expected_commit": args.expected_commit,
            "observed_commit": head,
        },
        "invariants": {
            "unknown_rpc_outcome_is_not_retried_as_new_spend": ok,
            "unknown_rpc_outcome_retains_recovery_intent": ok,
            "restart_with_unresolved_intent_is_fail_closed": ok,
            "redis_accounting_uses_multi_exec": ok,
            "one_logical_payout_at_most_one_economic_payment": ok,
            "transaction_identity_is_durable_before_broadcast": durable_before_broadcast and ok,
            "same_signed_transaction_is_recoverable_after_unknown_outcome": ok,
            "winning_share_accounting_regression_passes": ok,
            "share_durability_regression_passes": ok,
            "pplns_window_regression_passes": ok,
            "randomx_backpressure_regression_passes": ok,
            "solved_block_spool_regression_passes": ok,
            "recovered_block_restores_money_context": ok,
            "recovered_duplicate_reaches_idempotent_accounting": ok,
            "record_block_idempotency_regression_passes": ok,
            "randomx_native_workers_are_vm_slot_bounded": ok,
        },
        "source_contract": source_checks,
        "commands": results,
        "result": "PASS" if ok else "FAIL",
    }

    out = args.out if args.out.is_absolute() else repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"evidence: {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
