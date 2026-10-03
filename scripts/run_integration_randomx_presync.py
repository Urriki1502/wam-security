#!/usr/bin/env python3
"""Validate WAM RandomX/header pre-sync invariants on local source and fixtures.

Scope is intentionally limited to an exact open-source checkout, static source
inspection, deterministic synthetic fixtures, and local unit tests. It does
not contact nodes, peers, wallets, pools, or third-party infrastructure.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import time

from wam_security.audit.source import audit_wam_source
from wam_security.model.presync import HeaderClaim, validated_work

WAM_COMMIT = "bd71b0bd645286a3867dad6b2bfefd911ec8a5b6"
FINDING_ID = "WS-P2P-001"


def git_head(root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> dict:
    started = time.time()
    p = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    return {
        "command": cmd,
        "returncode": p.returncode,
        "duration_ms": int((time.time() - started) * 1000),
        "output": p.stdout[-12000:],
    }


def window(text: str, marker: str, size: int = 7000) -> str:
    pos = text.find(marker)
    if pos < 0:
        raise AssertionError(f"missing source marker: {marker}")
    return text[pos : pos + size]


def source_contract(patcher: str) -> dict[str, bool]:
    presync = window(patcher, 'marker="WAM_PRESYNC_POW_SKIPPED"')
    contextual = window(patcher, 'marker="WAM_RANDOMX_POW_VERIFIED"')
    transition = window(patcher, 'marker="WAM_DGW_TRANSITION_PERMITTED"')

    checks = {
        "presync_pow_gate_is_explicitly_skipped":
            "bool HasValidProofOfWork" in presync
            and "WAM_PRESYNC_POW_SKIPPED" in presync
            and "return true;" in presync,
        "contextual_randomx_pow_check_exists":
            "wam::GetRandomXSeedHash(pindexPrev" in contextual
            and "wam::GetRandomXPoWHash(block, seed)" in contextual
            and "wam::CheckProofOfWork" in contextual,
        "randomx_seed_is_chain_context_derived":
            "GetRandomXSeedHash(pindexPrev" in contextual,
        "dgw_transition_filter_is_not_a_pow_check":
            "WAM_DGW_TRANSITION_PERMITTED" in transition
            and "return true;" in transition,
    }
    missing = [name for name, ok in checks.items() if not ok]
    if missing:
        raise AssertionError("source contract mismatch: " + ", ".join(missing))
    return checks


def exercise_synthetic_matrix(cases: int) -> dict:
    """Exercise the existing generic pre-sync invariant model.

    The current WAM source shape is modeled with require_pow=False because its
    early HasValidProofOfWork gate returns success without establishing RandomX
    evidence. The required fail-closed shape is modeled with require_pow=True.
    """

    rng = random.Random(0x57414D)
    divergence = 0
    invalid_claims_accepted_by_current_shape = 0

    for _ in range(cases):
        count = rng.randint(1, 12)
        headers = [
            HeaderClaim(
                claimed_work=rng.randint(1, 1000),
                pow_verified=(rng.randrange(4) == 0),
            )
            for _ in range(count)
        ]
        threshold = rng.randint(1, sum(h.claimed_work for h in headers))

        current_work = validated_work(headers, require_pow=False)
        invalid_count = sum(not h.pow_verified for h in headers)
        invalid_claims_accepted_by_current_shape += invalid_count

        try:
            verified_work = validated_work(headers, require_pow=True)
            safe_rejected = False
        except ValueError:
            verified_work = 0
            safe_rejected = True

        current_reaches = current_work >= threshold
        required_reaches = (not safe_rejected) and verified_work >= threshold

        if current_reaches and not required_reaches:
            divergence += 1

    if divergence == 0:
        raise AssertionError("synthetic matrix did not exercise the pre-sync divergence")

    return {
        "cases": cases,
        "divergence_cases": divergence,
        "unverified_claims_accepted_by_current_shape":
            invalid_claims_accepted_by_current_shape,
        "required_shape_rejects_unverified_work": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path, help="local checkout of wamcoin-core-dev/wam-coin")
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument("--cases", type=int, default=5000)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/integration-randomx-presync.json"),
    )
    args = ap.parse_args()

    if args.cases < 1 or args.cases > 100000:
        raise SystemExit("--cases must be between 1 and 100000")

    repo = Path(__file__).resolve().parents[1]
    wam = args.wam_root.resolve()
    patcher = wam / "scripts/patch_upstream.py"

    if not patcher.is_file():
        raise SystemExit(f"missing WAM patch source: {patcher}")

    head = git_head(wam)
    if head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {head!r}, expected {args.expected_commit}")

    patch_text = patcher.read_text(encoding="utf-8")
    contract = source_contract(patch_text)

    findings = {f.finding_id: f for f in audit_wam_source(wam)}
    finding = findings.get(FINDING_ID)
    if finding is None:
        raise AssertionError(f"{FINDING_ID} was not reproduced by the source audit")

    pyenv = os.environ.copy()
    pyenv["PYTHONPATH"] = str(repo / "src")

    commands = []
    for pattern in (
        "test_randomx_consensus.py",
        "test_presync_model.py",
        "test_source_audit.py",
    ):
        result = run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", pattern, "-v"],
            cwd=repo,
            env=pyenv,
        )
        commands.append(result)
        status = "PASS" if result["returncode"] == 0 else "FAIL"
        print(f"{status:4}  {pattern}")
        if result["returncode"] != 0:
            print(result["output"])
            break

    if len(commands) != 3 or any(c["returncode"] != 0 for c in commands):
        ok = False
        matrix = {}
    else:
        matrix = exercise_synthetic_matrix(args.cases)
        ok = True

    evidence = {
        "schema": "wam-security-integration-randomx-presync/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "commit": head,
            "patch_source": "scripts/patch_upstream.py",
        },
        "locked_scope": {
            "local_fixtures_only": True,
            "network_io": False,
            "public_node_testing": False,
            "third_party_targeting": False,
        },
        "finding": {
            "id": FINDING_ID,
            "status": "CONFIRMED" if ok else "VALIDATION_FAILED",
            "severity": finding.severity,
            "title": finding.title,
            "path": finding.path,
        },
        "invariants": {
            "presync_claimed_work_requires_pow_evidence": False if ok else None,
            "presync_threshold_must_depend_on_verified_work": False if ok else None,
            "contextual_consensus_randomx_check_remains_present": contract.get(
                "contextual_randomx_pow_check_exists", False
            ),
            "randomx_seed_is_chain_context_derived": contract.get(
                "randomx_seed_is_chain_context_derived", False
            ),
            "consensus_acceptance_bypass_observed": False if ok else None,
        },
        "source_contract": contract,
        "synthetic_matrix": matrix,
        "commands": commands,
        "validation_result": "PASS" if ok else "FAIL",
        "security_state": "CONFIRMED_PRESYNC_ANTIDOS_GAP" if ok else "UNKNOWN",
    }

    out = args.out if args.out.is_absolute() else repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"evidence: {out}")
    if ok:
        print(
            f"CONFIRMED {FINDING_ID}: pre-sync can account claimed work before "
            "RandomX proof evidence; later contextual consensus validation remains present."
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
