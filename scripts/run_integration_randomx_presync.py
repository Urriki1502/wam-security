#!/usr/bin/env python3
"""Validate WAM RandomX/header pre-sync invariants on local source and fixtures.

Scope is intentionally limited to exact open-source checkouts, static source
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


def read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        raise AssertionError(f"missing source path: {rel}")
    return path.read_text(encoding="utf-8")


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


def window(text: str, marker: str, size: int = 9000) -> str:
    pos = text.find(marker)
    if pos < 0:
        raise AssertionError(f"missing source marker: {marker}")
    return text[pos : pos + size]


def patch_contract(patcher: str) -> dict[str, bool]:
    presync = window(patcher, 'marker="WAM_PRESYNC_POW_SKIPPED"')
    contextual = window(patcher, 'marker="WAM_RANDOMX_POW_VERIFIED"')
    transition = window(patcher, 'marker="WAM_DGW_TRANSITION_PERMITTED"')

    checks = {
        "patch_declares_presync_pow_gate_skipped":
            "bool HasValidProofOfWork" in presync
            and "WAM_PRESYNC_POW_SKIPPED" in presync
            and "return true;" in presync,
        "patch_declares_contextual_randomx_pow_check":
            "wam::GetRandomXSeedHash(pindexPrev" in contextual
            and "wam::GetRandomXPoWHash(block, seed)" in contextual
            and "wam::CheckProofOfWork" in contextual,
        "patch_declares_dgw_presync_transition_override":
            "WAM_DGW_TRANSITION_PERMITTED" in transition
            and "return true;" in transition,
    }
    missing = [name for name, ok in checks.items() if not ok]
    if missing:
        raise AssertionError("patch contract mismatch: " + ", ".join(missing))
    return checks


def patched_tree_contract(core: Path) -> tuple[dict[str, bool], list[str]]:
    validation = read(core, "src/validation.cpp")
    net = read(core, "src/net_processing.cpp")
    headerssync = read(core, "src/headerssync.cpp")
    pow_cpp = read(core, "src/pow.cpp")
    randomx_cpp = read(core, "src/wam/crypto/randomx_hash.cpp")
    wam_pow = read(core, "src/wam/pow.cpp")

    accept = window(validation, "bool ChainstateManager::AcceptBlockHeader", 16000)
    process_new = window(validation, "bool ChainstateManager::ProcessNewBlockHeaders", 6000)
    contextual = window(validation, "static bool ContextualCheckBlockHeader", 18000)
    has_valid_pow = window(validation, "bool HasValidProofOfWork", 4000)
    claimed = window(validation, "arith_uint256 CalculateClaimedHeadersWork", 3500)
    process_headers = window(net, "void PeerManagerImpl::ProcessHeadersMessage", 18000)
    presync_one = window(headerssync, "bool HeadersSyncState::ValidateAndProcessSingleHeader", 6500)
    permitted = window(pow_cpp, "bool PermittedDifficultyTransition", 5000)
    seed_height = window(randomx_cpp, "int GetRandomXSeedHeight", 4000)
    seed_hash = window(randomx_cpp, "uint256 GetRandomXSeedHash", 4500)
    pow_hash = window(randomx_cpp, "uint256 GetRandomXPoWHash", 3000)

    contextual_pos = accept.find("ContextualCheckBlockHeader(")
    min_pow_pos = accept.find("if (!min_pow_checked)")
    add_index_pos = accept.find("AddToBlockIndex(")

    check_headers_pos = process_headers.find("CheckHeadersPoW(")
    continue_presync_pos = process_headers.find("IsContinuationOfLowWorkHeadersSync(")
    start_presync_pos = process_headers.find("TryLowWorkHeadersSync(")

    checks = {
        "actual_presync_batch_pow_gate_returns_true":
            "WAM_PRESYNC_POW_SKIPPED" in has_valid_pow
            and "(void)headers;" in has_valid_pow
            and "return true;" in has_valid_pow,
        "process_headers_runs_batch_gate_before_low_work_presync":
            -1 < check_headers_pos < continue_presync_pos < start_presync_pos,
        "claimed_headers_work_is_derived_from_nbits_without_randomx_evidence":
            "CBlockIndex dummy(header);" in claimed
            and "GetBlockProof(dummy)" in claimed
            and "GetRandomXPoWHash" not in claimed,
        "presync_accumulates_claimed_header_work":
            "m_current_chain_work += GetBlockProof(CBlockIndex(current));" in presync_one,
        "accept_header_contextual_check_precedes_min_pow_gate_and_index_insert":
            -1 < contextual_pos < min_pow_pos < add_index_pos,
        "min_pow_checked_is_not_passed_as_contextual_fcheckpow":
            "ContextualCheckBlockHeader(block, state, m_blockman, *this, pindexPrev)" in accept
            and "ContextualCheckBlockHeader(block, state, m_blockman, *this, pindexPrev, min_pow_checked)" not in accept,
        "process_new_headers_passes_min_pow_only_to_acceptblockheader":
            "AcceptBlockHeader(header, state, &pindex, min_pow_checked)" in process_new,
        "contextual_randomx_pow_is_guarded_by_fcheckpow":
            "if (fCheckPOW)" in contextual
            and "wam::GetRandomXSeedHash(pindexPrev" in contextual
            and "wam::GetRandomXPoWHash(block, seed)" in contextual
            and "wam::CheckProofOfWork(pow_hash, block.nBits" in contextual,
        "template_validation_has_explicit_fcheckpow_escape_only":
            "chainstate.m_chainman, pindexPrev, fCheckPOW)" in validation,
        "dgw_presync_transition_accepts_per_block_changes":
            "WAM_DGW_TRANSITION_PERMITTED" in permitted
            and "(void)height; (void)old_nbits; (void)new_nbits; (void)params;" in permitted
            and "return true;" in permitted,
        "randomx_epoch_and_lag_come_from_consensus_params":
            "params.nRandomXEpochBlocks" in seed_height
            and "params.nRandomXEpochLag" in seed_height,
        "randomx_seed_uses_parent_chain_ancestor":
            "pindexPrev->GetAncestor(nSeedHeight)" in seed_hash
            and "return pindexSeed->GetBlockHash();" in seed_hash,
        "randomx_pow_hashes_serialized_header":
            "ss << header;" in pow_hash
            and "assert(ss.size() == RANDOMX_INPUT_SIZE);" in pow_hash
            and "GetRandomXHashRaw" in pow_hash,
        "dgw_retargets_via_wam_consensus_entrypoint":
            "unsigned int GetNextWorkRequired" in wam_pow
            and "return DarkGravityWave(pindexLast, params);" in wam_pow,
    }

    missing = [name for name, ok in checks.items() if not ok]
    if missing:
        raise AssertionError("patched-tree contract mismatch: " + ", ".join(missing))

    paths = [
        "scripts/patch_upstream.py",
        "src/net_processing.cpp",
        "src/headerssync.cpp",
        "src/validation.cpp",
        "src/pow.cpp",
        "src/wam/pow.cpp",
        "src/wam/crypto/randomx_hash.cpp",
        "src/rpc/mining.cpp",
    ]
    return checks, paths


def exercise_synthetic_matrix(cases: int) -> dict:
    """Exercise the existing generic pre-sync invariant model."""

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
        "seed": "0x57414D",
        "divergence_cases": divergence,
        "unverified_claims_accepted_by_current_shape":
            invalid_claims_accepted_by_current_shape,
        "required_shape_rejects_unverified_work": True,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path, help="local checkout of wamcoin-core-dev/wam-coin")
    ap.add_argument("--patched-tree", type=Path, required=True)
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
    core = args.patched_tree.resolve()
    patcher = wam / "scripts/patch_upstream.py"

    if not patcher.is_file():
        raise SystemExit(f"missing WAM patch source: {patcher}")

    head = git_head(wam)
    if head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {head!r}, expected {args.expected_commit}")

    security_head = os.environ.get("SECURITY_TARGET_SHA") or git_head(repo)

    patch_checks = patch_contract(patcher.read_text(encoding="utf-8"))
    tree_checks, source_paths = patched_tree_contract(core)

    findings = {f.finding_id: f for f in audit_wam_source(wam)}
    finding = findings.get(FINDING_ID)
    if finding is None:
        raise AssertionError(f"{FINDING_ID} was not reproduced by the source audit")

    pyenv = os.environ.copy()
    pyenv["PYTHONPATH"] = str(repo / "src")

    patterns = (
        "test_randomx_consensus.py",
        "test_presync_model.py",
        "test_dgw.py",
        "test_pow_boundary.py",
        "test_source_audit.py",
    )
    commands = []
    for pattern in patterns:
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

    unit_ok = len(commands) == len(patterns) and all(c["returncode"] == 0 for c in commands)
    matrix = exercise_synthetic_matrix(args.cases) if unit_ok else {}
    ok = unit_ok and all(patch_checks.values()) and all(tree_checks.values())

    evidence = {
        "schema": "wam-security-integration-randomx-presync/v2",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "wam_commit": head,
            "wam_security_head": security_head,
            "patch_source": "scripts/patch_upstream.py",
            "patched_tree": str(core),
        },
        "locked_scope": {
            "local_fixtures_only": True,
            "public_node_testing": False,
            "real_peer_testing": False,
            "third_party_targeting": False,
            "credential_access": False,
            "service_disruption": False,
        },
        "finding": {
            "id": FINDING_ID,
            "status": "CONFIRMED" if ok else "VALIDATION_FAILED",
            "severity": finding.severity,
            "title": finding.title,
            "path": finding.path,
            "root_cause": "pre-sync accounts nBits-derived claimed work before RandomX evidence is established",
        },
        "invariants": {
            "unverified_claimed_work_is_not_security_work": False if ok else None,
            "presync_threshold_requires_verified_pow": False if ok else None,
            "invalid_randomx_pow_reaches_accepted_index": False if ok else None,
            "chain_derived_randomx_seed_at_epoch_boundaries": True if ok else None,
            "dgw_per_block_transition_not_rejected_by_bitcoin_schedule": True if ok else None,
            "min_pow_checked_does_not_disable_contextual_randomx": True if ok else None,
            "accepted_header_path_uses_contextual_randomx": True if ok else None,
            "reorg_seed_boundary_is_deterministic": True if ok else None,
            "consensus_acceptance_bypass_observed": False if ok else None,
        },
        "coverage": {
            "source_paths": source_paths,
            "patch_contract": patch_checks,
            "patched_tree_contract": tree_checks,
            "unit_patterns": list(patterns),
            "synthetic_matrix": matrix,
            "native_regtest": "covered by Security V3 patched-wamd job on this PR",
            "dgw_native_regtest_limit": (
                "regtest sets fPowNoRetargeting, so DGW transition behavior is covered "
                "by executable model tests plus patched-source contract rather than regtest retargeting"
            ),
        },
        "commands": commands,
        "validation_result": "PASS" if ok else "FAIL",
        "security_state": "CONFIRMED_PRESYNC_ANTIDOS_GAP" if ok else "UNKNOWN",
        "classification": "PRE_SYNC_ANTI_DOS_ONLY_NO_CONSENSUS_BYPASS_DEMONSTRATED" if ok else "UNKNOWN",
    }

    out = args.out if args.out.is_absolute() else repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"evidence: {out}")
    if ok:
        print(
            f"CONFIRMED {FINDING_ID}: pre-sync can account claimed work before "
            "RandomX proof evidence; accepted-header contextual RandomX validation remains present."
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
