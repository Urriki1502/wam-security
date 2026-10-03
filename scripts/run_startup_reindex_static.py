#!/usr/bin/env python3
"""Static contract for WAM startup/reindex RandomX trust boundaries.

This runner is intentionally non-adversarial. It inspects the exact reviewed
open-source WAM source and its exact patched Bitcoin Core tree. It does not
modify databases, construct persisted corruption, contact peers, or perform
network I/O.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess

WAM_COMMIT = "bd71b0bd645286a3867dad6b2bfefd911ec8a5b6"


def read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        raise AssertionError(f"missing source path: {rel}")
    return path.read_text(encoding="utf-8")


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


def function_body(text: str, marker: str, *, max_len: int = 22000) -> str:
    start = text.find(marker)
    if start < 0:
        raise AssertionError(f"missing source marker: {marker}")
    return text[start : start + max_len]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("--patched-tree", type=Path, required=True)
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/startup-reindex-static.json"),
    )
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[1]
    wam = args.wam_root.resolve()
    core = args.patched_tree.resolve()

    wam_head = git_head(wam)
    if wam_head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {wam_head!r}, expected {args.expected_commit}")

    patcher = read(wam, "scripts/patch_upstream.py")
    blockstorage = read(core, "src/node/blockstorage.cpp")
    validation = read(core, "src/validation.cpp")
    chainstate = read(core, "src/node/chainstate.cpp")
    init = read(core, "src/init.cpp")
    randomx = read(core, "src/wam/crypto/randomx_hash.cpp")

    load_index = function_body(blockstorage, "bool BlockTreeDB::LoadBlockIndexGuts", max_len=9000)
    load_tip = function_body(validation, "bool Chainstate::LoadChainTip", max_len=5000)
    verify_db = function_body(validation, "VerifyDBResult CVerifyDB::VerifyDB", max_len=17000)
    complete_init = function_body(chainstate, "static ChainstateLoadResult CompleteChainstateInitialization", max_len=17000)
    startup_flags = function_body(init, "bool do_reindex", max_len=12000)
    seed_hash = function_body(randomx, "uint256 GetRandomXSeedHash", max_len=5000)

    checks = {
        "wam_patch_removes_index_sha256d_pow_recheck":
            "WAM_INDEX_POW_CHECK_REMOVED" in patcher,
        "wam_patch_removes_disk_sha256d_pow_recheck":
            "WAM_DISK_POW_CHECK_REMOVED" in patcher,
        "patched_index_loader_restores_validation_status":
            "pindexNew->nStatus" in load_index
            and "pindexNew->nBits" in load_index
            and "pindexNew->nNonce" in load_index,
        "patched_index_loader_has_no_contextual_randomx_recheck":
            "CheckProofOfWork" not in load_index
            and "GetRandomXPoWHash" not in load_index
            and "ContextualCheckBlockHeader" not in load_index,
        "loadchaintip_restores_tip_from_coins_best_block":
            "CoinsTip()" in load_tip
            and "LookupBlockIndex(coins_cache.GetBestBlock())" in load_tip
            and "m_chain.SetTip(*pindex)" in load_tip,
        "startup_verification_uses_verifydb":
            "VerifyDB(" in chainstate
            and "VerifyLoadedChainstate" in chainstate,
        "verifydb_does_not_call_contextual_header_validation":
            "CheckBlock(block, state, consensus_params)" in verify_db
            and "ContextualCheckBlockHeader(" not in verify_db,
        "reindex_chainstate_wipes_chainstate_not_block_tree":
            "options.wipe_block_tree_db = do_reindex;" in startup_flags
            and "options.wipe_chainstate_db = do_reindex || do_reindex_chainstate;" in startup_flags,
        "full_reindex_wipes_block_tree_and_chainstate":
            "options.wipe_block_tree_db = do_reindex;" in startup_flags
            and "options.wipe_chainstate_db = do_reindex || do_reindex_chainstate;" in startup_flags,
        "reindex_marks_block_files_for_rebuild":
            "pblocktree->WriteReindexing(true);" in complete_init,
        "randomx_seed_is_parent_chain_ancestor_derived":
            "pindexPrev->GetAncestor(nSeedHeight)" in seed_hash
            and "return pindexSeed->GetBlockHash();" in seed_hash,
    }

    missing = [name for name, ok in checks.items() if not ok]
    if missing:
        raise AssertionError("startup/reindex source contract mismatch: " + ", ".join(missing))

    evidence = {
        "schema": "wam-security-startup-reindex-static/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "wam_commit": wam_head,
            "wam_security_head": os.environ.get("SECURITY_TARGET_SHA") or git_head(repo),
        },
        "scope": {
            "static_source_only": True,
            "database_mutation": False,
            "persisted_metadata_tampering": False,
            "public_nodes": False,
            "real_peers": False,
        },
        "source_paths": [
            "scripts/patch_upstream.py",
            "src/node/blockstorage.cpp",
            "src/validation.cpp",
            "src/node/chainstate.cpp",
            "src/init.cpp",
            "src/wam/crypto/randomx_hash.cpp",
        ],
        "checks": checks,
        "observations": {
            "normal_restart": (
                "Block-index entries restore persisted status/height/header fields; "
                "LoadChainTip selects the CoinsTip best block."
            ),
            "reindex_chainstate": (
                "Chainstate is rebuilt while the existing block-index database is retained."
            ),
            "full_reindex": (
                "Block tree and chainstate are wiped and rebuilt from local blk*.dat files."
            ),
            "startup_randomx_contextual_recheck": (
                "The ordinary startup VerifyDB path does not call ContextualCheckBlockHeader; "
                "this is recorded as a trust-boundary coverage gap, not as an exploit finding."
            ),
        },
        "classification": "NORMAL_PATH_REGRESSION_TARGET_WITH_PERSISTED_STATE_COVERAGE_GAP",
        "result": "PASS",
    }

    out = args.out if args.out.is_absolute() else repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("startup/reindex static contract: PASS")
    print(f"evidence: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
