#!/usr/bin/env python3
"""Isolated WAM startup/reindex regression probe.

The probe uses one temporary regtest datadir, disables peer networking, mines a
valid local RandomX chain, and verifies that clean restart, -reindex-chainstate,
and full -reindex reconstruct the same observable chain state.

It never edits database files or persisted metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any


def run(cmd: list[str], *, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
        timeout=timeout,
    )


def block_id(header_hex: str) -> str:
    raw = bytes.fromhex(header_hex)
    digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return digest[::-1].hex()


def invalid_difficulty_header(header_hex: str) -> tuple[str, str]:
    raw = bytearray.fromhex(header_hex)
    if len(raw) != 80:
        raise AssertionError(f"expected 80-byte header, got {len(raw)}")
    raw[72:76] = b"\x00\x00\x00\x00"
    mutated = raw.hex()
    return mutated, block_id(mutated)


def parse_json(cp: subprocess.CompletedProcess[str]) -> Any:
    return json.loads(cp.stdout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core-tree", type=Path, required=True)
    ap.add_argument("--wam-source", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    core = args.core_tree.resolve()
    wam_source = args.wam_source.resolve()
    wamd = core / "src/wamd"
    cli = core / "src/wam-cli"
    for p in (wamd, cli):
        if not p.exists():
            raise SystemExit(f"missing local executable: {p}")

    wam_commit = run(["git", "-C", str(wam_source), "rev-parse", "HEAD"]).stdout.strip()
    security_head = os.environ.get("SECURITY_TARGET_SHA")

    datadir = Path(tempfile.mkdtemp(prefix="wam-startup-reindex-"))
    rpc_user = "startupci"
    rpc_pass = "local-regtest-only"

    cli_base = [
        str(cli),
        "-regtest",
        f"-datadir={datadir}",
        f"-rpcuser={rpc_user}",
        f"-rpcpassword={rpc_pass}",
    ]

    daemon_base = [
        str(wamd),
        "-regtest",
        f"-datadir={datadir}",
        "-server=1",
        "-listen=0",
        "-dnsseed=0",
        "-fixedseeds=0",
        "-discover=0",
        "-connect=0",
        "-persistmempool=0",
        f"-rpcuser={rpc_user}",
        f"-rpcpassword={rpc_pass}",
        "-daemonwait",
    ]

    evidence: dict[str, Any] = {
        "schema": "wam-security-startup-reindex-native/v1",
        "target": {
            "wam_commit": wam_commit,
            "wam_security_head": security_head,
        },
        "scope": {
            "regtest_only": True,
            "temporary_datadir": True,
            "listen": False,
            "dnsseed": False,
            "fixedseeds": False,
            "discover": False,
            "automatic_connections": False,
            "database_mutation": False,
            "persisted_metadata_tampering": False,
            "public_nodes": False,
            "real_peers": False,
        },
        "states": {},
    }

    def cli_call(*args_: str, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
        return run(cli_base + list(args_), check=check, timeout=timeout)

    def start(extra: list[str] | None = None) -> None:
        cmd = daemon_base + (extra or [])
        cp = run(cmd, check=False, timeout=600)
        if cp.returncode != 0:
            raise RuntimeError(f"wamd startup failed ({cp.returncode}): {cp.stdout[-4000:]}")
        cli_call("-rpcwait", "getblockchaininfo", timeout=300)

    def stop() -> None:
        cli_call("stop", check=False, timeout=60)
        for _ in range(120):
            cp = cli_call("getblockchaininfo", check=False, timeout=5)
            if cp.returncode != 0:
                return
            time.sleep(0.25)
        raise RuntimeError("daemon did not stop")

    def wait_for_tip(expected_hash: str, expected_height: int) -> None:
        deadline = time.time() + 300
        last: dict[str, Any] | None = None
        while time.time() < deadline:
            cp = cli_call("getblockchaininfo", check=False, timeout=15)
            if cp.returncode == 0:
                last = json.loads(cp.stdout)
                if (
                    last.get("bestblockhash") == expected_hash
                    and last.get("blocks") == expected_height
                ):
                    return
            time.sleep(0.5)
        raise AssertionError(f"tip did not restore: last={last}")

    def snapshot() -> dict[str, Any]:
        chain = parse_json(cli_call("getblockchaininfo"))
        rx = parse_json(cli_call("getrandomxinfo"))
        seed_height = int(rx["seed_height"])
        seed_block = cli_call("getblockhash", str(seed_height)).stdout.strip()
        return {
            "blocks": chain["blocks"],
            "headers": chain["headers"],
            "bestblockhash": chain["bestblockhash"],
            "chainwork": chain["chainwork"],
            "randomx_height": rx["height"],
            "randomx_seed_height": seed_height,
            "randomx_seed_hash": rx["seed_hash"],
            "randomx_bootstrap": rx["bootstrap"],
            "randomx_epoch_blocks": rx["epoch_blocks"],
            "randomx_epoch_lag": rx["epoch_lag"],
            "seed_block_hash": seed_block,
            "seed_matches_chain_ancestor": rx["seed_hash"] == seed_block,
        }

    def assert_same_state(name: str, baseline: dict[str, Any], observed: dict[str, Any]) -> None:
        keys = [
            "blocks",
            "headers",
            "bestblockhash",
            "chainwork",
            "randomx_height",
            "randomx_seed_height",
            "randomx_seed_hash",
            "randomx_bootstrap",
            "randomx_epoch_blocks",
            "randomx_epoch_lag",
            "seed_block_hash",
            "seed_matches_chain_ancestor",
        ]
        mismatches = {
            k: {"expected": baseline[k], "observed": observed[k]}
            for k in keys
            if baseline[k] != observed[k]
        }
        if mismatches:
            raise AssertionError(f"{name} state mismatch: {mismatches}")

    def assert_rejected_header(header_hex: str, header_id: str) -> dict[str, Any]:
        submitted = cli_call("submitheader", header_hex, check=False)
        lookup = cli_call("getblockheader", header_id, check=False)
        if submitted.returncode == 0:
            raise AssertionError("previously invalid local header was accepted")
        if lookup.returncode == 0:
            raise AssertionError("rejected local header appeared in block index")
        return {
            "submit_returncode": submitted.returncode,
            "submit_message": submitted.stdout.strip()[-1000:],
            "block_index_lookup_returncode": lookup.returncode,
            "accepted": False,
            "present_in_block_index": False,
        }

    try:
        start()

        cli_call("createwallet", "startupci")
        address = cli_call("-rpcwallet=startupci", "getnewaddress").stdout.strip()
        mined = parse_json(cli_call("generatetoaddress", "70", address, timeout=300))
        if len(mined) != 70:
            raise AssertionError(f"expected 70 mined blocks, got {len(mined)}")

        baseline = snapshot()
        if baseline["blocks"] != 70:
            raise AssertionError(baseline)
        if not baseline["seed_matches_chain_ancestor"]:
            raise AssertionError("RandomX seed hash does not match chain-derived seed block")

        tip_header = cli_call("getblockheader", baseline["bestblockhash"], "false").stdout.strip()
        bad_header, bad_id = invalid_difficulty_header(tip_header)
        first_reject = assert_rejected_header(bad_header, bad_id)

        evidence["invalid_header"] = {
            "id": bad_id,
            "construction": "local valid header with nBits replaced by zero",
            "initial_rejection": first_reject,
        }
        evidence["states"]["baseline"] = baseline

        stop()
        start()
        wait_for_tip(baseline["bestblockhash"], baseline["blocks"])
        restart = snapshot()
        assert_same_state("clean_restart", baseline, restart)
        restart_reject = assert_rejected_header(bad_header, bad_id)
        evidence["states"]["clean_restart"] = restart
        evidence["invalid_header"]["after_clean_restart"] = restart_reject

        stop()
        start(["-reindex-chainstate=1"])
        wait_for_tip(baseline["bestblockhash"], baseline["blocks"])
        chainstate_reindex = snapshot()
        assert_same_state("reindex_chainstate", baseline, chainstate_reindex)
        chainstate_reject = assert_rejected_header(bad_header, bad_id)
        evidence["states"]["reindex_chainstate"] = chainstate_reindex
        evidence["invalid_header"]["after_reindex_chainstate"] = chainstate_reject

        stop()
        start(["-reindex=1"])
        wait_for_tip(baseline["bestblockhash"], baseline["blocks"])
        full_reindex = snapshot()
        assert_same_state("full_reindex", baseline, full_reindex)
        full_reject = assert_rejected_header(bad_header, bad_id)
        evidence["states"]["full_reindex"] = full_reindex
        evidence["invalid_header"]["after_full_reindex"] = full_reject

        evidence["invariants"] = {
            "clean_restart_preserves_active_tip": True,
            "clean_restart_preserves_chainwork": True,
            "clean_restart_preserves_randomx_seed_state": True,
            "reindex_chainstate_reconstructs_same_chain_state": True,
            "full_reindex_reconstructs_same_chain_state": True,
            "rejected_local_header_stays_rejected_after_restart": True,
            "rejected_local_header_stays_rejected_after_reindex_chainstate": True,
            "rejected_local_header_stays_rejected_after_full_reindex": True,
            "chain_derived_seed_identity_survives_all_normal_paths": True,
        }
        evidence["coverage_gap"] = {
            "persisted_state_tampering_tested": False,
            "reason": (
                "Scope intentionally excludes manual database mutation, forged block-index "
                "records, and persisted metadata tampering. Normal-path success therefore "
                "does not prove resistance to corrupted or forged persisted validation status."
            ),
        }
        evidence["classification"] = "NORMAL_RESTART_REINDEX_PATHS_PASS_PERSISTED_STATE_TAMPERING_UNTESTED"
        evidence["result"] = "PASS"

    except Exception as exc:
        evidence["result"] = "FAIL"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        try:
            stop()
        except Exception:
            pass
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(datadir, ignore_errors=True)

    print("isolated startup/restart/reindex regression: PASS")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
