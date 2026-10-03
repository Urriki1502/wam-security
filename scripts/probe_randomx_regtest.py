#!/usr/bin/env python3
"""Isolated regtest probe for WAM RandomX header acceptance invariants.

The probe launches only a local regtest daemon with peer networking disabled.
It verifies an invalid RandomX header is rejected even though submitheader uses
min_pow_checked=true, then exercises the first RandomX epoch/lag transition.
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


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
        timeout=180,
    )


def block_id(header_hex: str) -> str:
    raw = bytes.fromhex(header_hex)
    digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    return digest[::-1].hex()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core-tree", type=Path, required=True)
    ap.add_argument("--helper", type=Path, required=True)
    ap.add_argument("--wam-source", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    core = args.core_tree.resolve()
    helper = args.helper.resolve()
    wam_source = args.wam_source.resolve()
    wamd = core / "src/wamd"
    cli = core / "src/wam-cli"

    for p in (wamd, cli, helper):
        if not p.exists():
            raise SystemExit(f"missing required local executable: {p}")

    wam_commit = run(["git", "-C", str(wam_source), "rev-parse", "HEAD"]).stdout.strip()
    security_head = os.environ.get("SECURITY_TARGET_SHA")

    datadir = Path(tempfile.mkdtemp(prefix="wam-randomx-regtest-"))
    rpc_user = "randomxci"
    rpc_pass = "local-regtest-only"

    base = [
        str(cli),
        "-regtest",
        f"-datadir={datadir}",
        f"-rpcuser={rpc_user}",
        f"-rpcpassword={rpc_pass}",
    ]

    daemon_cmd = [
        str(wamd),
        "-regtest",
        f"-datadir={datadir}",
        "-server=1",
        "-listen=0",
        "-dnsseed=0",
        "-discover=0",
        "-connect=0",
        f"-rpcuser={rpc_user}",
        f"-rpcpassword={rpc_pass}",
        "-daemonwait",
    ]

    evidence: dict[str, object] = {
        "schema": "wam-security-randomx-native-regtest/v1",
        "scope": {
            "regtest_only": True,
            "listen": False,
            "dnsseed": False,
            "discover": False,
            "automatic_connections": False,
            "public_nodes": False,
        },
        "wam_commit": wam_commit,
        "wam_security_head": security_head,
    }

    try:
        run(daemon_cmd)
        run(base + ["-rpcwait", "getblockchaininfo"])

        wallet = "randomxci"
        run(base + ["createwallet", wallet])
        address = run(base + [f"-rpcwallet={wallet}", "getnewaddress"]).stdout.strip()

        info0 = json.loads(run(base + ["getrandomxinfo"]).stdout)
        assert info0["height"] == 0, info0
        assert info0["epoch_blocks"] == 64, info0
        assert info0["epoch_lag"] == 4, info0
        assert info0["seed_height"] == 0, info0
        assert info0["bootstrap"] is True, info0

        mined1 = json.loads(run(base + ["generatetoaddress", "1", address]).stdout)
        assert len(mined1) == 1
        h1 = mined1[0]
        header1 = run(base + ["getblockheader", h1, "false"]).stdout.strip()

        probe = run([str(helper), info0["seed_hash"], header1]).stdout
        fields = {}
        for line in probe.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip()

        bad_header = fields["header"]
        bad_nonce = int(fields["nonce"])
        bad_id = block_id(bad_header)

        rejected = run(base + ["submitheader", bad_header], check=False)
        reject_text = rejected.stdout.strip()
        assert rejected.returncode != 0, "locally generated invalid RandomX header was accepted"
        assert (
            "high-hash" in reject_text
            or "RandomX proof of work failed" in reject_text
        ), reject_text

        lookup = run(base + ["getblockheader", bad_id], check=False)
        assert lookup.returncode != 0, "rejected RandomX header entered the block index"

        # Height is already 1. Reach 66, where the candidate for height 67 is
        # still in the bootstrap epoch, then cross to height 67 so the next
        # candidate (68) uses block 64 as its RandomX seed.
        run(base + ["generatetoaddress", "65", address])
        info66 = json.loads(run(base + ["getrandomxinfo"]).stdout)
        assert info66["height"] == 66, info66
        assert info66["seed_height"] == 0, info66
        assert info66["bootstrap"] is True, info66

        run(base + ["generatetoaddress", "1", address])
        info67 = json.loads(run(base + ["getrandomxinfo"]).stdout)
        h64 = run(base + ["getblockhash", "64"]).stdout.strip()
        assert info67["height"] == 67, info67
        assert info67["seed_height"] == 64, info67
        assert info67["seed_hash"] == h64, (info67["seed_hash"], h64)
        assert info67["bootstrap"] is False, info67

        evidence.update({
            "result": "PASS",
            "invalid_pow_acceptance": {
                "submitheader_min_pow_checked_path": True,
                "rejected": True,
                "reject_reason": reject_text[-1000:],
                "entered_block_index": False,
                "fixture_nonce": bad_nonce,
                "fixture_block_id": bad_id,
            },
            "epoch_transition": {
                "height_66_seed_height": info66["seed_height"],
                "height_67_next_seed_height": info67["seed_height"],
                "expected_seed_block_64": h64,
                "observed_seed_hash": info67["seed_hash"],
                "pass": True,
            },
            "invariants": {
                "invalid_randomx_pow_never_enters_accepted_block_index": True,
                "min_pow_checked_true_does_not_skip_contextual_randomx": True,
                "regtest_epoch_lag_boundary_uses_chain_derived_seed": True,
            },
        })
    except Exception as exc:
        evidence.update({
            "result": "FAIL",
            "error": f"{type(exc).__name__}: {exc}",
        })
        raise
    finally:
        stop = run(base + ["stop"], check=False)
        _ = stop
        time.sleep(1)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(datadir, ignore_errors=True)

    print("isolated RandomX regtest acceptance + epoch transition: PASS")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
