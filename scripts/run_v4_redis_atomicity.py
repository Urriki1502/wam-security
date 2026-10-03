#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

def redis(port: int, *args: str, check: bool = True) -> str:
    p = subprocess.run(
        ["redis-cli", "-p", str(port), "--raw", *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out = p.stdout.strip()
    if check and p.returncode != 0:
        raise RuntimeError(out)
    return out

def eval_script(port: int, script: Path, keys: list[str], args: list[str]) -> str:
    cmd = ["redis-cli", "-p", str(port), "--raw", "--eval", str(script), *keys, ",", *args]
    p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.strip()

def hget(port: int, key: str, field: str) -> int:
    return int(redis(port, "HGET", key, field) or "0")

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=6397)
    p.add_argument("--script", type=Path, default=Path("reference/redis/commit_payment.lua"))
    args = p.parse_args()

    prefix = "wam-v4-ci"
    balances, paid = f"{prefix}:balances", f"{prefix}:paid"
    active, payments = f"{prefix}:payment:active", f"{prefix}:payments"
    redis(args.port, "DEL", balances, paid, active, payments)
    redis(args.port, "HSET", balances, "alice", "500", "bob", "300")

    intent = {"intent_id": "intent-1", "state": "seen", "txid": "txid-1", "raw_tx": "deadbeef"}
    redis(args.port, "SET", active, json.dumps(intent, separators=(",", ":")))
    journal = json.dumps({"txid": "txid-1", "total": 300}, separators=(",", ":"))
    out = eval_script(
        args.port, args.script,
        [balances, paid, active, payments],
        ["intent-1", journal, "alice", "100", "bob", "200"],
    )
    if out != "COMMITTED":
        raise AssertionError(f"atomic commit failed: {out}")

    assert hget(args.port, balances, "alice") == 400
    assert hget(args.port, balances, "bob") == 100
    assert hget(args.port, paid, "alice") == 100
    assert hget(args.port, paid, "bob") == 200
    assert redis(args.port, "EXISTS", active) == "0"
    assert redis(args.port, "LLEN", payments) == "1"

    replay = eval_script(
        args.port, args.script,
        [balances, paid, active, payments],
        ["intent-1", journal, "alice", "100", "bob", "200"],
    )
    if "no active intent" not in replay:
        raise AssertionError(f"replay was not rejected: {replay}")
    assert hget(args.port, balances, "alice") == 400
    assert hget(args.port, paid, "alice") == 100

    bad = {"intent_id": "intent-2", "state": "seen", "txid": "txid-2", "raw_tx": "cafebabe"}
    redis(args.port, "SET", active, json.dumps(bad, separators=(",", ":")))
    before = (
        hget(args.port, balances, "alice"),
        hget(args.port, balances, "bob"),
        hget(args.port, paid, "alice"),
        hget(args.port, paid, "bob"),
        redis(args.port, "LLEN", payments),
    )
    rejected = eval_script(
        args.port, args.script,
        [balances, paid, active, payments],
        ["intent-2", "{}", "alice", "999999", "bob", "1"],
    )
    if "insufficient balance" not in rejected:
        raise AssertionError(f"bad commit was not rejected: {rejected}")
    after = (
        hget(args.port, balances, "alice"),
        hget(args.port, balances, "bob"),
        hget(args.port, paid, "alice"),
        hget(args.port, paid, "bob"),
        redis(args.port, "LLEN", payments),
    )
    if before != after:
        raise AssertionError(f"Redis script partially mutated accounting: {before} -> {after}")
    if redis(args.port, "EXISTS", active) != "1":
        raise AssertionError("failed commit deleted recovery intent")

    print("V4 Redis atomic accounting: PASS (commit, replay rejection, failed-precondition rollback)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
