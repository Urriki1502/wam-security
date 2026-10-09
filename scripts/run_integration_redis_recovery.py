#!/usr/bin/env python3
"""Validate the Redis atomicity/recovery assumption used by WAM payouts.

This is a loopback-only integration test. It does not contact public nodes,
wallets, pools, or third-party infrastructure.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

PATCH_COMMIT = "260bc468e5adffea7ce68d8f97fac3e27e4c50b2"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def resp(*parts: object) -> bytes:
    out = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        b = str(part).encode("utf-8")
        out.append(f"${len(b)}\r\n".encode())
        out.append(b + b"\r\n")
    return b"".join(out)


class RedisConn:
    def __init__(self, host: str, port: int, timeout: float = 2.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.fp = self.sock.makefile("rb")

    def close(self) -> None:
        try:
            self.fp.close()
        finally:
            self.sock.close()

    def send_raw(self, payload: bytes) -> None:
        self.sock.sendall(payload)

    def cmd(self, *parts: object):
        self.send_raw(resp(*parts))
        return self.read_reply()

    def read_reply(self):
        lead = self.fp.read(1)
        if not lead:
            raise ConnectionError("redis connection closed before reply")
        line = self.fp.readline()
        if not line.endswith(b"\r\n"):
            raise ConnectionError("truncated redis reply")
        body = line[:-2]
        if lead == b"+":
            return body.decode()
        if lead == b"-":
            raise RuntimeError(body.decode())
        if lead == b":":
            return int(body)
        if lead == b"$":
            n = int(body)
            if n == -1:
                return None
            data = self.fp.read(n)
            if self.fp.read(2) != b"\r\n":
                raise ConnectionError("truncated bulk reply")
            return data.decode()
        if lead == b"*":
            n = int(body)
            if n == -1:
                return None
            return [self.read_reply() for _ in range(n)]
        raise RuntimeError(f"unknown redis reply type: {lead!r}")


def with_conn(host: str, port: int, fn):
    c = RedisConn(host, port)
    try:
        return fn(c)
    finally:
        c.close()


def delete_case(host: str, port: int, prefix: str) -> None:
    keys = [
        f"{prefix}:balances", f"{prefix}:paid", f"{prefix}:payments",
        f"{prefix}:payment:inflight", f"{prefix}:payment:postponed",
    ]
    with_conn(host, port, lambda c: c.cmd("DEL", *keys))


def seed_case(host: str, port: int, prefix: str, amount: int) -> None:
    def seed(c: RedisConn):
        c.cmd("HSET", f"{prefix}:balances", "addr1", amount)
        c.cmd("SET", f"{prefix}:payment:inflight", json.dumps({
            "startedAt": 1, "total": amount, "payouts": {"addr1": amount}
        }, separators=(",", ":")))
    with_conn(host, port, seed)


def queue_accounting(c: RedisConn, prefix: str, amount: int, txid: str) -> None:
    if c.cmd("MULTI") != "OK":
        raise AssertionError("MULTI was not accepted")
    queued = [
        ("HINCRBY", f"{prefix}:balances", "addr1", -amount),
        ("HINCRBY", f"{prefix}:paid", "addr1", amount),
        ("LPUSH", f"{prefix}:payments", json.dumps({"txid": txid, "total": amount})),
        ("LTRIM", f"{prefix}:payments", 0, 999),
        ("DEL", f"{prefix}:payment:inflight"),
        ("DEL", f"{prefix}:payment:postponed"),
    ]
    for op in queued:
        if c.cmd(*op) != "QUEUED":
            raise AssertionError(f"redis did not queue {op[0]}")


def snapshot(host: str, port: int, prefix: str) -> dict:
    def read(c: RedisConn):
        return {
            "balance": c.cmd("HGET", f"{prefix}:balances", "addr1"),
            "paid": c.cmd("HGET", f"{prefix}:paid", "addr1"),
            "payments": c.cmd("LLEN", f"{prefix}:payments"),
            "inflight": c.cmd("GET", f"{prefix}:payment:inflight"),
        }
    return with_conn(host, port, read)


def expect_uncommitted(state: dict, amount: int) -> None:
    assert state["balance"] == str(amount), state
    assert state["paid"] is None, state
    assert state["payments"] == 0, state
    assert state["inflight"] is not None, state


def expect_committed(state: dict, amount: int) -> None:
    assert state["balance"] == "0", state
    assert state["paid"] == str(amount), state
    assert state["payments"] == 1, state
    assert state["inflight"] is None, state


def test_disconnect_before_exec(host: str, port: int, prefix: str, amount: int) -> None:
    delete_case(host, port, prefix)
    seed_case(host, port, prefix, amount)
    c = RedisConn(host, port)
    try:
        queue_accounting(c, prefix, amount, "tx-before")
        # Simulate a process/connection dying after every operation is queued,
        # but before EXEC reaches Redis. Redis must discard the transaction.
    finally:
        c.close()
    time.sleep(0.01)
    expect_uncommitted(snapshot(host, port, prefix), amount)


def test_disconnect_after_exec_without_reply(host: str, port: int, prefix: str, amount: int) -> None:
    delete_case(host, port, prefix)
    seed_case(host, port, prefix, amount)
    c = RedisConn(host, port)
    try:
        queue_accounting(c, prefix, amount, "tx-after")
        # Send EXEC completely, then stop reading before Redis can return the
        # result. From the caller's perspective the outcome is unknown; Redis
        # must nevertheless apply the queued accounting as one atomic unit.
        c.send_raw(resp("EXEC"))
        c.sock.shutdown(socket.SHUT_WR)
        time.sleep(0.005)
    finally:
        c.close()
    time.sleep(0.01)
    expect_committed(snapshot(host, port, prefix), amount)


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


def require_source_contract(wam_root: Path) -> dict:
    share = wam_root / "pool/lib/shareProcessor.js"
    if not share.is_file():
        raise SystemExit(f"missing WAM source file: {share}")
    text = share.read_text(encoding="utf-8")
    required = {
        "uses_multi": "const pipe = this.redis.multi();",
        "clears_inflight_inside_transaction": "pipe.del(this.k('payment:inflight'));",
        "executes_transaction": "await pipe.exec();",
    }
    result = {name: token in text for name, token in required.items()}
    missing = [name for name, ok in result.items() if not ok]
    if missing:
        raise AssertionError("WAM source contract missing: " + ", ".join(missing))
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path, help="checkout of wamcoin-core-dev/wam-coin")
    ap.add_argument("--expected-commit", default=PATCH_COMMIT)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--cases", type=int, default=100)
    ap.add_argument("--out", type=Path,
                    default=Path("security-reports/integration-redis-recovery.json"))
    args = ap.parse_args()

    if args.host not in LOOPBACK:
        raise SystemExit("refusing non-loopback Redis target; this harness is local-only")
    if args.cases < 1 or args.cases > 5000:
        raise SystemExit("--cases must be between 1 and 5000")

    wam_root = args.wam_root.resolve()
    head = git_head(wam_root)
    if head != args.expected_commit:
        raise SystemExit(
            f"WAM checkout is {head or 'not a git checkout'}, expected {args.expected_commit}"
        )
    source_contract = require_source_contract(wam_root)
    ping = with_conn(args.host, args.port, lambda c: c.cmd("PING"))
    if ping != "PONG":
        raise SystemExit(f"unexpected Redis PING reply: {ping!r}")

    failures = []
    started = time.time()
    for i in range(args.cases):
        amount = 100_000_000 + i
        try:
            test_disconnect_before_exec(args.host, args.port, f"wamsec:pre:{i}", amount)
            test_disconnect_after_exec_without_reply(args.host, args.port, f"wamsec:post:{i}", amount)
        except Exception as exc:
            failures.append({"case": i, "error": repr(exc)})
            break

    completed = args.cases if not failures else failures[0]["case"]
    evidence = {
        "schema": "wam-security-integration-redis-recovery/v2",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "expected_commit": args.expected_commit,
            "observed_commit": head,
        },
        "redis": {"host": args.host, "port": args.port, "loopback_only": True},
        "source_contract": source_contract,
        "cases_requested": args.cases,
        "cases_completed": completed,
        "scenarios_per_case": 2,
        "invariants": {
            "disconnect_before_exec_applies_none": not failures,
            "disconnect_after_exec_before_reply_applies_all": not failures,
            "inflight_survives_uncommitted_accounting": not failures,
            "inflight_clears_with_committed_accounting": not failures,
            "no_partial_accounting_state_observed": not failures,
        },
        "failures": failures,
        "duration_ms": int((time.time() - started) * 1000),
        "result": "PASS" if not failures else "FAIL",
    }

    out = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": evidence["result"],
        "cases": evidence["cases_completed"],
        "scenarios": evidence["cases_completed"] * 2,
        "evidence": str(out),
    }, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
