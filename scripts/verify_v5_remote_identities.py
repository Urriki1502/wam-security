#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from wam_security.supplychain.identities import load_identity_lock, locked_identities


def resolve(repository: str, ref: str) -> str:
    peeled = ref + "^{}"
    proc = subprocess.run(
        ["git", "ls-remote", repository, ref, peeled],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-remote failed for {repository} {ref}: {proc.stdout.strip()}")
    found: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            found[parts[1]] = parts[0]
    value = found.get(peeled) or found.get(ref)
    if not value:
        raise RuntimeError(f"remote ref not found: {repository} {ref}")
    return value.lower()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--lock", type=Path, default=Path("supply-chain-lock.json"))
    args = p.parse_args()

    data = load_identity_lock(args.lock)
    failures = 0
    for item in locked_identities(data):
        got = resolve(item.repository, item.ref)
        expected = item.commit.lower()
        if got != expected:
            failures += 1
            print(f"DRIFT {item.name}: {item.ref} -> {got}, expected {expected}")
        else:
            print(f"PASS  {item.name}: {item.ref} -> {got}")
    if failures:
        print(f"{failures} reviewed remote identity lock(s) drifted")
        return 2
    print("V5 remote identity lock: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
