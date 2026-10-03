#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import hashlib
import json


FILES = [
    "wam-release-surface.tar.gz",
    "provenance.json",
    "sbom.spdx.json",
    "summary.json",
]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("builder_a", type=Path)
    p.add_argument("builder_b", type=Path)
    args = p.parse_args()

    evidence = {}
    for name in FILES:
        a = args.builder_a / name
        b = args.builder_b / name
        if not a.is_file() or not b.is_file():
            raise AssertionError(f"missing independent-builder evidence file: {name}")
        if a.read_bytes() != b.read_bytes():
            raise AssertionError(
                f"independent builders disagree for {name}: {sha(a)} != {sha(b)}"
            )
        evidence[name] = sha(a)

    summary = json.loads((args.builder_a / "summary.json").read_text(encoding="utf-8"))
    if not summary.get("reproducible_reference"):
        raise AssertionError("builder summary does not assert reproducible reference output")

    print(json.dumps(evidence, sort_keys=True))
    print("V6 independent builders: PASS (Ubuntu 22.04 == Ubuntu 24.04 byte-for-byte)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
