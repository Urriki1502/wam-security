#!/usr/bin/env python3
from __future__ import annotations

import argparse

from wam_security.adversarial.faults import exercise_crash_matrix
from wam_security.adversarial.fuzz import run_adversarial_fuzz


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", required=True, type=lambda x: int(x, 0))
    p.add_argument("--cases", type=int, default=2000)
    args = p.parse_args()

    crash_scenarios = exercise_crash_matrix()
    stats = run_adversarial_fuzz(args.seed, args.cases)
    print(f"crash-matrix: PASS ({crash_scenarios} scenarios)")
    print(f"fuzz: PASS {stats.to_json()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
