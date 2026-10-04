#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from wam_security.formal.checker import expect_counterexample
from wam_security.formal import payout, release


def formal_case(name: str, expected: str) -> None:
    cases = {
        "payout-commit-unknown": (
            payout.initial(),
            payout.mutant_commit_unknown,
            payout.invariants(),
        ),
        "payout-second-identity": (
            payout.initial(),
            payout.mutant_second_identity,
            payout.invariants(),
        ),
        "release-one-review": (
            release.initial(),
            release.mutant_one_review_publish,
            release.invariants(),
        ),
        "release-no-provenance": (
            release.initial(),
            release.mutant_publish_without_provenance,
            release.invariants(),
        ),
    }
    if name not in cases:
        raise AssertionError(f"unknown formal mutant: {name}")
    init, successors, invariants = cases[name]
    violation = expect_counterexample(
        model=name,
        initial=init,
        successors=successors,
        invariants=invariants,
        expected_invariant=expected,
    )
    print(f"PASS formal mutant {name}: {violation.invariant}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("wam_checkout", type=Path)
    p.add_argument("--corpus", type=Path, default=Path("redteam/corpus.json"))
    p.add_argument("--report", type=Path, default=Path("security-reports/security-report.json"))
    args = p.parse_args()

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    finding_ids = {f["finding_id"] for f in report["findings"]}

    passed = 0
    for case in corpus:
        kind = case["check"]
        if kind == "upstream-file":
            path = args.wam_checkout / case["path"]
            if not path.is_file():
                raise AssertionError(f"{case['id']}: missing regression file {case['path']}")
            print(f"PASS {case['id']}: {case['path']}")
        elif kind == "formal-mutant":
            formal_case(case["mutant"], case["expected_invariant"])
            print(f"PASS {case['id']}")
        elif kind == "audit-finding":
            fid = case["finding_id"]
            if fid not in finding_ids:
                raise AssertionError(f"{case['id']}: expected finding missing: {fid}")
            print(f"PASS {case['id']}: {fid}")
        elif kind == "audit-absence":
            fid = case["finding_id"]
            if fid in finding_ids:
                raise AssertionError(f"{case['id']}: fixed finding regressed: {fid}")
            print(f"PASS {case['id']}: {fid} remains absent")
        else:
            raise AssertionError(f"{case['id']}: unknown check type {kind}")
        passed += 1

    print(f"V6 red-team regression corpus: PASS ({passed}/{len(corpus)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
