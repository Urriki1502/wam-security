#!/usr/bin/env python3
from __future__ import annotations

import json

from wam_security.formal.checker import explore, expect_counterexample
from wam_security.formal import payout, release


def main() -> int:
    payout_result = explore(
        model="payout",
        initial=payout.initial(),
        successors=payout.successors,
        invariants=payout.invariants(),
    )
    release_result = explore(
        model="release",
        initial=release.initial(),
        successors=release.successors,
        invariants=release.invariants(),
    )

    counterexamples = [
        expect_counterexample(
            model="payout-commit-unknown-mutant",
            initial=payout.initial(),
            successors=payout.mutant_commit_unknown,
            invariants=payout.invariants(),
            expected_invariant="CommitOnlyAfterSeen",
        ),
        expect_counterexample(
            model="payout-second-identity-mutant",
            initial=payout.initial(),
            successors=payout.mutant_second_identity,
            invariants=payout.invariants(),
            expected_invariant="AtMostOneIdentity",
        ),
        expect_counterexample(
            model="release-one-review-mutant",
            initial=release.initial(),
            successors=release.mutant_one_review_publish,
            invariants=release.invariants(),
            expected_invariant="PublishRequiresTwoReviews",
        ),
        expect_counterexample(
            model="release-no-provenance-mutant",
            initial=release.initial(),
            successors=release.mutant_publish_without_provenance,
            invariants=release.invariants(),
            expected_invariant="ApprovalRequiresEvidence",
        ),
    ]

    summary = {
        "payout": payout_result.__dict__,
        "release": release_result.__dict__,
        "mutants_caught": [
            {
                "invariant": c.invariant,
                "path": list(c.path),
            }
            for c in counterexamples
        ],
    }
    print(json.dumps(summary, sort_keys=True))
    print("V6 exhaustive formal models: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
