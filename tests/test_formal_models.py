import unittest

from wam_security.formal.checker import explore, expect_counterexample
from wam_security.formal import payout, release


class FormalModelTests(unittest.TestCase):
    def test_safe_payout_model_closes(self):
        result = explore(
            model="payout",
            initial=payout.initial(),
            successors=payout.successors,
            invariants=payout.invariants(),
        )
        self.assertGreaterEqual(result.states, 6)
        self.assertGreater(result.transitions, result.states)

    def test_safe_release_model_closes(self):
        result = explore(
            model="release",
            initial=release.initial(),
            successors=release.successors,
            invariants=release.invariants(),
        )
        self.assertGreaterEqual(result.states, 10)

    def test_payout_mutants_are_detected(self):
        a = expect_counterexample(
            model="commit-unknown",
            initial=payout.initial(),
            successors=payout.mutant_commit_unknown,
            invariants=payout.invariants(),
            expected_invariant="CommitOnlyAfterSeen",
        )
        b = expect_counterexample(
            model="second-identity",
            initial=payout.initial(),
            successors=payout.mutant_second_identity,
            invariants=payout.invariants(),
            expected_invariant="AtMostOneIdentity",
        )
        self.assertIn("MUTANT-commit-unknown", a.path)
        self.assertIn("MUTANT-new-identity-on-retry", b.path)

    def test_release_mutants_are_detected(self):
        a = expect_counterexample(
            model="one-review",
            initial=release.initial(),
            successors=release.mutant_one_review_publish,
            invariants=release.invariants(),
            expected_invariant="PublishRequiresTwoReviews",
        )
        b = expect_counterexample(
            model="no-provenance",
            initial=release.initial(),
            successors=release.mutant_publish_without_provenance,
            invariants=release.invariants(),
            expected_invariant="ApprovalRequiresEvidence",
        )
        self.assertIn("MUTANT-publish-one-review", a.path)
        self.assertIn("MUTANT-publish-no-provenance", b.path)


if __name__ == "__main__":
    unittest.main()
