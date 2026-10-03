import unittest

from wam_security.consensus.randomx import (
    MAINNET,
    REGTEST,
    TESTNET,
    reorg_changes_seed,
    seed_hash_for_candidate,
    seed_height,
)


class RandomXConsensusTests(unittest.TestCase):
    def test_profile_boundaries(self):
        for profile in (MAINNET, TESTNET, REGTEST):
            e, lag = profile.epoch_blocks, profile.epoch_lag
            cases = {
                0: 0,
                lag: 0,
                lag + 1: 0,
                e + lag - 1: 0,
                e + lag: e,
                e + lag + 1: e,
                2 * e + lag: 2 * e,
            }
            for height, expected in cases.items():
                self.assertEqual(seed_height(height, profile), expected, (profile, height))

    def test_seed_hash_falls_back_if_ancestor_is_missing(self):
        h = MAINNET.epoch_blocks + MAINNET.epoch_lag
        self.assertEqual(seed_hash_for_candidate(h, {}, MAINNET), "bootstrap")
        self.assertEqual(
            seed_hash_for_candidate(h, {MAINNET.epoch_blocks: "seed-block"}, MAINNET),
            "seed-block",
        )

    def test_reorg_boundary_is_exact(self):
        p = REGTEST
        candidate = p.epoch_blocks + p.epoch_lag
        parent = candidate - 1
        sh = seed_height(candidate, p)
        stable_depth = parent - sh
        self.assertFalse(reorg_changes_seed(candidate, parent, stable_depth, p))
        self.assertTrue(reorg_changes_seed(candidate, parent, stable_depth + 1, p))

    def test_competing_branches_use_branch_specific_seed_at_rotation(self):
        p = REGTEST
        candidate = p.epoch_blocks + p.epoch_lag
        sh = seed_height(candidate, p)
        self.assertEqual(sh, p.epoch_blocks)

        branch_a = {sh: "seed-A"}
        branch_b = {sh: "seed-B"}

        self.assertEqual(seed_hash_for_candidate(candidate, branch_a, p), "seed-A")
        self.assertEqual(seed_hash_for_candidate(candidate, branch_b, p), "seed-B")
        self.assertNotEqual(
            seed_hash_for_candidate(candidate, branch_a, p),
            seed_hash_for_candidate(candidate, branch_b, p),
        )

    def test_reorg_that_does_not_touch_seed_keeps_seed_identity(self):
        p = REGTEST
        candidate = p.epoch_blocks + p.epoch_lag + 1
        sh = seed_height(candidate, p)
        parent = candidate - 1

        self.assertEqual(sh, p.epoch_blocks)
        self.assertFalse(reorg_changes_seed(candidate, parent, 1, p))
        self.assertTrue(reorg_changes_seed(candidate, parent, parent - sh + 1, p))


if __name__ == "__main__":
    unittest.main()
