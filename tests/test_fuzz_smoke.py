import unittest

from wam_security.adversarial.fuzz import run_adversarial_fuzz


class DeterministicFuzzTests(unittest.TestCase):
    def test_smoke_seeds_are_reproducible_and_bounded(self):
        for seed in (0x57414D, 0x352, 0xC0FFEE):
            a = run_adversarial_fuzz(seed, cases=300)
            b = run_adversarial_fuzz(seed, cases=300)
            self.assertEqual(a, b)
            self.assertEqual(a.cases, a.accepted + a.rejected)
            self.assertLessEqual(a.max_work_units, 16_384)


if __name__ == "__main__":
    unittest.main()
