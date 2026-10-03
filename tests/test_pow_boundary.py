import unittest

from wam_security.consensus.compact import target_to_compact
from wam_security.consensus.dgw import check_pow_hash


POW_LIMIT = int("00000fffff000000000000000000000000000000000000000000000000000000", 16)


class ProofOfWorkBoundaryTests(unittest.TestCase):
    def test_hash_equal_to_target_is_valid(self):
        bits = 0x1E0FFFF0
        from wam_security.consensus.compact import compact_to_target
        target = compact_to_target(bits)[0]
        self.assertTrue(check_pow_hash(target, bits, POW_LIMIT))
        self.assertTrue(check_pow_hash(target - 1, bits, POW_LIMIT))
        self.assertFalse(check_pow_hash(target + 1, bits, POW_LIMIT))

    def test_invalid_compact_targets_fail_closed(self):
        self.assertFalse(check_pow_hash(0, 0, POW_LIMIT))
        self.assertFalse(check_pow_hash(0, 0x1D80FFFF, POW_LIMIT))
        self.assertFalse(check_pow_hash(0, 0x2300FFFF, POW_LIMIT))

    def test_target_above_pow_limit_is_rejected(self):
        too_easy = target_to_compact(POW_LIMIT << 8)
        self.assertFalse(check_pow_hash(0, too_easy, POW_LIMIT))


if __name__ == "__main__":
    unittest.main()
