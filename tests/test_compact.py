import unittest

from wam_security.consensus.compact import compact_to_target, target_to_compact


class CompactTargetTests(unittest.TestCase):
    def test_roundtrip_known_wam_targets(self):
        for bits in (0x1E0FFFF0, 0x1E0FFFFF, 0x1D00FFFF, 0x207FFFFF):
            target, negative, overflow = compact_to_target(bits)
            self.assertFalse(negative)
            self.assertFalse(overflow)
            self.assertEqual(target_to_compact(target), bits)

    def test_zero(self):
        self.assertEqual(compact_to_target(0)[0], 0)
        self.assertEqual(target_to_compact(0), 0)

    def test_negative_and_overflow_flags(self):
        _, negative, _ = compact_to_target(0x1D80FFFF)
        self.assertTrue(negative)
        _, _, overflow = compact_to_target(0x2300FFFF)
        self.assertTrue(overflow)


if __name__ == "__main__":
    unittest.main()
