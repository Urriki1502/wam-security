import unittest

from wam_security.consensus.compact import compact_to_target, target_to_compact
from wam_security.consensus.dgw import DgwBlock, DgwParams, dark_gravity_wave


POW_LIMIT = int("00000fffff000000000000000000000000000000000000000000000000000000", 16)
PARAMS = DgwParams(pow_limit=POW_LIMIT)


def history(bits: int, spacing: int = 120, height: int = 1000) -> list[DgwBlock]:
    newest_time = 2_000_000
    return [
        DgwBlock(height - i, newest_time - i * spacing, bits)
        for i in range(24)
    ]


class DgwTests(unittest.TestCase):
    def test_bootstrap_window_uses_pow_limit(self):
        for h in (0, 1, 23):
            blocks = [DgwBlock(h, 1000, 0x1E0FFFF0)]
            self.assertEqual(dark_gravity_wave(blocks, PARAMS), target_to_compact(POW_LIMIT))

    def test_constant_target_and_ideal_spacing_is_near_stable(self):
        bits = 0x1E07FFF0
        out = dark_gravity_wave(history(bits), PARAMS)
        target_in = compact_to_target(bits)[0]
        target_out = compact_to_target(out)[0]
        # WAM defines expected span as 24*spacing but timestamps cover 23 gaps.
        expected = target_in * (23 * 120) // (24 * 120)
        self.assertLessEqual(abs(target_out - expected), max(1, expected // 1_000_000))

    def test_fast_chain_clamps_to_one_third(self):
        bits = 0x1E07FFF0
        out = dark_gravity_wave(history(bits, spacing=1), PARAMS)
        got = compact_to_target(out)[0]
        base = compact_to_target(bits)[0]
        expected = base // 3
        self.assertLessEqual(abs(got - expected), max(1, expected // 1_000_000))

    def test_slow_chain_clamps_to_three_x(self):
        bits = 0x1E03FFF0
        out = dark_gravity_wave(history(bits, spacing=10_000), PARAMS)
        got = compact_to_target(out)[0]
        base = compact_to_target(bits)[0]
        expected = min(base * 3, POW_LIMIT)
        self.assertLessEqual(abs(got - expected), max(1, expected // 1_000_000))

    def test_pow_limit_caps_easier_result(self):
        bits = target_to_compact(POW_LIMIT)
        self.assertEqual(dark_gravity_wave(history(bits, 10_000), PARAMS), bits)


if __name__ == "__main__":
    unittest.main()
