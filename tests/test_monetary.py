import unittest

from wam_security.constants import COIN, MAX_MONEY
from wam_security.model.monetary import (
    block_subsidy,
    lifetime_treasury,
    miner_subsidy,
    total_supply_at_height,
    treasury_amount,
)


class MonetaryModelTests(unittest.TestCase):
    def test_consensus_boundaries(self):
        self.assertEqual(block_subsidy(-1), 0)
        self.assertEqual(block_subsidy(0), 2_000_000 * COIN)
        self.assertEqual(block_subsidy(1), 50 * COIN)
        self.assertEqual(block_subsidy(200_000), 50 * COIN)
        self.assertEqual(block_subsidy(200_001), 25 * COIN)
        self.assertEqual(block_subsidy(400_000), 25 * COIN)
        self.assertEqual(block_subsidy(400_001), 1_250_000_000)
        self.assertEqual(block_subsidy(6_600_000), 1)
        self.assertEqual(block_subsidy(6_600_001), 0)

    def test_treasury_sunset(self):
        self.assertEqual(treasury_amount(block_subsidy(1), 1), 250_000_000)
        self.assertEqual(treasury_amount(block_subsidy(200_001), 200_001), 125_000_000)
        self.assertEqual(treasury_amount(block_subsidy(400_000), 400_000), 125_000_000)
        self.assertEqual(treasury_amount(block_subsidy(400_001), 400_001), 0)
        self.assertEqual(lifetime_treasury(), 750_000 * COIN)

    def test_treasury_is_carved_out_not_added(self):
        for h in (1, 199_999, 200_000, 200_001, 400_000, 400_001, 6_600_000):
            subsidy = block_subsidy(h)
            self.assertEqual(miner_subsidy(h) + treasury_amount(subsidy, h), subsidy)

    def test_supply_is_monotone_and_bounded_at_all_boundaries(self):
        points = [0, 1, 199_999, 200_000, 200_001, 399_999, 400_000, 400_001]
        points += [e * 200_000 + delta for e in range(1, 34) for delta in (-1, 0, 1)]
        points = sorted({p for p in points if p >= 0})
        last = 0
        for h in points:
            supply = total_supply_at_height(h)
            self.assertGreaterEqual(supply, last)
            self.assertLessEqual(supply, MAX_MONEY)
            last = supply
        self.assertLess(total_supply_at_height(6_600_000), MAX_MONEY)
        self.assertEqual(total_supply_at_height(6_600_001), total_supply_at_height(6_600_000))


if __name__ == "__main__":
    unittest.main()
