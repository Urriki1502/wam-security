import unittest

from wam_security.consensus.presync import (
    SyntheticHeader,
    contextual_randomx_accepts,
    model_presync,
)


class RandomXPresyncTests(unittest.TestCase):
    def test_unverified_claimed_work_must_not_reach_threshold(self):
        headers = [SyntheticHeader(claimed_work=25, pow_valid=False) for _ in range(4)]

        current_shape = model_presync(
            headers, threshold=100, require_pow_evidence=False
        )
        required_shape = model_presync(
            headers, threshold=100, require_pow_evidence=True
        )

        self.assertTrue(current_shape.reached_threshold)
        self.assertEqual(current_shape.credited_work, 100)
        self.assertEqual(current_shape.verified_work, 0)
        self.assertEqual(current_shape.invalid_headers_credited, 4)

        self.assertFalse(required_shape.reached_threshold)
        self.assertEqual(required_shape.credited_work, 0)
        self.assertEqual(required_shape.invalid_headers_credited, 0)

    def test_mixed_batch_threshold_depends_only_on_verified_work(self):
        headers = [
            SyntheticHeader(claimed_work=40, pow_valid=True),
            SyntheticHeader(claimed_work=70, pow_valid=False),
        ]

        current_shape = model_presync(
            headers, threshold=100, require_pow_evidence=False
        )
        required_shape = model_presync(
            headers, threshold=100, require_pow_evidence=True
        )

        self.assertTrue(current_shape.reached_threshold)
        self.assertEqual(current_shape.credited_work, 110)
        self.assertEqual(current_shape.verified_work, 40)

        self.assertFalse(required_shape.reached_threshold)
        self.assertEqual(required_shape.credited_work, 40)

    def test_later_contextual_validation_still_rejects_invalid_pow(self):
        bad = SyntheticHeader(claimed_work=500, pow_valid=False)
        good = SyntheticHeader(claimed_work=500, pow_valid=True)

        self.assertFalse(contextual_randomx_accepts(bad))
        self.assertTrue(contextual_randomx_accepts(good))

    def test_validation_model_rejects_nonsensical_work_values(self):
        with self.assertRaises(ValueError):
            SyntheticHeader(claimed_work=0, pow_valid=True)
        with self.assertRaises(ValueError):
            model_presync([], threshold=0, require_pow_evidence=True)


if __name__ == "__main__":
    unittest.main()
