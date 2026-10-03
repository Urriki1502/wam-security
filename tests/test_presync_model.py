import unittest

from wam_security.model.presync import HeaderClaim, validated_work


class PresyncInvariantTests(unittest.TestCase):
    def test_unverified_claimed_work_cannot_count_as_security_work(self):
        headers = [HeaderClaim(claimed_work=10_000_000, pow_verified=False)]
        with self.assertRaises(ValueError):
            validated_work(headers, require_pow=True)

    def test_model_exposes_why_bypass_requires_separate_anti_dos_review(self):
        headers = [HeaderClaim(claimed_work=10_000_000, pow_verified=False)]
        self.assertEqual(validated_work(headers, require_pow=False), 10_000_000)


if __name__ == "__main__":
    unittest.main()
