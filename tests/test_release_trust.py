import unittest

from wam_security.release_trust import (
    normalize_fingerprint,
    security_fingerprint,
    verifier_fingerprint,
)


class ReleaseTrustTests(unittest.TestCase):
    def test_fingerprint_normalization_and_source_parsing(self):
        spaced = "4BD4 A8D3 AFD4 3F5C BCB5  00E2 3798 462F E00A DBA4"
        expected = "4BD4A8D3AFD43F5CBCB500E23798462FE00ADBA4"
        self.assertEqual(normalize_fingerprint(spaced), expected)
        self.assertEqual(
            security_fingerprint("## The signing key\n\n```\n" + spaced + "\n```"),
            expected,
        )
        self.assertEqual(verifier_fingerprint('EXPECT="' + expected + '"\n'), expected)

    def test_bad_fingerprint_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "INVALID_FINGERPRINT"):
            normalize_fingerprint("1234")
        with self.assertRaisesRegex(ValueError, "SIGNING_FINGERPRINT_MISSING"):
            security_fingerprint("## The signing key\nnone")


if __name__ == "__main__":
    unittest.main()
