import hashlib
import unittest

from wam_security.electrum.trust import (
    compare_servers,
    compare_with_node,
    single_server_completeness_claim,
    verify_endpoint_claim,
    verify_merkle_inclusion,
)


def h256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class ElectrumTrustTests(unittest.TestCase):
    def test_endpoint_impersonation_and_wrong_chain_fail(self):
        verify_endpoint_claim(
            {"genesis_hash": "aa" * 32},
            {"height": 100},
            "aa" * 32,
            102,
            5,
        )
        with self.assertRaisesRegex(ValueError, "ELECTRUM_CHAIN_IDENTITY"):
            verify_endpoint_claim(
                {"genesis_hash": "bb" * 32},
                {"height": 100},
                "aa" * 32,
                100,
                5,
            )
        with self.assertRaisesRegex(ValueError, "ELECTRUM_HEIGHT_DIVERGENCE"):
            verify_endpoint_claim(
                {"genesis_hash": "aa" * 32},
                {"height": 80},
                "aa" * 32,
                100,
                5,
            )

    def test_valid_inclusion_does_not_prove_completeness(self):
        left = "11" * 32
        right = "22" * 32
        root = h256(bytes.fromhex(left)[::-1] + bytes.fromhex(right)[::-1])[::-1].hex()
        self.assertTrue(verify_merkle_inclusion(left, [right], 0, root))
        self.assertEqual(
            single_server_completeness_claim(True),
            "UNPROVEN_BY_SINGLE_SERVER",
        )

    def test_bad_merkle_proof_is_rejected(self):
        self.assertFalse(
            verify_merkle_inclusion("11" * 32, ["22" * 32], 0, "33" * 32)
        )

    def test_two_servers_expose_divergence_but_do_not_resolve_truth(self):
        a = [{"tx_hash": "11" * 32, "height": 5}]
        b = [
            {"tx_hash": "11" * 32, "height": 5},
            {"tx_hash": "22" * 32, "height": 8},
        ]
        result = compare_servers(a, b)
        self.assertFalse(result["agree"])
        self.assertFalse(result["truth_resolved"])

    def test_node_derived_history_detects_omission(self):
        server = [{"tx_hash": "11" * 32, "height": 5}]
        node = server + [{"tx_hash": "22" * 32, "height": 8}]
        result = compare_with_node(server, node)
        self.assertFalse(result["complete"])
        self.assertEqual(result["missing_from_server"], (("22" * 32, 8),))


if __name__ == "__main__":
    unittest.main()
