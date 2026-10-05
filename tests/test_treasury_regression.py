import hashlib
import inspect
import unittest

from wam_security.treasury import common, offline, online


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = common.B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + (out or "1")


def wif(secret=1, version=190, compressed=True):
    body = bytes([version]) + secret.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    check = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    return b58encode(body + check)


def plan():
    return {
        "network": "mainnet",
        "from": "W-treasury",
        "to": "W-destination",
        "amount": "5.00000000",
        "change": "4.99990000",
        "fee": "0.00010000",
        "inputs": 2,
        "inputTotal": "10.00000000",
        "unsignedHex": "00aa",
        "prevtxs": [
            {
                "txid": "11" * 32,
                "vout": 0,
                "scriptPubKey": "76",
                "amount": "5.00000000",
            },
            {
                "txid": "22" * 32,
                "vout": 1,
                "scriptPubKey": "76",
                "amount": "5.00000000",
            },
        ],
        "reason": "synthetic regression",
    }


def decoded_unsigned():
    return {
        "vin": [
            {"txid": "11" * 32, "vout": 0},
            {"txid": "22" * 32, "vout": 1},
        ]
    }


class TreasuryRegressionTests(unittest.TestCase):
    def test_mempool_spent_utxo_is_never_selected(self):
        utxos = [
            {
                "txid": "11" * 32,
                "vout": 0,
                "height": 1,
                "amount": "2.5",
                "scriptPubKey": "76",
            },
            {
                "txid": "22" * 32,
                "vout": 0,
                "height": 2,
                "amount": "2.5",
                "scriptPubKey": "76",
            },
        ]
        mempool = [{"vin": [{"txid": "11" * 32, "vout": 0}]}]
        selected = common.filter_spendable(utxos, 200, mempool)
        self.assertEqual([common.outpoint(x) for x in selected], [("22" * 32, 0)])

    def test_mempool_read_uncertainty_fails_closed(self):
        class RPC:
            def call(self, method, params=None):
                if method == "getrawmempool":
                    return ["aa" * 32]
                raise TimeoutError("synthetic")

        with self.assertRaisesRegex(ValueError, "MEMPOOL_STATE_UNKNOWN"):
            online.collect_mempool_transactions(RPC())

    def test_strict_wam_wif_base58check_network_length_and_scalar(self):
        self.assertEqual(common.validate_wif(wif())["version"], 190)
        bad = wif()[:-1] + ("1" if wif()[-1] != "1" else "2")
        with self.assertRaises(ValueError):
            common.validate_wif(bad)
        with self.assertRaisesRegex(ValueError, "WIF_NETWORK"):
            common.validate_wif(wif(version=128))
        with self.assertRaisesRegex(ValueError, "WIF_SCALAR"):
            common.validate_wif(wif(secret=0))

    def test_fee_and_change_are_integer_exact(self):
        fee = common.estimate_fee_atoms(201, 2)
        self.assertEqual(fee, 596_520)
        fee2, change = common.calculate_change(50_000_000_000, 49_999_000_000, 201)
        self.assertEqual(fee2, 596_520)
        self.assertEqual(change, 403_480)

    def test_plan_rejects_inconsistent_and_duplicate_inputs(self):
        candidate = plan()
        candidate["inputTotal"] = "9.00000000"
        with self.assertRaisesRegex(ValueError, "PLAN_INPUT_TOTAL"):
            common.validate_plan(candidate)
        candidate = plan()
        candidate["prevtxs"][1] = dict(candidate["prevtxs"][0])
        with self.assertRaisesRegex(ValueError, "PLAN_DUPLICATE_INPUT"):
            common.validate_plan(candidate)

    def test_offline_preflight_rejects_input_swap_before_key_prompt(self):
        calls = []

        def key_supplier():
            calls.append("key")
            return wif()

        with self.assertRaisesRegex(ValueError, "UNSIGNED_INPUT_SET_MISMATCH"):
            offline.sign_plan(
                plan(),
                {"vin": list(reversed(decoded_unsigned()["vin"]))},
                key_supplier,
                lambda *_: {},
            )
        self.assertEqual(calls, [])

    def test_mistyped_wif_fails_before_signer_use(self):
        used = []
        bad = wif()[:-1] + ("1" if wif()[-1] != "1" else "2")

        def signer(*_):
            used.append(True)
            return {"complete": True, "hex": "ff"}

        with self.assertRaises(ValueError):
            offline.sign_plan(plan(), decoded_unsigned(), lambda: bad, signer)
        self.assertEqual(used, [])

    def test_offline_signer_emits_exact_input_set(self):
        result = offline.sign_plan(
            plan(),
            decoded_unsigned(),
            lambda: wif(),
            lambda raw, key, prev: {"complete": True, "hex": "deadbeef"},
        )
        self.assertNotIn("prevtxs", result)
        self.assertEqual(result["inputSet"][0]["txid"], "11" * 32)

    def test_broadcaster_rechecks_stale_utxo_and_fee(self):
        candidate = plan()
        signed = {k: v for k, v in candidate.items() if k != "prevtxs"}
        signed["inputSet"] = [
            {"txid": "11" * 32, "vout": 0},
            {"txid": "22" * 32, "vout": 1},
        ]
        decoded = {
            "vin": decoded_unsigned()["vin"],
            "vout": [
                {
                    "value": "5.00000000",
                    "scriptPubKey": {"address": "W-destination"},
                },
                {
                    "value": "4.99990000",
                    "scriptPubKey": {"address": "W-treasury"},
                },
            ],
        }

        class RPC:
            def call(self, method, params=None):
                if params[0] == "11" * 32:
                    return {"value": "5.00000000"}
                return None

        with self.assertRaisesRegex(ValueError, "STALE_OR_SPENT_UTXO"):
            online.verify_broadcast_state(signed, decoded, RPC())

    def test_online_role_has_no_secret_or_signing_loader(self):
        source = inspect.getsource(online)
        for forbidden in ("getpass", "signrawtransactionwithkey", "validate_wif", "key_supplier"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
