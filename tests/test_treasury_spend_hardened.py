import builtins
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


CANDIDATE = (
    Path(__file__).resolve().parents[1]
    / "reference"
    / "upstream_patch"
    / "scripts"
    / "treasury_spend_hardened.py"
)
spec = importlib.util.spec_from_file_location("treasury_spend_hardened", CANDIDATE)
treasury = importlib.util.module_from_spec(spec)
spec.loader.exec_module(treasury)


def txid(byte):
    return ("%02x" % byte) * 32


def b58encode(raw):
    alphabet = treasury._B58
    n = int.from_bytes(raw, "big")
    text = ""
    while n:
        n, rem = divmod(n, 58)
        text = alphabet[rem] + text
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * zeros + (text or "")


def make_wif(scalar=1, version=treasury.WAM_WIF_VERSION, compressed=True, marker=1):
    payload = scalar.to_bytes(32, "big")
    if compressed:
        payload += bytes([marker])
    body = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    return b58encode(body + checksum)


def utxo(n, amount="2.50000000", height=1):
    return {
        "txid": txid(n),
        "vout": 0,
        "height": height,
        "amount": amount,
        "scriptPubKey": "76a914" + ("%02x" % n) * 20 + "88ac",
    }


def decoded_for_plan(plan, *, destination=None, amount=None, change=None, inputs=None,
                     unexpected=None):
    destination = destination or plan["to"]
    amount = plan["amount"] if amount is None else amount
    change = plan["change"] if change is None else change
    source = plan.get("prevtxs") or plan["inputSet"]
    ins = inputs if inputs is not None else [
        {"txid": p["txid"], "vout": p["vout"]} for p in source
    ]
    outs = [
        {
            "value": amount,
            "scriptPubKey": {"address": destination},
        }
    ]
    if treasury._coins_to_atoms(change):
        outs.append(
            {
                "value": change,
                "scriptPubKey": {"address": treasury.TREASURY},
            }
        )
    if unexpected:
        outs.append(
            {
                "value": unexpected[1],
                "scriptPubKey": {"address": unexpected[0]},
            }
        )
    return {"txid": txid(250), "vin": ins, "vout": outs}


def make_plan():
    prev = [utxo(1, "2.50000000", 1), utxo(2, "2.50000000", 2)]
    fee = treasury._estimate_fee_atoms(2, 2)[1]
    input_total = 5 * treasury.COIN
    amount = treasury.COIN
    change = input_total - amount - fee
    return {
        "network": "mainnet",
        "from": treasury.TREASURY,
        "to": "Wdestination11111111111111111111111111",
        "amount": treasury._atoms_to_number(amount),
        "change": treasury._atoms_to_number(change),
        "fee": treasury._atoms_to_number(fee),
        "inputs": 2,
        "inputTotal": treasury._atoms_to_number(input_total),
        "sizeBytes": 2 * 148 + 2 * 34 + 10,
        "plannedAtHeight": 200,
        "unsignedHex": "00aa",
        "prevtxs": [
            {
                "txid": p["txid"],
                "vout": p["vout"],
                "scriptPubKey": p["scriptPubKey"],
                "amount": p["amount"],
            }
            for p in prev
        ],
        "reason": "mocked regression",
    }


class PlannerRpc:
    def __init__(self, *, mempool=None, mempool_txs=None, unspents=None, tip=200):
        self.mempool = [] if mempool is None else mempool
        self.mempool_txs = {} if mempool_txs is None else mempool_txs
        self.unspents = [utxo(1), utxo(2)] if unspents is None else unspents
        self.tip = tip
        self.created = None

    def call(self, method, params=None):
        if method == "getblockcount":
            return self.tip
        if method == "scantxoutset":
            return {
                "success": True,
                "unspents": self.unspents,
                "total_amount": sum(float(u["amount"]) for u in self.unspents),
            }
        if method == "getrawmempool":
            return self.mempool
        if method == "getrawtransaction":
            item = self.mempool_txs[params[0]]
            if isinstance(item, Exception):
                raise item
            return item
        if method == "createrawtransaction":
            self.created = params
            return "00aa"
        raise AssertionError(method)


class BroadcastRpc:
    def __init__(self, decoded, values, *, stale=None):
        self.decoded = decoded
        self.values = values
        self.stale = set() if stale is None else set(stale)
        self.sent = []

    def call(self, method, params=None):
        if method == "decoderawtransaction":
            return self.decoded
        if method == "gettxout":
            point = (params[0], params[1])
            if point in self.stale:
                return None
            return {"value": self.values[point]}
        if method == "sendrawtransaction":
            self.sent.append(params[0])
            return txid(251)
        raise AssertionError(method)


class TreasurySpendHardenedTests(unittest.TestCase):
    def run_plan(self, rpc, amount="1.00000000"):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "plan.json"
            args = types.SimpleNamespace(
                conf="unused",
                port=9554,
                amount=amount,
                to="Wdestination11111111111111111111111111",
                reason="mocked regression",
                out=str(out),
            )
            with mock.patch.object(treasury, "Rpc", return_value=rpc):
                with contextlib.redirect_stdout(io.StringIO()):
                    treasury.cmd_plan(args)
            return json.loads(out.read_text()), rpc

    def test_normal_plan_creation_uses_exact_fee_and_change(self):
        plan, rpc = self.run_plan(PlannerRpc())
        self.assertEqual(plan["inputs"], 2)
        self.assertEqual(
            treasury._coins_to_atoms(plan["fee"]),
            treasury._estimate_fee_atoms(2, 2)[1],
        )
        self.assertEqual(
            treasury._coins_to_atoms(plan["inputTotal"]),
            treasury._coins_to_atoms(plan["amount"])
            + treasury._coins_to_atoms(plan["change"])
            + treasury._coins_to_atoms(plan["fee"]),
        )
        self.assertEqual(len(rpc.created[0]), 2)

    def test_mempool_spent_utxo_is_excluded(self):
        spend = txid(99)
        rpc = PlannerRpc(
            mempool=[spend],
            mempool_txs={
                spend: {
                    "txid": spend,
                    "vin": [{"txid": txid(1), "vout": 0}],
                }
            },
            unspents=[utxo(1), utxo(2), utxo(3)],
        )
        plan, _ = self.run_plan(rpc)
        points = {(p["txid"], p["vout"]) for p in plan["prevtxs"]}
        self.assertNotIn((txid(1), 0), points)

    def test_unknown_mempool_transaction_state_fails_closed(self):
        spend = txid(99)
        rpc = PlannerRpc(
            mempool=[spend],
            mempool_txs={spend: RuntimeError("mocked lookup failure")},
        )
        with self.assertRaises(SystemExit):
            self.run_plan(rpc)

    def test_immature_coinbase_is_excluded(self):
        rpc = PlannerRpc(
            unspents=[
                utxo(1, height=1),
                utxo(2, height=2),
                utxo(3, height=150),
            ],
            tip=200,
        )
        plan, _ = self.run_plan(rpc)
        points = {(p["txid"], p["vout"]) for p in plan["prevtxs"]}
        self.assertNotIn((txid(3), 0), points)

    def test_duplicate_scanned_input_rejected(self):
        same = utxo(1)
        with self.assertRaises(SystemExit):
            self.run_plan(PlannerRpc(unspents=[same, dict(same)]))

    def test_duplicate_plan_input_rejected(self):
        plan = make_plan()
        plan["prevtxs"][1] = dict(plan["prevtxs"][0])
        with self.assertRaises(SystemExit):
            treasury._validate_plan(plan)

    def test_inconsistent_unsigned_input_set_rejected(self):
        plan = make_plan()
        decoded = decoded_for_plan(plan)
        decoded["vin"].reverse()
        with self.assertRaises(SystemExit):
            treasury._verify_transaction_against_plan(
                plan, decoded, treasury._validate_plan(plan)
            )

    def test_malformed_base58check_rejected(self):
        with self.assertRaises(SystemExit):
            treasury._validate_wif("not-a-wif")

    def test_bad_base58check_checksum_rejected(self):
        valid = make_wif()
        bad = valid[:-1] + ("1" if valid[-1] != "1" else "2")
        with self.assertRaises(SystemExit):
            treasury._validate_wif(bad)

    def test_wrong_wif_version_rejected(self):
        with self.assertRaises(SystemExit):
            treasury._validate_wif(make_wif(version=128))

    def test_invalid_compressed_marker_rejected(self):
        with self.assertRaises(SystemExit):
            treasury._validate_wif(make_wif(marker=2))

    def test_zero_private_scalar_rejected(self):
        with self.assertRaises(SystemExit):
            treasury._validate_wif(make_wif(scalar=0))

    def test_out_of_range_private_scalar_rejected(self):
        with self.assertRaises(SystemExit):
            treasury._validate_wif(make_wif(scalar=treasury.SECP256K1_N))

    def test_valid_synthetic_wif_accepted(self):
        self.assertTrue(treasury._validate_wif(make_wif(scalar=1)))

    def test_fee_calculation_matches_upstream_policy_exactly(self):
        size, fee = treasury._estimate_fee_atoms(201, 2)
        self.assertEqual(size, 29826)
        self.assertEqual(fee, 596520)

    def test_change_calculation_is_exact(self):
        size, fee, change = treasury._calculate_change(
            5 * treasury.COIN, treasury.COIN, 2
        )
        self.assertEqual(size, 374)
        self.assertEqual(change, 5 * treasury.COIN - treasury.COIN - fee)

    def test_fee_mismatch_rejected(self):
        plan = make_plan()
        plan["fee"] = treasury._atoms_to_number(
            treasury._coins_to_atoms(plan["fee"]) + 1
        )
        with self.assertRaises(SystemExit):
            treasury._verify_transaction_against_plan(
                plan, decoded_for_plan(plan), treasury._validate_plan(make_plan())
            )

    def test_changed_destination_rejected(self):
        plan = make_plan()
        with self.assertRaises(SystemExit):
            treasury._verify_transaction_against_plan(
                plan,
                decoded_for_plan(plan, destination="Wattacker111111111111111111111111111"),
                treasury._validate_plan(plan),
            )

    def test_changed_amount_rejected(self):
        plan = make_plan()
        changed = treasury._atoms_to_number(
            treasury._coins_to_atoms(plan["amount"]) + 1
        )
        with self.assertRaises(SystemExit):
            treasury._verify_transaction_against_plan(
                plan,
                decoded_for_plan(plan, amount=changed),
                treasury._validate_plan(plan),
            )

    def test_unexpected_output_rejected(self):
        plan = make_plan()
        with self.assertRaises(SystemExit):
            treasury._verify_transaction_against_plan(
                plan,
                decoded_for_plan(
                    plan,
                    unexpected=("Wunexpected111111111111111111111111", "0.00000001"),
                ),
                treasury._validate_plan(plan),
            )

    def test_unsigned_mismatch_fails_before_key_prompt(self):
        plan = make_plan()
        decoded = decoded_for_plan(plan)
        decoded["vin"].reverse()
        with tempfile.TemporaryDirectory() as td:
            infile = Path(td) / "plan.json"
            outfile = Path(td) / "signed.json"
            infile.write_text(json.dumps(plan))
            args = types.SimpleNamespace(
                infile=str(infile),
                out=str(outfile),
                cli="wam-cli",
                rpcconnect="127.0.0.1",
                port=9554,
                rpcuser="",
                rpcpassword="",
            )
            key_prompt = mock.Mock(return_value=make_wif())
            with mock.patch.object(
                treasury, "_offline_cli_call", return_value=decoded
            ), mock.patch.object(treasury.getpass, "getpass", key_prompt):
                with self.assertRaises(SystemExit):
                    treasury.cmd_sign(args)
            key_prompt.assert_not_called()

    def test_signing_primitive_not_called_on_preflight_failure(self):
        plan = make_plan()
        bad = decoded_for_plan(plan, destination="Wbad111111111111111111111111111111111")
        calls = []

        def offline(_args, method, payload):
            calls.append(method)
            if method == "decoderawtransaction":
                return bad
            raise AssertionError("signing must not be reached")

        with tempfile.TemporaryDirectory() as td:
            infile = Path(td) / "plan.json"
            infile.write_text(json.dumps(plan))
            args = types.SimpleNamespace(
                infile=str(infile),
                out=str(Path(td) / "signed.json"),
                cli="wam-cli",
                rpcconnect="127.0.0.1",
                port=9554,
                rpcuser="",
                rpcpassword="",
            )
            with mock.patch.object(treasury, "_offline_cli_call", side_effect=offline):
                with self.assertRaises(SystemExit):
                    treasury.cmd_sign(args)
        self.assertEqual(calls, ["decoderawtransaction"])

    def test_valid_mocked_sign_flow_adds_exact_input_set(self):
        plan = make_plan()
        decoded = decoded_for_plan(plan)

        def offline(_args, method, payload):
            if method == "decoderawtransaction":
                return decoded
            if method == "signrawtransactionwithkey":
                self.assertNotIn(make_wif(), " ".join(treasury._cli_base(_args)))
                return {"complete": True, "hex": "deadbeef"}
            raise AssertionError(method)

        with tempfile.TemporaryDirectory() as td:
            infile = Path(td) / "plan.json"
            outfile = Path(td) / "signed.json"
            infile.write_text(json.dumps(plan))
            args = types.SimpleNamespace(
                infile=str(infile),
                out=str(outfile),
                cli="wam-cli",
                rpcconnect="127.0.0.1",
                port=9554,
                rpcuser="",
                rpcpassword="",
            )
            with mock.patch.object(treasury, "_offline_cli_call", side_effect=offline), \
                 mock.patch.object(treasury.getpass, "getpass", return_value=make_wif()), \
                 mock.patch.object(builtins, "input", return_value=plan["to"]), \
                 contextlib.redirect_stdout(io.StringIO()):
                treasury.cmd_sign(args)
            signed = json.loads(outfile.read_text())
            self.assertEqual(len(signed["inputSet"]), plan["inputs"])
            self.assertNotIn("prevtxs", signed)
            self.assertEqual(signed["signedHex"], "deadbeef")

    def test_online_plan_and_broadcast_paths_do_not_prompt_or_sign(self):
        for fn in (treasury.cmd_plan, treasury.cmd_broadcast):
            source = inspect.getsource(fn)
            self.assertNotIn("getpass", source)
            self.assertNotIn("signrawtransactionwithkey", source)

    def test_stale_input_rejected_before_broadcast(self):
        plan = make_plan()
        expected = treasury._validate_plan(plan)
        signed = {k: v for k, v in plan.items() if k != "prevtxs"}
        signed["inputSet"] = [{"txid": a, "vout": b} for a, b in expected]
        signed["signedHex"] = "deadbeef"
        decoded = decoded_for_plan(signed)
        values = {point: plan["prevtxs"][i]["amount"] for i, point in enumerate(expected)}
        rpc = BroadcastRpc(decoded, values, stale={expected[0]})

        with tempfile.TemporaryDirectory() as td:
            infile = Path(td) / "signed.json"
            infile.write_text(json.dumps(signed))
            args = types.SimpleNamespace(
                infile=str(infile), conf="unused", port=9554, yes=True
            )
            with mock.patch.object(treasury, "Rpc", return_value=rpc), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    treasury.cmd_broadcast(args)
        self.assertEqual(rpc.sent, [])

    def test_valid_mocked_broadcast_flow_succeeds(self):
        plan = make_plan()
        expected = treasury._validate_plan(plan)
        signed = {k: v for k, v in plan.items() if k != "prevtxs"}
        signed["inputSet"] = [{"txid": a, "vout": b} for a, b in expected]
        signed["signedHex"] = "deadbeef"
        decoded = decoded_for_plan(signed)
        values = {point: plan["prevtxs"][i]["amount"] for i, point in enumerate(expected)}
        rpc = BroadcastRpc(decoded, values)

        with tempfile.TemporaryDirectory() as td:
            infile = Path(td) / "signed.json"
            infile.write_text(json.dumps(signed))
            args = types.SimpleNamespace(
                infile=str(infile), conf="unused", port=9554, yes=True
            )
            with mock.patch.object(treasury, "Rpc", return_value=rpc), \
                 contextlib.redirect_stdout(io.StringIO()):
                treasury.cmd_broadcast(args)
        self.assertEqual(rpc.sent, ["deadbeef"])

    def test_signed_transport_duplicate_input_rejected(self):
        plan = make_plan()
        expected = treasury._validate_plan(plan)
        signed = {k: v for k, v in plan.items() if k != "prevtxs"}
        signed["inputSet"] = [
            {"txid": expected[0][0], "vout": expected[0][1]},
            {"txid": expected[0][0], "vout": expected[0][1]},
        ]
        signed["signedHex"] = "deadbeef"
        with self.assertRaises(SystemExit):
            treasury._validate_signed_transport(signed)


if __name__ == "__main__":
    unittest.main()
