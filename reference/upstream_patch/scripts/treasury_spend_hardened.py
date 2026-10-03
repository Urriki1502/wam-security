#!/usr/bin/env python3
# Copyright (c) 2026 The WAM Coin developers
# Distributed under the MIT software license, see COPYING.
"""
Review-ready hardened candidate for WAM Core's treasury spend script.

Baseline:
    wamcoin-core-dev/wam-coin@bd71b0bd645286a3867dad6b2bfefd911ec8a5b6
    scripts/treasury_spend.py

Operator workflow is intentionally preserved:

    ONLINE   python3 scripts/treasury_spend_hardened.py plan --to <addr> --amount 500
    OFFLINE  python3 scripts/treasury_spend_hardened.py sign --in plan.json
    ONLINE   python3 scripts/treasury_spend_hardened.py broadcast --in signed.json

This candidate keeps the upstream CLI/RPC/file flow but fails closed when chain
or mempool state is unknown, validates the exact transaction before the signing
key is requested, validates WAM WIF structure, and re-checks every input against
current node+mempool state immediately before broadcast.
"""

import argparse
import base64
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import getpass
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

TREASURY = "WdMMqW1DcgWZ6HtyJuEMdce6QkKg4raGmE"
COINBASE_MATURITY = 100
COIN = 100_000_000
DUST_ATOMS = 546
WAM_WIF_VERSION = 190
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Same policy as upstream: 0.0002 WAM/kvB == 20,000 atomic units/kvB.
FEERATE_ATOMS_PER_KVB = 20_000
FEERATE_PER_KVB = 0.0002


def die(msg):
    sys.stderr.write("error: %s\n" % msg)
    raise SystemExit(1)


class Rpc:
    """Talks to a node over HTTP, reading credentials from its wam.conf."""

    def __init__(self, conf, host="127.0.0.1", port=9554):
        creds = {}
        try:
            for line in open(conf, encoding="utf-8"):
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    creds[k.strip()] = v.strip()
        except OSError as e:
            die("cannot read %s: %s" % (conf, e))
        if "rpcuser" not in creds or "rpcpassword" not in creds:
            die("%s has no rpcuser/rpcpassword" % conf)
        self.auth = base64.b64encode(
            ("%s:%s" % (creds["rpcuser"], creds["rpcpassword"])).encode()
        ).decode()
        self.url = "http://%s:%d/" % (host, port)

    def call(self, method, params=None):
        body = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": "treasury",
                "method": method,
                "params": params or [],
            }
        )
        req = urllib.request.Request(
            self.url,
            data=body.encode(),
            headers={
                "Authorization": "Basic " + self.auth,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                out = json.load(r)
        except Exception as e:
            die("%s: %s" % (method, e))
        if out.get("error"):
            die("%s: %s" % (method, out["error"].get("message", out["error"])))
        return out["result"]


def _coins_to_atoms(value):
    try:
        amount = Decimal(str(value)) * COIN
    except (InvalidOperation, ValueError, TypeError):
        die("invalid WAM amount: %r" % (value,))
    if not amount.is_finite() or amount != amount.to_integral_value() or amount < 0:
        die("amount must be non-negative with at most 8 decimal places: %r" % (value,))
    return int(amount)


def _atoms_to_decimal(atoms):
    if type(atoms) is not int or atoms < 0:
        die("invalid atomic amount")
    return Decimal(atoms) / COIN


def _atoms_to_number(atoms):
    # Preserve upstream's numeric JSON fields while deriving them from exact atoms.
    return float("%.8f" % _atoms_to_decimal(atoms))


def wam(x):
    """Coins, printed the way the node prints them."""
    if type(x) is int:
        return "%.8f" % _atoms_to_decimal(x)
    return "%.8f" % Decimal(str(x))


def _outpoint(item):
    if not isinstance(item, dict):
        die("invalid input entry")
    txid, vout = item.get("txid"), item.get("vout")
    if not isinstance(txid, str) or len(txid) != 64:
        die("invalid input txid")
    try:
        bytes.fromhex(txid)
    except ValueError:
        die("invalid input txid")
    if type(vout) is not int or not 0 <= vout < 2**32:
        die("invalid input vout")
    return txid, vout


def _unique_outpoints(items, label):
    points = tuple(_outpoint(item) for item in items)
    if len(set(points)) != len(points):
        die("duplicate outpoint in %s" % label)
    return points


def _estimate_fee_atoms(input_count, output_count=2):
    if type(input_count) is not int or input_count < 1 or output_count not in (1, 2):
        die("invalid transaction shape for fee calculation")
    size = input_count * 148 + output_count * 34 + 10
    fee = int(
        (Decimal(FEERATE_ATOMS_PER_KVB) * size / 1000).to_integral_value(
            rounding=ROUND_CEILING
        )
    )
    return size, fee


def _calculate_change(input_atoms, amount_atoms, input_count):
    size, fee = _estimate_fee_atoms(input_count, 2)
    change = input_atoms - amount_atoms - fee
    if change < 0:
        die("the chosen inputs do not cover the amount and the fee")
    if 0 < change < DUST_ATOMS:
        fee += change
        change = 0
    return size, fee, change


def _decode_base58check(text):
    if not isinstance(text, str) or not text or any(c not in _B58 for c in text):
        die("that is not a valid Base58Check key")
    n = 0
    for c in text:
        n = n * 58 + _B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5:
        die("that is not a valid Base58Check key")
    body, check = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    if check != expected:
        die("that key's Base58Check checksum does not match")
    return body


def _validate_wif(text):
    body = _decode_base58check(text)
    if body[0] != WAM_WIF_VERSION:
        die("that WIF is for the wrong network/version")
    payload = body[1:]
    if len(payload) == 33:
        if payload[-1] != 1:
            die("that WIF has an invalid compressed-key marker")
        payload = payload[:-1]
    elif len(payload) != 32:
        die("that WIF has an invalid payload length")
    scalar = int.from_bytes(payload, "big")
    if not 1 <= scalar < SECP256K1_N:
        die("that WIF contains an invalid secp256k1 private scalar")
    return True


def _validate_plan(plan):
    required = {
        "network",
        "from",
        "to",
        "amount",
        "change",
        "fee",
        "inputs",
        "inputTotal",
        "unsignedHex",
        "prevtxs",
        "reason",
    }
    if not isinstance(plan, dict) or not required <= plan.keys():
        die("the plan is missing required fields")
    if plan["network"] != "mainnet" or plan["from"] != TREASURY:
        die("the plan is not for the WAM mainnet treasury")
    if not isinstance(plan["to"], str) or not plan["to"]:
        die("the plan has no destination")
    if not isinstance(plan["unsignedHex"], str) or not plan["unsignedHex"]:
        die("the plan has no unsigned transaction")
    if not isinstance(plan["prevtxs"], list):
        die("the plan has no previous-output set")
    if type(plan["inputs"]) is not int or plan["inputs"] != len(plan["prevtxs"]):
        die("the plan input count does not match prevtxs")

    points = _unique_outpoints(plan["prevtxs"], "plan")
    total_atoms = 0
    for prev in plan["prevtxs"]:
        if not isinstance(prev.get("scriptPubKey"), str) or not prev["scriptPubKey"]:
            die("a planned input has no scriptPubKey")
        total_atoms += _coins_to_atoms(prev.get("amount"))

    amount_atoms = _coins_to_atoms(plan["amount"])
    change_atoms = _coins_to_atoms(plan["change"])
    fee_atoms = _coins_to_atoms(plan["fee"])
    claimed_total = _coins_to_atoms(plan["inputTotal"])
    if amount_atoms <= 0 or fee_atoms <= 0:
        die("the plan has an invalid amount or fee")
    if claimed_total != total_atoms:
        die("the plan input total does not match prevtxs")
    if total_atoms != amount_atoms + change_atoms + fee_atoms:
        die("the plan does not conserve value")
    return points


def _signed_input_set(signed):
    raw = signed.get("inputSet")
    if not isinstance(raw, list) or type(signed.get("inputs")) is not int:
        die("the signed transport has no exact input set")
    points = _unique_outpoints(raw, "signed input set")
    if len(points) != signed["inputs"]:
        die("the signed transport input count does not match its input set")
    return points


def _decoded_input_set(tx):
    if not isinstance(tx, dict) or not isinstance(tx.get("vin"), list):
        die("cannot decode transaction inputs")
    return _unique_outpoints(tx["vin"], "decoded transaction")


def _decoded_outputs(tx):
    if not isinstance(tx, dict) or not isinstance(tx.get("vout"), list):
        die("cannot decode transaction outputs")
    outputs = []
    for out in tx["vout"]:
        if not isinstance(out, dict) or not isinstance(out.get("scriptPubKey"), dict):
            die("cannot decode a transaction output")
        addr = out["scriptPubKey"].get("address")
        if not isinstance(addr, str) or not addr:
            die("transaction contains an output without a single address")
        outputs.append((addr, _coins_to_atoms(out.get("value"))))
    return outputs


def _verify_transaction_against_plan(plan, tx, expected_inputs):
    actual_inputs = _decoded_input_set(tx)
    if actual_inputs != tuple(expected_inputs):
        die("the transaction input set/order does not match the approved plan")

    outputs = _decoded_outputs(tx)
    amount_atoms = _coins_to_atoms(plan["amount"])
    change_atoms = _coins_to_atoms(plan["change"])
    fee_atoms = _coins_to_atoms(plan["fee"])
    input_total_atoms = _coins_to_atoms(plan["inputTotal"])

    expected_outputs = [(plan["to"], amount_atoms)]
    if change_atoms:
        expected_outputs.append((TREASURY, change_atoms))

    # createrawtransaction may preserve mapping/list order. Security checking
    # does not rely on output order, but it requires exactly one destination
    # output and at most one treasury change output, with no other script.
    if sorted(outputs) != sorted(expected_outputs):
        die("the transaction outputs do not match destination/change exactly")

    total_out = sum(value for _, value in outputs)
    if input_total_atoms - total_out != fee_atoms:
        die("the transaction fee does not match the approved plan")
    return {
        "inputs": actual_inputs,
        "outputs": outputs,
        "fee_atoms": fee_atoms,
        "input_total_atoms": input_total_atoms,
    }


def _cli_base(args):
    cli = [
        args.cli,
        "-chain=main",
        "-rpcconnect=%s" % args.rpcconnect,
        "-rpcport=%d" % args.port,
    ]
    if args.rpcuser:
        cli += ["-rpcuser=%s" % args.rpcuser, "-rpcpassword=%s" % args.rpcpassword]
    return cli


def _offline_cli_call(args, method, payload_lines):
    cli = _cli_base(args) + ["-stdin", method]
    payload = "\n".join(payload_lines) + "\n"
    proc = subprocess.run(cli, input=payload, capture_output=True, text=True)
    del payload
    if proc.returncode != 0:
        die("%s failed: %s" % (method, proc.stderr.strip() or proc.stdout.strip()))
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        die("%s returned invalid JSON" % method)


def _collect_mempool_spent(rpc):
    try:
        txids = rpc.call("getrawmempool")
    except BaseException:
        raise
    if not isinstance(txids, list) or len(set(txids)) != len(txids):
        die("cannot establish a complete mempool transaction set")
    spent = set()
    for txid in txids:
        if not isinstance(txid, str):
            die("cannot establish mempool spend state")
        try:
            entry = rpc.call("getrawtransaction", [txid, True])
        except SystemExit:
            raise
        except Exception as e:
            die("cannot establish mempool spend state for %s: %s" % (txid, e))
        if not isinstance(entry, dict) or not isinstance(entry.get("vin"), list):
            die("cannot establish mempool spend state for %s" % txid)
        if entry.get("txid") not in (None, txid):
            die("mempool transaction identity changed while planning")
        for vin in entry["vin"]:
            if "coinbase" in vin:
                continue
            point = _outpoint(vin)
            if point in spent:
                die("mempool view contains a duplicate spent outpoint")
            spent.add(point)
    return spent


# ---------------------------------------------------------------------------
# plan -- runs where the chain is
# ---------------------------------------------------------------------------

def cmd_plan(args):
    rpc = Rpc(args.conf, port=args.port)
    tip = rpc.call("getblockcount")
    if type(tip) is not int or tip < 0:
        die("node returned an invalid chain height")

    print("scanning the treasury's unspent outputs (this takes a minute)...")
    scan = rpc.call("scantxoutset", ["start", ["addr(%s)" % TREASURY]])
    if not isinstance(scan, dict) or not scan.get("success"):
        die("the scan did not complete")

    utxos = scan.get("unspents", [])
    if not isinstance(utxos, list):
        die("the scan returned an invalid UTXO set")
    _unique_outpoints(utxos, "scantxoutset")

    mature = []
    young = 0
    for u in utxos:
        height = u.get("height")
        if type(height) is not int or height < 1 or height > tip:
            die("the scan returned an invalid UTXO height")
        if not isinstance(u.get("scriptPubKey"), str) or not u["scriptPubKey"]:
            die("the scan returned an input without scriptPubKey")
        _coins_to_atoms(u.get("amount"))
        if tip - height + 1 > COINBASE_MATURITY:
            mature.append(u)
        else:
            young += 1

    spent = _collect_mempool_spent(rpc)
    if spent:
        before = len(mature)
        mature = [u for u in mature if _outpoint(u) not in spent]
        held = before - len(mature)
        if held:
            print(
                "  in the mempool      %d output(s) already spent by an "
                "unconfirmed transaction, left out" % held
            )

    scan_total_atoms = _coins_to_atoms(scan.get("total_amount", 0))
    print("  height              %d" % tip)
    print(
        "  outputs             %d, totalling %s WAM"
        % (len(utxos), wam(scan_total_atoms))
    )
    print(
        "  spendable now       %d (%d are at or under %d confirmations)"
        % (len(mature), young, COINBASE_MATURITY)
    )

    mature.sort(key=lambda u: (u["height"], u["txid"], u["vout"]))

    target_atoms = _coins_to_atoms(args.amount)
    if target_atoms <= 0:
        die("amount must be greater than zero")
    chosen, got_atoms = [], 0
    for u in mature:
        chosen.append(u)
        got_atoms += _coins_to_atoms(u["amount"])
        # Preserve upstream's one-input cushion policy (treasury outputs are 2.5 WAM).
        if got_atoms >= target_atoms + 3 * COIN:
            break
    if got_atoms < target_atoms:
        die(
            "the treasury has only %s WAM spendable and %s was asked for"
            % (wam(got_atoms), wam(target_atoms))
        )

    size, fee_atoms, change_atoms = _calculate_change(
        got_atoms, target_atoms, len(chosen)
    )

    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in chosen]
    outputs = [{args.to: _atoms_to_number(target_atoms)}]
    if change_atoms:
        outputs.append({TREASURY: _atoms_to_number(change_atoms)})

    raw = rpc.call("createrawtransaction", [inputs, outputs])
    if not isinstance(raw, str) or not raw:
        die("createrawtransaction returned no transaction")

    prevtxs = [
        {
            "txid": u["txid"],
            "vout": u["vout"],
            "scriptPubKey": u["scriptPubKey"],
            "amount": _atoms_to_number(_coins_to_atoms(u["amount"])),
        }
        for u in chosen
    ]

    plan = {
        "network": "mainnet",
        "from": TREASURY,
        "to": args.to,
        "amount": _atoms_to_number(target_atoms),
        "change": _atoms_to_number(change_atoms),
        "fee": _atoms_to_number(fee_atoms),
        "inputs": len(chosen),
        "inputTotal": _atoms_to_number(got_atoms),
        "sizeBytes": size,
        "plannedAtHeight": tip,
        "unsignedHex": raw,
        "prevtxs": prevtxs,
        "reason": args.reason,
    }
    _validate_plan(plan)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(plan, f, indent=2)

    print()
    print("=" * 66)
    print(" READ THIS BEFORE YOU SIGN IT")
    print("=" * 66)
    print("  paying             %s WAM" % wam(target_atoms))
    print("  to                 %s" % args.to)
    print("  from               %s  (the treasury)" % TREASURY)
    print(
        "  inputs             %d, totalling %s WAM"
        % (len(chosen), wam(got_atoms))
    )
    print("  change back        %s WAM" % wam(change_atoms))
    print("  fee                %s WAM  (%d bytes)" % (wam(fee_atoms), size))
    print("  reason             %s" % args.reason)
    print()
    print("  written to         %s" % args.out)
    print()
    print("  Carry that file to the air-gapped machine and run:")
    print(
        "      python3 scripts/treasury_spend_hardened.py sign --in %s"
        % os.path.basename(args.out)
    )
    print("=" * 66)


# ---------------------------------------------------------------------------
# sign -- runs where the key is, with no network
# ---------------------------------------------------------------------------

def cmd_sign(args):
    with open(args.infile, encoding="utf-8") as f:
        plan = json.load(f)

    expected_inputs = _validate_plan(plan)

    # Decode and verify every non-secret property before asking for the key.
    decoded = _offline_cli_call(
        args, "decoderawtransaction", [plan["unsignedHex"]]
    )
    _verify_transaction_against_plan(plan, decoded, expected_inputs)

    print("=" * 66)
    print(" WHAT YOU ARE ABOUT TO SIGN")
    print("=" * 66)
    print("  paying       %s WAM" % wam(plan["amount"]))
    print("  to           %s" % plan["to"])
    print("  from         %s" % plan["from"])
    print("  change back  %s WAM" % wam(plan["change"]))
    print("  fee          %s WAM" % wam(plan["fee"]))
    print("  reason       %s" % plan.get("reason", "(none given)"))
    print("=" * 66)
    if input("  type the destination address again to confirm: ").strip() != plan["to"]:
        die("that is not the address in the plan; nothing was signed")

    wif = ""
    for attempt in range(3):
        wif = getpass.getpass("  treasury private key (WIF, not echoed): ").strip()
        if not wif:
            die("no key was given")
        try:
            _validate_wif(wif)
            break
        except SystemExit:
            left = 2 - attempt
            if left:
                print(
                    "  that is not a valid WAM mainnet private key. "
                    "%d try/tries left." % left
                )
            else:
                die("three invalid keys; nothing was signed")

    res = _offline_cli_call(
        args,
        "signrawtransactionwithkey",
        [plan["unsignedHex"], json.dumps([wif]), json.dumps(plan["prevtxs"])],
    )
    del wif

    if not isinstance(res, dict) or not res.get("complete"):
        die(
            "the transaction is not fully signed: %s"
            % json.dumps((res or {}).get("errors", []))[:400]
        )
    if not isinstance(res.get("hex"), str) or not res["hex"]:
        die("the signing command returned no signed transaction")

    out = dict(plan)
    out["inputSet"] = [
        {"txid": txid, "vout": vout} for txid, vout in expected_inputs
    ]
    out["signedHex"] = res["hex"]
    out.pop("prevtxs", None)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)

    print()
    print("  signed, and the key was not written anywhere.")
    print("  carry %s back and run:" % args.out)
    print(
        "      python3 scripts/treasury_spend_hardened.py broadcast --in %s"
        % os.path.basename(args.out)
    )


# ---------------------------------------------------------------------------
# broadcast -- runs where the chain is, and checks before it sends
# ---------------------------------------------------------------------------

def _validate_signed_transport(signed):
    required = {
        "network",
        "from",
        "to",
        "amount",
        "change",
        "fee",
        "inputs",
        "inputTotal",
        "signedHex",
        "inputSet",
    }
    if not isinstance(signed, dict) or not required <= signed.keys():
        die("the signed transport is missing required fields")
    if signed["network"] != "mainnet" or signed["from"] != TREASURY:
        die("the signed transport is not for the WAM mainnet treasury")
    if not isinstance(signed["to"], str) or not signed["to"]:
        die("the signed transport has no destination")
    if not isinstance(signed["signedHex"], str) or not signed["signedHex"]:
        die("the signed transport has no signed transaction")
    points = _signed_input_set(signed)

    input_total = _coins_to_atoms(signed["inputTotal"])
    amount = _coins_to_atoms(signed["amount"])
    change = _coins_to_atoms(signed["change"])
    fee = _coins_to_atoms(signed["fee"])
    if amount <= 0 or fee <= 0 or input_total != amount + change + fee:
        die("the signed transport does not conserve value")
    return points


def _recheck_inputs(rpc, points, expected_total_atoms):
    observed_total = 0
    for txid, vout in points:
        state = rpc.call("gettxout", [txid, vout, True])
        if not isinstance(state, dict):
            die("an approved input is now spent or unavailable: %s:%d" % (txid, vout))
        observed_total += _coins_to_atoms(state.get("value"))
    if observed_total != expected_total_atoms:
        die("current input values no longer match the signed plan")


def cmd_broadcast(args):
    with open(args.infile, encoding="utf-8") as f:
        signed = json.load(f)

    expected_inputs = _validate_signed_transport(signed)
    rpc = Rpc(args.conf, port=args.port)

    tx = rpc.call("decoderawtransaction", [signed["signedHex"]])
    verified = _verify_transaction_against_plan(signed, tx, expected_inputs)

    print("=" * 66)
    print(" WHAT THE SIGNED TRANSACTION ACTUALLY DOES")
    print("=" * 66)
    for addr, atoms in sorted(verified["outputs"], key=lambda kv: -kv[1]):
        tag = (
            "  <- the destination"
            if addr == signed["to"]
            else "  <- back to the treasury"
            if addr == TREASURY
            else "  <- UNEXPECTED"
        )
        print("  %s WAM  %s%s" % (wam(atoms), addr, tag))
    print("  fee                %s WAM" % wam(verified["fee_atoms"]))
    print("  inputs             %d" % len(verified["inputs"]))
    print("  txid               %s" % tx.get("txid", "(decoder did not return txid)"))
    print("=" * 66)

    # Fresh state check happens after decoding/plan verification and immediately
    # before the operator's SEND confirmation / broadcast.
    _recheck_inputs(rpc, expected_inputs, verified["input_total_atoms"])

    print("  every field and every current input matches the plan.")
    if not args.yes:
        if input("  type SEND to broadcast it: ").strip() != "SEND":
            die("not sent")

    txid = rpc.call("sendrawtransaction", [signed["signedHex"]])
    print()
    print("  broadcast. txid %s" % txid)
    print()
    print("  Publish it: the amount, the reason and this txid. That is the")
    print("  promise in SECURITY.md and in docs/TREASURY_CUSTODY.md, and this")
    print("  is the treasury's first movement since block 1.")


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan", help="build the unsigned transaction (online)")
    p.add_argument("--to", required=True)
    # Keep the CLI spelling identical, but delay conversion so decimal input is
    # not first rounded through binary float.
    p.add_argument("--amount", required=True)
    p.add_argument(
        "--reason", required=True, help="one line, and it will be published with the txid"
    )
    p.add_argument("--conf", default="/root/.wam-mainnet/wam.conf")
    p.add_argument("--port", type=int, default=9554)
    p.add_argument("--out", default="treasury-plan.json")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("sign", help="sign it where the key is (offline)")
    p.add_argument("--in", dest="infile", default="treasury-plan.json")
    p.add_argument("--out", default="treasury-signed.json")
    p.add_argument("--cli", default="wam-cli")
    p.add_argument("--rpcconnect", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9554)
    p.add_argument("--rpcuser", default="")
    p.add_argument("--rpcpassword", default="")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("broadcast", help="check it, then send it (online)")
    p.add_argument("--in", dest="infile", default="treasury-signed.json")
    p.add_argument("--conf", default="/root/.wam-mainnet/wam.conf")
    p.add_argument("--port", type=int, default=9554)
    p.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    p.set_defaults(func=cmd_broadcast)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
