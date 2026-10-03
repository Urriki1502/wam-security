#!/usr/bin/env python3
"""Native isolated-regtest wallet lifecycle probe for WAM.

The probe uses only disposable local wallets, a temporary datadir, local RPC,
local mining, and deterministic transaction-state checks. It never connects to
public peers and never reads or exports private keys.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from decimal import Decimal
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any

SAT = Decimal("0.00000001")
WAM_COMMIT = "bd71b0bd645286a3867dad6b2bfefd911ec8a5b6"


def run(cmd: list[str], *, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
        timeout=timeout,
    )


def parse_json(cp: subprocess.CompletedProcess[str]) -> Any:
    return json.loads(cp.stdout)


def dec(value: Any) -> Decimal:
    return Decimal(str(value))


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core-tree", type=Path, required=True)
    ap.add_argument("--wam-source", type=Path, required=True)
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/wallet-state-native.json"),
    )
    args = ap.parse_args()

    core = args.core_tree.resolve()
    wam_source = args.wam_source.resolve()
    wamd = core / "src/wamd"
    cli = core / "src/wam-cli"
    for path in (wamd, cli):
        if not path.exists():
            raise SystemExit(f"missing local executable: {path}")

    wam_commit = run(["git", "-C", str(wam_source), "rev-parse", "HEAD"]).stdout.strip()
    if wam_commit != args.expected_commit:
        raise SystemExit(f"WAM checkout is {wam_commit}, expected {args.expected_commit}")
    core_upstream_commit = run(["git", "-C", str(core), "rev-parse", "HEAD"]).stdout.strip()

    datadir = Path(tempfile.mkdtemp(prefix="wam-wallet-integrity-"))
    backup_dir = Path(tempfile.mkdtemp(prefix="wam-wallet-backup-"))
    rpc_port = pick_free_port()
    rpc_user = "walletci"
    rpc_pass = secrets.token_urlsafe(24)
    wallet_passphrase = secrets.token_urlsafe(32)

    cli_base = [
        str(cli),
        "-regtest",
        f"-datadir={datadir}",
        f"-rpcport={rpc_port}",
        f"-rpcuser={rpc_user}",
        f"-rpcpassword={rpc_pass}",
    ]
    daemon_base = [
        str(wamd),
        "-regtest",
        f"-datadir={datadir}",
        "-server=1",
        "-listen=0",
        "-dnsseed=0",
        "-fixedseeds=0",
        "-discover=0",
        "-connect=0",
        "-persistmempool=0",
        "-txindex=1",
        f"-rpcport={rpc_port}",
        f"-rpcuser={rpc_user}",
        f"-rpcpassword={rpc_pass}",
        "-daemonwait",
    ]

    evidence: dict[str, Any] = {
        "schema": "wam-security-wallet-state-native/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "wam_commit": wam_commit,
            "upstream_tag": "bitcoin/bitcoin v28.1",
            "upstream_commit": core_upstream_commit,
            "binaries": {
                "wamd_sha256": file_sha256(wamd),
                "wam_cli_sha256": file_sha256(cli),
            },
            "wam_security_head": os.environ.get("SECURITY_TARGET_SHA"),
        },
        "scope": {
            "regtest_only": True,
            "temporary_datadir": True,
            "listen": False,
            "dnsseed": False,
            "fixedseeds": False,
            "discover": False,
            "automatic_connections": False,
            "real_wallets": False,
            "real_keys": False,
            "private_key_export": False,
            "database_tampering": False,
            "public_nodes": False,
            "public_testnet": False,
        },
        "states": {},
        "transactions": {},
        "invariants": {},
    }

    def cli_call(*argv: str, wallet: str | None = None, check: bool = True, timeout: int = 240) -> subprocess.CompletedProcess[str]:
        cmd = list(cli_base)
        if wallet is not None:
            cmd.append(f"-rpcwallet={wallet}")
        cmd.extend(argv)
        return run(cmd, check=check, timeout=timeout)

    def jcall(*argv: str, wallet: str | None = None, check: bool = True, timeout: int = 240) -> Any:
        return parse_json(cli_call(*argv, wallet=wallet, check=check, timeout=timeout))

    def start() -> None:
        cp = run(daemon_base, check=False, timeout=600)
        if cp.returncode != 0:
            raise RuntimeError(f"wamd startup failed ({cp.returncode}): {cp.stdout[-4000:]}")
        cli_call("-rpcwait", "getblockchaininfo", timeout=300)

    def load_wallets(*names: str) -> None:
        loaded = set(jcall("listwallets"))
        for name in names:
            if name not in loaded:
                cli_call("loadwallet", name)
                loaded.add(name)

    def stop() -> None:
        cli_call("stop", check=False, timeout=60)
        deadline = time.time() + 45
        while time.time() < deadline:
            cp = cli_call("getblockchaininfo", check=False, timeout=3)
            if cp.returncode != 0:
                return
            time.sleep(0.25)
        raise RuntimeError("daemon did not stop")

    def wallet_balances(wallet: str) -> dict[str, str]:
        b = jcall("getbalances", wallet=wallet)
        mine = b.get("mine", {})
        return {
            "trusted": str(mine.get("trusted", 0)),
            "untrusted_pending": str(mine.get("untrusted_pending", 0)),
            "immature": str(mine.get("immature", 0)),
        }

    def wallet_state(wallet: str) -> dict[str, Any]:
        balances = wallet_balances(wallet)
        unspent = jcall("listunspent", "0", wallet=wallet)
        txs = jcall("listtransactions", "*", "1000", "0", "true", wallet=wallet)
        return {
            "balances": balances,
            "unspent": sorted(
                [
                    {
                        "txid": u["txid"],
                        "vout": int(u["vout"]),
                        "amount": str(u["amount"]),
                        "confirmations": int(u["confirmations"]),
                    }
                    for u in unspent
                ],
                key=lambda x: (x["txid"], x["vout"]),
            ),
            "txids": sorted({str(t["txid"]) for t in txs if "txid" in t}),
        }

    def tx_record_count(wallet: str, txid: str) -> int:
        txs = jcall("listtransactions", "*", "1000", "0", "true", wallet=wallet)
        return sum(1 for t in txs if t.get("txid") == txid)

    def wait_mempool_contains(txid: str, want: bool = True, timeout: int = 20) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            mempool = set(jcall("getrawmempool"))
            if (txid in mempool) == want:
                return
            time.sleep(0.2)
        raise AssertionError(f"mempool condition failed for {txid}, want={want}")

    def wait_confirmations(wallet: str, txid: str, minimum: int, timeout: int = 20) -> dict[str, Any]:
        deadline = time.time() + timeout
        last: dict[str, Any] | None = None
        while time.time() < deadline:
            cp = cli_call("gettransaction", txid, wallet=wallet, check=False)
            if cp.returncode == 0:
                last = json.loads(cp.stdout)
                if int(last.get("confirmations", 0)) >= minimum:
                    return last
            time.sleep(0.2)
        raise AssertionError(f"confirmation condition failed for {txid}: {last}")

    def wait_nonpositive_confirmation(wallet: str, txid: str, timeout: int = 20) -> dict[str, Any]:
        deadline = time.time() + timeout
        last: dict[str, Any] | None = None
        while time.time() < deadline:
            cp = cli_call("gettransaction", txid, wallet=wallet, check=False)
            if cp.returncode == 0:
                last = json.loads(cp.stdout)
                if int(last.get("confirmations", 0)) <= 0:
                    return last
            time.sleep(0.2)
        raise AssertionError(f"transaction did not leave confirmed state: {last}")

    def decode_tx(txid: str) -> dict[str, Any]:
        return jcall("getrawtransaction", txid, "true")

    def tx_input_outpoints(txid: str) -> list[str]:
        tx = decode_tx(txid)
        return [f"{vin['txid']}:{int(vin['vout'])}" for vin in tx.get("vin", []) if "txid" in vin]

    def accounting(txid: str, recipient_address: str) -> dict[str, str | list[str]]:
        tx = decode_tx(txid)
        inputs = Decimal("0")
        input_outpoints: list[str] = []
        for vin in tx["vin"]:
            prev_txid = vin["txid"]
            prev_vout = int(vin["vout"])
            prev = jcall("getrawtransaction", prev_txid, "true")
            inputs += dec(prev["vout"][prev_vout]["value"])
            input_outpoints.append(f"{prev_txid}:{prev_vout}")

        recipient = Decimal("0")
        change = Decimal("0")
        outputs = Decimal("0")
        for vout in tx["vout"]:
            value = dec(vout["value"])
            outputs += value
            address = vout.get("scriptPubKey", {}).get("address")
            if address == recipient_address:
                recipient += value
            elif address:
                mine = jcall("getaddressinfo", address, wallet="alice")
                if bool(mine.get("ismine")):
                    change += value

        fee = inputs - outputs
        if inputs != recipient + change + fee:
            raise AssertionError(
                f"transaction conservation failed: inputs={inputs}, recipient={recipient}, "
                f"change={change}, fee={fee}"
            )
        if recipient <= 0:
            raise AssertionError("recipient output not found")
        if fee < 0:
            raise AssertionError("negative fee")

        return {
            "inputs": str(inputs),
            "recipient": str(recipient),
            "change": str(change),
            "fee": str(fee),
            "input_outpoints": input_outpoints,
        }

    def raw_http_sendtoaddress_without_reading(address: str, amount: str) -> None:
        body = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": "lost-response",
                "method": "sendtoaddress",
                "params": [address, float(amount)],
            },
            separators=(",", ":"),
        ).encode()
        auth = base64.b64encode(f"{rpc_user}:{rpc_pass}".encode()).decode()
        req = (
            f"POST /wallet/alice HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{rpc_port}\r\n"
            f"Authorization: Basic {auth}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        with socket.create_connection(("127.0.0.1", rpc_port), timeout=10) as sock:
            sock.sendall(req)
            sock.shutdown(socket.SHUT_WR)
            time.sleep(0.15)

    def assert_failure_unchanged(
        label: str,
        before: dict[str, Any],
        cp: subprocess.CompletedProcess[str],
        wallet: str = "alice",
    ) -> None:
        if cp.returncode == 0:
            raise AssertionError(f"{label}: operation unexpectedly succeeded")
        after = wallet_state(wallet)
        if before["balances"] != after["balances"]:
            raise AssertionError(f"{label}: balances changed on failed operation")
        before_unspent = {(x["txid"], x["vout"], x["amount"]) for x in before["unspent"]}
        after_unspent = {(x["txid"], x["vout"], x["amount"]) for x in after["unspent"]}
        if before_unspent != after_unspent:
            raise AssertionError(f"{label}: spendable UTXO set changed on failed operation")

    failure_message: str | None = None

    try:
        start()
        cli_call("createwallet", "alice")
        cli_call("createwallet", "bob")

        alice_mining = cli_call("getnewaddress", wallet="alice").stdout.strip()
        bob_receive = cli_call("getnewaddress", wallet="bob").stdout.strip()

        alice_addr = jcall("getaddressinfo", alice_mining, wallet="alice")
        bob_addr = jcall("getaddressinfo", bob_receive, wallet="bob")
        alice_view_of_bob = jcall("getaddressinfo", bob_receive, wallet="alice")
        if not alice_addr.get("ismine") or not bob_addr.get("ismine") or alice_view_of_bob.get("ismine"):
            raise AssertionError("wallet address ownership boundary is inconsistent")

        mined = jcall("generatetoaddress", "110", alice_mining, timeout=600)
        if len(mined) != 110:
            raise AssertionError(f"expected 110 mined blocks, got {len(mined)}")

        chain = jcall("getblockchaininfo")
        baseline = {
            "height": int(chain["blocks"]),
            "tip": str(chain["bestblockhash"]),
            "alice": wallet_state("alice"),
            "bob": wallet_state("bob"),
        }
        if dec(baseline["alice"]["balances"]["trusted"]) <= 0:
            raise AssertionError("Alice has no mature trusted balance after local mining")
        evidence["states"]["baseline"] = baseline

        normal_amount = "1.25000000"
        normal_txid = cli_call("sendtoaddress", bob_receive, normal_amount, wallet="alice").stdout.strip()
        wait_mempool_contains(normal_txid, True)
        normal_accounting = accounting(normal_txid, bob_receive)
        if abs(dec(normal_accounting["recipient"]) - dec(normal_amount)) > SAT:
            raise AssertionError(normal_accounting)
        normal_raw = cli_call("getrawtransaction", normal_txid).stdout.strip()
        normal_records_before = tx_record_count("alice", normal_txid)

        dup1 = cli_call("sendrawtransaction", normal_raw, check=False)
        dup2 = cli_call("sendrawtransaction", normal_raw, check=False)
        normal_records_after = tx_record_count("alice", normal_txid)
        if normal_records_after != normal_records_before:
            raise AssertionError("rebroadcast changed wallet transaction record count")

        confirm_address = cli_call("getnewaddress", wallet="alice").stdout.strip()
        block_hash = jcall("generatetoaddress", "1", confirm_address, timeout=300)[0]
        normal_confirmed = wait_confirmations("alice", normal_txid, 1)
        evidence["transactions"]["normal"] = {
            "txid": normal_txid,
            "accounting": normal_accounting,
            "mempool_seen": True,
            "confirmation_block": block_hash,
            "confirmations": int(normal_confirmed["confirmations"]),
            "rebroadcast_returncodes": [dup1.returncode, dup2.returncode],
            "wallet_record_count_stable": normal_records_after == normal_records_before,
        }

        pre_restart = {
            "alice": wallet_state("alice"),
            "bob": wallet_state("bob"),
            "normal_confirmations": int(jcall("gettransaction", normal_txid, wallet="alice")["confirmations"]),
        }
        stop()
        start()
        load_wallets("alice", "bob")
        post_restart = {
            "alice": wallet_state("alice"),
            "bob": wallet_state("bob"),
            "normal_confirmations": int(jcall("gettransaction", normal_txid, wallet="alice")["confirmations"]),
        }
        if pre_restart != post_restart:
            raise AssertionError("clean restart changed wallet state")
        evidence["states"]["clean_restart"] = post_restart

        before_invalid = wallet_state("alice")
        invalid = cli_call("sendtoaddress", "not-a-wam-address", "0.5", wallet="alice", check=False)
        assert_failure_unchanged("invalid destination", before_invalid, invalid)

        before_insufficient = wallet_state("alice")
        insufficient = cli_call("sendtoaddress", bob_receive, "999999999", wallet="alice", check=False)
        assert_failure_unchanged("insufficient funds", before_insufficient, insufficient)

        mempool_before = set(jcall("getrawmempool"))
        wallet_txids_before = set(wallet_state("alice")["txids"])
        raw_http_sendtoaddress_without_reading(bob_receive, "0.50000000")

        deadline = time.time() + 20
        lost_txid: str | None = None
        while time.time() < deadline:
            mempool_after = set(jcall("getrawmempool"))
            wallet_txids_after = set(wallet_state("alice")["txids"])
            new = (mempool_after - mempool_before) & (wallet_txids_after - wallet_txids_before)
            if len(new) == 1:
                lost_txid = next(iter(new))
                break
            if len(new) > 1:
                raise AssertionError(f"lost-response request created multiple transactions: {sorted(new)}")
            time.sleep(0.2)
        if not lost_txid:
            raise AssertionError("lost-response request could not be reconciled to one wallet/mempool tx")

        lost_before_restart = jcall("gettransaction", lost_txid, wallet="alice")
        if tx_record_count("alice", lost_txid) != 1:
            raise AssertionError("lost-response transaction is not represented exactly once in wallet history")

        stop()
        start()
        load_wallets("alice", "bob")
        lost_after_restart = jcall("gettransaction", lost_txid, wallet="alice")
        wait_mempool_contains(lost_txid, True)
        if tx_record_count("alice", lost_txid) != 1:
            raise AssertionError("restart duplicated lost-response wallet accounting")
        if lost_before_restart["txid"] != lost_after_restart["txid"]:
            raise AssertionError("lost-response transaction identity changed after restart")

        evidence["transactions"]["unknown_broadcast_outcome"] = {
            "txid": lost_txid,
            "response_intentionally_unread": True,
            "reconciled_via_wallet_and_mempool": True,
            "wallet_record_count": 1,
            "survived_restart": True,
        }

        bob_two = cli_call("getnewaddress", wallet="bob").stdout.strip()
        bob_three = cli_call("getnewaddress", wallet="bob").stdout.strip()
        spend_a = cli_call("sendtoaddress", bob_two, "0.40000000", wallet="alice").stdout.strip()
        spend_b = cli_call("sendtoaddress", bob_three, "0.30000000", wallet="alice").stdout.strip()
        inputs_a = set(tx_input_outpoints(spend_a))
        inputs_b = set(tx_input_outpoints(spend_b))
        if inputs_a & inputs_b:
            raise AssertionError(f"two wallet sends reused the same input prevout: {sorted(inputs_a & inputs_b)}")
        evidence["transactions"]["pending_spend_pair"] = {
            "txids": [spend_a, spend_b],
            "input_sets_disjoint": True,
        }

        jcall("generatetoaddress", "1", confirm_address, timeout=300)
        for txid in (lost_txid, spend_a, spend_b):
            wait_confirmations("alice", txid, 1)

        mature = jcall("listunspent", "1", "9999999", wallet="alice")
        if not mature:
            raise AssertionError("no confirmed spendable UTXO for rejection fixture")
        selected = mature[0]
        reject_outpoint = f"{selected['txid']}:{int(selected['vout'])}"
        rejection_before = wallet_state("alice")
        rejection_address = cli_call("getnewaddress", wallet="bob").stdout.strip()
        raw_zero_fee = cli_call(
            "createrawtransaction",
            json.dumps([{"txid": selected["txid"], "vout": int(selected["vout"])}]),
            json.dumps([{rejection_address: selected["amount"]}]),
        ).stdout.strip()
        signed = jcall("signrawtransactionwithwallet", raw_zero_fee, wallet="alice")
        if not signed.get("complete"):
            raise AssertionError("zero-fee rejection fixture could not be signed locally")
        rejected = cli_call("sendrawtransaction", signed["hex"], check=False)
        if rejected.returncode == 0:
            raise AssertionError("zero-fee rejection fixture unexpectedly entered mempool")
        rejection_after = wallet_state("alice")
        if rejection_before["balances"] != rejection_after["balances"]:
            raise AssertionError("mempool rejection changed wallet balances")
        if reject_outpoint not in {f"{u['txid']}:{u['vout']}" for u in rejection_after["unspent"]}:
            raise AssertionError("rejected transaction made its input unavailable")

        stop()
        start()
        load_wallets("alice", "bob")
        rejection_restart = wallet_state("alice")
        if reject_outpoint not in {f"{u['txid']}:{u['vout']}" for u in rejection_restart["unspent"]}:
            raise AssertionError("rejected transaction input did not survive restart as spendable")
        evidence["transactions"]["rejected_zero_fee"] = {
            "input": reject_outpoint,
            "node_returncode": rejected.returncode,
            "input_remains_spendable": True,
            "survived_restart": True,
        }

        normal_before_reorg = jcall("gettransaction", normal_txid, wallet="alice")
        if int(normal_before_reorg["confirmations"]) <= 0:
            raise AssertionError("normal transaction not confirmed before reorg test")
        normal_block = str(normal_before_reorg["blockhash"])
        cli_call("invalidateblock", normal_block)
        normal_reorged = wait_nonpositive_confirmation("alice", normal_txid)

        cli_call("reconsiderblock", normal_block)
        normal_reconfirmed = wait_confirmations("alice", normal_txid, 1)
        if tx_record_count("alice", normal_txid) != 1:
            raise AssertionError("reorg/reconfirmation duplicated wallet history")

        evidence["transactions"]["reorg"] = {
            "txid": normal_txid,
            "block": normal_block,
            "confirmed_before": int(normal_before_reorg["confirmations"]),
            "after_invalidate": int(normal_reorged.get("confirmations", 0)),
            "after_reconsider": int(normal_reconfirmed["confirmations"]),
            "wallet_record_count": 1,
            "duplicate_accounting": False,
        }

        rescan_before = wallet_state("alice")
        rescan_result = jcall("rescanblockchain", "0", wallet="alice", timeout=600)
        rescan_after = wallet_state("alice")
        if rescan_before["balances"] != rescan_after["balances"]:
            raise AssertionError("rescan changed wallet balances")
        if set(rescan_before["txids"]) != set(rescan_after["txids"]):
            raise AssertionError("rescan changed wallet transaction identity set")
        evidence["states"]["rescan"] = {
            "result": rescan_result,
            "balances_preserved": True,
            "transaction_identity_set_preserved": True,
        }

        cli_call("createwallet", "watcher", "true", "true")
        descriptor_info = jcall("getdescriptorinfo", f"addr({bob_receive})")
        imported = jcall(
            "importdescriptors",
            json.dumps([{"desc": descriptor_info["descriptor"], "timestamp": 0, "active": False}]),
            wallet="watcher",
            timeout=600,
        )
        if not imported or not bool(imported[0].get("success")):
            raise AssertionError(f"watch-only descriptor import failed: {imported}")
        watcher_unspent = jcall("listunspent", "0", "9999999", wallet="watcher")
        watched = [u for u in watcher_unspent if u.get("address") == bob_receive]
        if not watched:
            raise AssertionError("watch-only wallet did not discover confirmed Bob outputs")
        if any(bool(u.get("spendable")) for u in watched):
            raise AssertionError("watch-only imported outputs unexpectedly marked spendable")
        evidence["states"]["watch_only"] = {
            "descriptor_imported": True,
            "observed_outputs": len(watched),
            "all_observed_outputs_nonspendable": True,
        }

        psbt_address = cli_call("getnewaddress", wallet="bob").stdout.strip()
        psbt = jcall(
            "walletcreatefundedpsbt",
            "[]",
            json.dumps([{psbt_address: 0.1}]),
            "0",
            "{}",
            "true",
            wallet="alice",
        )["psbt"]

        cli_call("encryptwallet", wallet_passphrase, wallet="alice")
        locked_sign = cli_call("walletprocesspsbt", psbt, "true", wallet="alice", check=False)
        if locked_sign.returncode == 0:
            locked_result = json.loads(locked_sign.stdout)
            if locked_result.get("complete"):
                raise AssertionError("locked encrypted wallet unexpectedly completed signing")

        cli_call("walletpassphrase", wallet_passphrase, "60", wallet="alice")
        unlocked_sign = jcall("walletprocesspsbt", psbt, "true", wallet="alice")
        if not unlocked_sign.get("complete"):
            raise AssertionError("unlocked encrypted wallet failed to complete local signing")
        cli_call("walletlock", wallet="alice")
        evidence["states"]["wallet_encryption"] = {
            "locked_signing_complete": False,
            "unlocked_signing_complete": True,
            "secret_values_recorded": False,
        }

        backup_path = backup_dir / "alice-wallet.bak"
        backup_balance = wallet_balances("alice")
        backup_txids = set(wallet_state("alice")["txids"])
        cli_call("backupwallet", str(backup_path), wallet="alice")
        if not backup_path.is_file():
            raise AssertionError("backupwallet did not create the requested local backup")

        cli_call("unloadwallet", "alice")
        restored = jcall("restorewallet", "alice_restore", str(backup_path))
        if restored.get("name") != "alice_restore":
            raise AssertionError(restored)
        restore_balance = wallet_balances("alice_restore")
        restore_txids = set(wallet_state("alice_restore")["txids"])
        if backup_balance != restore_balance:
            raise AssertionError("restored wallet balance differs from backup source")
        if not backup_txids.issubset(restore_txids):
            raise AssertionError("restored wallet is missing transaction history from backup")
        evidence["states"]["backup_restore"] = {
            "balance_preserved": True,
            "source_transaction_ids_present": True,
            "backup_path_recorded": False,
        }

        debug_log = datadir / "regtest" / "debug.log"
        log_text = debug_log.read_text(encoding="utf-8", errors="replace") if debug_log.exists() else ""
        if rpc_pass in log_text:
            raise AssertionError("generated RPC password leaked into debug.log")
        if wallet_passphrase in log_text:
            raise AssertionError("generated wallet passphrase leaked into debug.log")

        evidence["invariants"] = {
            "address_ownership_boundary_correct": True,
            "normal_transaction_value_conservation": True,
            "change_accounted_once": True,
            "rebroadcast_does_not_duplicate_wallet_accounting": True,
            "clean_restart_preserves_wallet_state": True,
            "invalid_destination_fails_without_state_mutation": True,
            "insufficient_funds_fails_without_state_mutation": True,
            "unknown_broadcast_result_is_reconcilable_without_second_payment": True,
            "unknown_broadcast_transaction_survives_restart_once": True,
            "pending_wallet_sends_do_not_reuse_same_prevout": True,
            "rejected_transaction_does_not_consume_wallet_utxo": True,
            "rejected_transaction_recovery_survives_restart": True,
            "confirmed_transaction_reorgs_to_nonconfirmed_state": True,
            "reconfirmation_does_not_duplicate_wallet_history": True,
            "rescan_preserves_balance_and_transaction_identities": True,
            "watch_only_import_discovers_nonspendable_outputs": True,
            "locked_encrypted_wallet_does_not_complete_signing": True,
            "unlocked_encrypted_wallet_can_complete_signing": True,
            "backup_restore_preserves_balance_and_history": True,
            "secret_log_scan_passes": True,
        }
        evidence["coverage"] = {
            "watch_only_import": "PASS",
            "manual_wallet_database_corruption": "UNTESTED_OUTSIDE_LOCKED_SCOPE",
            "public_network_behavior": "UNTESTED_OUTSIDE_LOCKED_SCOPE",
            "silent_payments_bip352": "NOT_APPLICABLE_TO_THIS_PHASE_SEPARATE_WSP_HARNESS",
        }
        evidence["result"] = "PASS"
        evidence["classification"] = "WALLET_TRANSACTION_STATE_INVARIANTS_PASS_ON_ISOLATED_REGTEST"

        serial = json.dumps(evidence, sort_keys=True)
        if rpc_pass in serial or wallet_passphrase in serial:
            raise AssertionError("secret material present in evidence")

    except Exception as exc:
        evidence["result"] = "FAIL"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        try:
            stop()
        except Exception:
            pass
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(datadir, ignore_errors=True)
        shutil.rmtree(backup_dir, ignore_errors=True)

    print("isolated WAM wallet transaction/state regression: PASS")
    print(f"evidence: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
