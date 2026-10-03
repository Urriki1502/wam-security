#!/usr/bin/env python3
"""Static source-contract map for WAM wallet integration security.

This runner reads the exact reviewed WAM repository and the exact Bitcoin Core
v28.1 tree materialized and patched by that repository. It does not mutate
wallet databases, use private keys, or contact public infrastructure.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess

WAM_COMMIT = "bd71b0bd645286a3867dad6b2bfefd911ec8a5b6"
UPSTREAM_TAG = "v28.1"


def read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        raise AssertionError(f"missing source path: {rel}")
    return path.read_text(encoding="utf-8")


def git_head(root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def body(text: str, marker: str, limit: int = 18000) -> str:
    pos = text.find(marker)
    if pos < 0:
        raise AssertionError(f"missing source marker: {marker}")
    return text[pos : pos + limit]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("--patched-tree", type=Path, required=True)
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/wallet-state-static.json"),
    )
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[1]
    wam = args.wam_root.resolve()
    core = args.patched_tree.resolve()

    wam_head = git_head(wam)
    if wam_head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {wam_head!r}, expected {args.expected_commit}")

    fetch_upstream = read(wam, "scripts/fetch-upstream.sh")
    patcher = read(wam, "scripts/patch_upstream.py")

    wallet_cpp = read(core, "src/wallet/wallet.cpp")
    wallet_h = read(core, "src/wallet/wallet.h")
    walletutil = read(core, "src/wallet/walletutil.cpp")
    spend_cpp = read(core, "src/wallet/spend.cpp")
    receive_cpp = read(core, "src/wallet/receive.cpp")
    rpc_spend = read(core, "src/wallet/rpc/spend.cpp")
    rpc_wallet = read(core, "src/wallet/rpc/wallet.cpp")
    rpc_backup = read(core, "src/wallet/rpc/backup.cpp")
    walletdb = read(core, "src/wallet/walletdb.cpp")
    sqlite = read(core, "src/wallet/sqlite.cpp")

    commit_tx = body(wallet_cpp, "void CWallet::CommitTransaction", 6500)
    rescan = body(wallet_cpp, "int64_t CWallet::RescanFromTime", 3500)
    sync_tx = body(wallet_cpp, "void CWallet::SyncTransaction", 4500)
    create_tx = body(spend_cpp, "static util::Result<CreatedTransactionResult> CreateTransactionInternal", 22000)
    select_coins = body(spend_cpp, "util::Result<SelectionResult> SelectCoins", 16000)
    balances = body(receive_cpp, "Balance GetBalance", 7000)
    backup = body(wallet_cpp, "bool CWallet::BackupWallet", 1800)

    add_pos = commit_tx.find("AddToWallet(")
    submit_pos = commit_tx.find("SubmitTxMemoryPoolAndRelay")
    fail_pos = commit_tx.find("Transaction cannot be broadcast immediately")

    checks = {
        "locked_wam_commit_matches": wam_head == args.expected_commit,
        "pinned_upstream_is_bitcoin_core_v28_1":
            'UPSTREAM_TAG="${UPSTREAM_TAG:-v28.1}"' in fetch_upstream,
        "wallet_is_upstream_core_with_wam_overlay":
            "WAM-023" in patcher
            and "src/wallet/walletutil.cpp" in patcher
            and "WAM-024" in patcher
            and "src/wallet/wallet.h" in patcher,
        "wam_bip44_coin_type_is_applied":
            "wam::WAM_BIP44_COIN_TYPE" in walletutil,
        "wam_fallback_fee_policy_is_applied":
            "WAM: a chain on its first day has no fee market" in wallet_h,
        "transaction_construction_present":
            "CreateTransactionInternal" in spend_cpp
            and "CreateTransaction(" in spend_cpp,
        "utxo_discovery_and_coin_selection_present":
            "CoinsResult AvailableCoins" in spend_cpp
            and "SelectCoins(" in select_coins,
        "balance_is_wallet_state_derived":
            "Balance GetBalance" in receive_cpp
            and "GetAvailableCredit" in balances,
        "wallet_commit_persists_before_broadcast":
            0 <= add_pos < submit_pos,
        "broadcast_failure_is_retained_for_recovery":
            submit_pos >= 0
            and fail_pos > submit_pos
            and "instead delete wtx from the wallet and return failure" in commit_tx,
        "restart_load_path_present":
            "DBErrors CWallet::LoadWallet" in wallet_cpp
            and "WalletBatch(GetDatabase()).LoadWallet(this)" in wallet_cpp,
        "chain_and_mempool_notification_path_present":
            "SyncTransaction(" in sync_tx
            and "TxStateInMempool" in wallet_cpp
            and "TxStateConfirmed" in wallet_cpp
            and "TxStateInactive" in wallet_cpp,
        "rescan_supported":
            "ScanForWalletTransactions" in rescan
            and '"rescanblockchain"' in rpc_wallet,
        "wallet_encryption_locking_supported":
            "bool CWallet::IsLocked()" in wallet_cpp
            and '"walletpassphrase"' in rpc_wallet,
        "backup_restore_supported":
            "return GetDatabase().Backup(strDest);" in backup
            and '"backupwallet"' in rpc_backup
            and '"restorewallet"' in rpc_backup,
        "descriptor_wallet_sqlite_supported":
            "DatabaseFormat::SQLITE" in walletdb
            and "SQLiteDatabase::Backup" in sqlite,
        "rpc_transaction_creation_uses_wallet_core":
            "CreateTransaction(wallet" in rpc_spend
            and "CommitTransaction" in rpc_spend,
    }

    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise AssertionError("wallet source contract mismatch: " + ", ".join(failed))

    source_map = {
        "wallet_creation_loading": [
            "src/wallet/wallet.cpp::LoadWallet",
            "src/wallet/rpc/wallet.cpp",
        ],
        "key_address_generation": [
            "src/wallet/walletutil.cpp",
            "src/wallet/scriptpubkeyman.cpp",
        ],
        "utxo_discovery": ["src/wallet/spend.cpp::AvailableCoins"],
        "balance": ["src/wallet/receive.cpp::GetBalance"],
        "transaction_construction": [
            "src/wallet/spend.cpp::CreateTransactionInternal",
            "src/wallet/spend.cpp::CreateTransaction",
        ],
        "coin_selection": ["src/wallet/spend.cpp::SelectCoins"],
        "fee_change": ["src/wallet/spend.cpp::CreateTransactionInternal"],
        "signing": [
            "src/wallet/spend.cpp::CreateTransactionInternal",
            "src/wallet/rpc/spend.cpp",
        ],
        "broadcast_commit": ["src/wallet/wallet.cpp::CommitTransaction"],
        "persistence": [
            "src/wallet/wallet.cpp::AddToWallet",
            "src/wallet/walletdb.cpp",
            "src/wallet/sqlite.cpp",
        ],
        "mempool_chain_notifications": [
            "src/wallet/wallet.cpp::SyncTransaction",
            "src/wallet/wallet.cpp::AddToWalletIfInvolvingMe",
        ],
        "confirmation_reorg_state": ["src/wallet/wallet.cpp"],
        "rescan": [
            "src/wallet/wallet.cpp::RescanFromTime",
            "src/wallet/wallet.cpp::ScanForWalletTransactions",
        ],
        "locking_encryption": ["src/wallet/wallet.cpp"],
        "backup_restore": [
            "src/wallet/wallet.cpp::BackupWallet",
            "src/wallet/rpc/backup.cpp",
        ],
    }

    evidence = {
        "schema": "wam-security-wallet-state-static/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "wam_commit": wam_head,
            "upstream": f"bitcoin/bitcoin {UPSTREAM_TAG}",
            "wam_security_head": os.environ.get("SECURITY_TARGET_SHA") or git_head(repo),
        },
        "scope": {
            "static_source_only": True,
            "database_tampering": False,
            "real_wallets": False,
            "real_keys": False,
            "public_network": False,
        },
        "source_map": source_map,
        "checks": checks,
        "important_semantics": {
            "commit_order": (
                "CWallet::CommitTransaction writes the wallet transaction first, marks "
                "spent inputs dirty, and only then attempts mempool submission."
            ),
            "broadcast_failure": (
                "Immediate broadcast failure is logged but the wallet transaction remains "
                "persisted for recovery/resubmission; callers must not assume automatic rollback."
            ),
            "wam_specific_wallet_changes": (
                "The reviewed WAM overlay changes the BIP44 coin-type derivation and the "
                "default fallback fee policy; the rest of the wallet lifecycle is inherited "
                "from the pinned Bitcoin Core v28.1 tree."
            ),
        },
        "result": "PASS",
        "classification": "WALLET_SOURCE_CONTRACT_MAPPED",
    }

    out = args.out if args.out.is_absolute() else repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("wallet source-contract map: PASS")
    print(f"evidence: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
