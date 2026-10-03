# WAM Wallet Integration Security

## Locked target

- WAM repository: wamcoin-core-dev/wam-coin
- WAM commit: bd71b0bd645286a3867dad6b2bfefd911ec8a5b6
- Upstream wallet baseline: Bitcoin Core v28.1
- Scope: local/open-source regression validation only

This phase validates the wallet already inherited by WAM. It does not implement
a replacement wallet and it does not exercise mainnet, public testnet, public
nodes, real funds, real user wallets, or real secrets.

## Source architecture

The locked WAM source materializes a pinned Bitcoin Core v28.1 tree and applies
the WAM overlay. The wallet lifecycle therefore remains primarily upstream Core
code.

WAM-specific wallet changes in the locked target include:

1. WAM-023: descriptor derivation uses WAM's registered BIP-44 coin type on
   mainnet instead of Bitcoin's coin type 0.
2. WAM-024: a non-zero fallback fee is enabled so a new WAM chain with no fee
   history can still construct transactions.

The integration harness maps and checks these wallet boundaries:

- creation/loading: src/wallet/wallet.cpp and src/wallet/rpc/wallet.cpp
- address/key derivation: src/wallet/walletutil.cpp and script-pubkey managers
- UTXO discovery and coin selection: src/wallet/spend.cpp
- balance computation: src/wallet/receive.cpp
- transaction construction, fee and change: src/wallet/spend.cpp
- commit/broadcast: CWallet::CommitTransaction
- persistence: walletdb.cpp and sqlite.cpp
- confirmation, mempool and reorg notifications: wallet.cpp
- rescan: RescanFromTime and ScanForWalletTransactions
- encryption/locking: wallet.cpp and wallet RPC
- backup/restore: BackupWallet, backupwallet and restorewallet

## Important broadcast semantic

CWallet::CommitTransaction persists a transaction in the wallet and marks its
spent inputs dirty before trying to submit it to the mempool.

If immediate broadcast fails, the transaction is retained for later
recovery/resubmission. A caller therefore must not interpret a missing RPC
response as proof that no wallet transaction was created. The native harness
contains an isolated response-loss regression specifically for this boundary.

## Native regression model

The native job starts one local wamd instance with:

- regtest only;
- a temporary datadir;
- peer listening disabled;
- DNS/fixed seeds disabled;
- automatic outbound connections disabled;
- no persisted mempool;
- locally generated disposable RPC credentials.

It creates disposable alice, bob and watch-only wallets and verifies:

- mature local funding and balance state;
- normal Alice to Bob send;
- input/output/fee/change conservation;
- duplicate rebroadcast does not duplicate wallet accounting;
- clean restart preserves state;
- invalid address and insufficient-funds failures do not mutate wallet state;
- a deliberately discarded successful RPC response can be reconciled to one
  wallet transaction and survives restart without duplicate accounting;
- concurrent pending wallet sends do not directly reuse the same prevout;
- deterministic zero-fee mempool rejection leaves its input spendable;
- confirmed to reorged/unconfirmed to confirmed lifecycle;
- rescan preserves balances and transaction identities;
- watch-only descriptor import discovers the expected outputs, keeps `private_keys_enabled=false`, and cannot complete signing for those outputs;
- encrypted/locked wallet cannot complete signing while an explicitly unlocked
  wallet can;
- local backup/restore preserves balance and transaction history;
- generated RPC and wallet passphrases do not appear in daemon logs or evidence.

## Scope boundaries

The harness deliberately does not:

- alter SQLite/BerkeleyDB records;
- forge persisted wallet metadata;
- export private keys or seeds;
- use any public node or network;
- test BIP-352 Silent Payments. WSP-1 remains a separate protocol/integration
  harness and should be connected only after the base WAM wallet lifecycle is
  validated.

Any behavior that would require those actions is recorded as
UNTESTED_OUTSIDE_LOCKED_SCOPE rather than guessed.

## CI closure

The wallet phase is not considered complete merely because the workflow is
green. Closure requires:

1. the static source map to match the exact locked WAM source;
2. the native isolated-regtest evidence to pass the wallet money/state
   invariants;
3. the normal Security V1 pull-request workflow to remain green;
4. evidence artifacts to contain no wallet secret material;
5. any failed invariant to remain reproducible and narrowly classified instead
   of being hidden or converted into an expected pass.


### Descriptor watch-only note

For the pinned Bitcoin Core v28.1 descriptor wallet, `DescriptorScriptPubKeyMan::IsMine()`
classifies scripts present in its descriptor map as `ISMINE_SPENDABLE`, so the
`listunspent.spendable` field alone is not used as proof of private-key
ownership in this harness. The security assertion is made at the signing
boundary instead: the disposable wallet is created with private keys disabled,
the imported output is discovered, and an actual wallet signing attempt must
not complete.
