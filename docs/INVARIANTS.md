# V1 Security Invariants

These are release-blocking properties, not aspirational guidelines.

## Monetary

- `supply(height) <= 22,000,000 WAM` for every height.
- block 0 mints only the 2,000,000 WAM premine.
- heights 1..200,000 mint 50 WAM per block; halving boundaries are exact.
- treasury is active only at heights 1..400,000.
- `miner subsidy + treasury amount == block subsidy` at every height.
- lifetime treasury from block subsidy is exactly 750,000 WAM under current consensus constants.
- subsidy becomes zero after the final non-zero block at height 6,600,000.

## Payout / money movement

For one logical payout intent:

- at most one economic transaction may settle it;
- a timeout is **unknown**, never proof of non-execution;
- unknown state must fail closed;
- transaction identity must be persisted before broadcast;
- retry must reuse the same transaction identity;
- balances may be cleared only after that transaction is known to the wallet/mempool/chain.

## P2P

- claimed chainwork must not be trusted as equivalent to verified RandomX work at a security boundary;
- malformed or insufficient-work headers cannot bypass contextual consensus validation;
- anti-DoS adaptations required by RandomX must be tested independently of block-validity tests.

## Supply chain

- security reports identify the exact audited WAM source revision;
- third-party CI actions should be pinned to immutable commit SHAs;
- release dependency graphs should be lockfile/reproducible-build controlled;
- no release gate is considered evidence if its definition can silently change in the same unreviewed change.
