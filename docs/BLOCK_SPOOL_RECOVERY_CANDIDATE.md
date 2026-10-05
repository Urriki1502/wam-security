# Block-spool recovery fix candidate

Target reviewed revision:

`wamcoin-core-dev/wam-coin@bb6d5214f2f5de3b7464587cc1b2949d221dcd18`

This document is a local defensive design candidate. It does not modify WAM
upstream. The executable state model lives in
`src/wam_security/block_spool/model.py`.

## Confirmed recovery gap

The current block spool solves one durability problem: raw solved-block bytes
survive a process restart when the node was unavailable.

The remaining gap is that raw-block durability and pool-accounting durability
are not the same state.

At the reviewed revision:

- the spool entry stores height, block hash, raw hex, worker and found time;
- an accepted recovered block emits a new `block` object that does not carry
  the complete original share/accounting context;
- `ShareProcessor.recordBlock()` needs fields including
  `distributableValue`, `coinbaseValue` and `devFeeAmount`;
- duplicate/inconclusive-like recovery settles the spool without necessarily
  creating the block-accounting transition;
- server startup begins `drainSpool()` before registering the normal
  `jobManager.on('block', ...)` accounting listener.

Therefore a solved block can become known to the node while the pool cannot
reconstruct its economic state from the current spool entry alone.

## Required invariant

> Once a solved block crosses the durability barrier, enough information must
> survive to determine both its node status and its economic/accounting status
> after any process restart, without guessing and without applying accounting
> twice.

## Chosen state model

The smallest model that satisfies the invariant has two durable components.

### 1. Recovery entry

Written before submission:

```text
RecoveryEntry {
    block_hash
    raw_block_hex
    original_share {
        height
        worker
        difficulty
        jobId
        distributableValue
        coinbaseValue
        devFeeAmount
        time
        ...other original share metadata
    }
    phase
}
```

Phases:

```text
SPOOLED
  |
  | node accepted, or duplicate-like + block is active
  v
ACCEPTED_UNACCOUNTED
  |
  | atomic account_once(block_hash)
  v
ACCOUNTED

SPOOLED -- duplicate-like + block inactive --> LOST_RACE
SPOOLED -- definitive validation refusal --> REFUSED
SPOOLED -- RPC/no answer -----------------> SPOOLED
```

No terminal state is inferred from transport failure.

### 2. Idempotent economic transition

Accounting is keyed by `block_hash`.

The target implementation must make these effects visible as one durable
transition:

- winning share accounted exactly once;
- pending block/accounting record created exactly once;
- accounting idempotency marker committed.

A crash before that transaction means none of the three is committed. A lost
reply after commit is safe because retrying the same block hash is a no-op.

The executable reference model represents this with
`AccountingLedger.apply_once()`.

## Duplicate / inconclusive handling

`duplicate`, `inconclusive` and `duplicate-inconclusive` are not sufficient
on their own to decide the pool-accounting outcome after restart.

For a recovery entry, query the stored block hash:

- block is on the active chain -> treat as accepted and run idempotent accounting;
- block is known but inactive/orphaned -> settle as lost race/orphan, no payout;
- block status cannot be established -> keep the recovery entry and retry later.

This avoids treating "the node has seen these bytes" as "this block should be
paid".

## Durability barrier

The model deliberately makes successful recovery-entry persistence a
precondition to submission.

That is stronger than current WAM behavior, which submits even if spooling
fails. The tradeoff is explicit:

- submitting without any durable recovery record preserves race latency but
  cannot guarantee crash recovery/accounting;
- refusing to cross the submission boundary without durability preserves the
  invariant but can sacrifice a block if storage is unavailable.

If the maintainer wants both availability and the stronger invariant, the next
implementation step is a second durable fallback (for example an fsync'd local
spool) rather than silently submitting with no recovery state.

## Integration points in WAM

A future upstream patch should remain small and local to the pool.

### `pool/lib/jobManager.js`

- spool the complete original share/accounting context, not a partial event;
- keep the entry live across unknown RPC outcomes;
- classify duplicate-like results only after checking the stored block hash
  against active-chain state;
- do not remove an accepted entry until the economic transition is known durable.

### `pool/lib/shareProcessor.js`

Add an idempotent block-accounting transition keyed by block hash.

The exact Redis mechanism can be Lua, WATCH/MULTI or another atomic primitive,
but a plain check-then-write sequence is not sufficient if concurrent workers
can execute it.

### `pool/server.js`

Recovery must not depend on a transient event emitted before the accounting
listener exists. Either:

- register all durable accounting hooks before the first drain; or
- have recovery call the idempotent accounting transition directly.

The second is stronger because the durable state machine no longer depends on
event-listener timing.

## Deterministic regression matrix

The model tests cover:

1. crash after spool write before submit;
2. crash after node accept before state update;
3. crash after accepted state before accounting;
4. restart returns `duplicate`;
5. restart returns `inconclusive`;
6. restart returns `duplicate-inconclusive`;
7. repeated drain after accounting;
8. accounting write failure before commit;
9. accounting acknowledgement loss after commit;
10. durable spool write failure;
11. malformed/incomplete recovery entry;
12. final validation refusal;
13. RPC/no-answer remains retryable.

## What this candidate does not claim

The reference model does not yet patch WAM upstream and does not model the
full Redis command sequence used by the production pool.

It establishes the recovery state machine and crash invariants first. An
upstream patch should be reviewed against this model and then exercised with
Redis-backed integration tests before merge.
