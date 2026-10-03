# V4 — Money Safety

V4 treats payout safety as a distributed-systems problem spanning the wallet,
RPC transport and Redis accounting state.

## Core invariants

1. One payout intent receives one signed transaction identity before the first network side effect.
2. Every retry broadcasts the same raw transaction; transport failure never creates a new spend.
3. An ambiguous response retains raw transaction + txid until reconciliation.
4. Owed balances are never cleared until that transaction identity is observed.
5. Balance deduction, lifetime-paid increment, payment journal append and active-intent removal commit atomically.
6. An unresolved intent blocks another payout run across process restarts, not only inside one process.
7. Money RPCs do not inherit generic daemon failover.
8. A dedicated named payout wallet and explicit recipient/value/fee/daily limits are mandatory.
9. New matured credit arriving while a payout is in flight is preserved.
10. Recovery fails closed: uncertainty delays payment rather than guessing.

## Current WAM target

V4 audits WAM commit `012f3d38570de232a750458e9cf6c91e985db6a1`, which is also the current
`main` head when V4 was started on 2026-10-03.

The present pool has several useful safeguards already: process-local overlap
guarding, an inflight marker, payout batch caps, wallet reserve checks and a
named mainnet payout wallet. V4 focuses on the remaining distributed failure
boundaries.

## Evidence layers

- source-semantic money audit
- deterministic exactly-once reference model
- crash/restart fault matrix
- real Redis Lua atomic-commit integration test
- actual patched `wamd` regtest raw-transaction idempotence probe

All node execution is isolated regtest. V4 does not send coins on WAM mainnet or
interact with public pool infrastructure.
