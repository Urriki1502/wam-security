# V2 Evidence Index

V2 is stacked on the V1 operational baseline and adds adversarial runtime assurance.

## Audited WAM snapshot

- Repository: `wamcoin-core-dev/wam-coin`
- Pinned commit: `012f3d38570de232a750458e9cf6c91e985db6a1`
- The V2 runtime audit uses the same pinned source as V1 so new runtime results are comparable to the baseline.

## V2 security commits

- `032472c01784fc463bf1c09a9068f7de4524f543` — protocol/resource/fault/fuzz models, runtime source audit and tests
- `6d8d7fe98997c347a270abd992f89ab6bc6a9ddd` — deterministic adversarial CI matrix and runtime regression gate
- `c6769ae186ec0ef2d7859d1835c9a02ffcd6d0ba` — fail-closed dependency watchdog and restart circuit budget

## Verified runtime properties

### Unit and invariant suite
- **33 tests PASS**
- includes all V1 tests plus V2 protocol, resource, runtime-audit, payout-fault, fuzz-smoke and watchdog tests

### Payout fault injection
- **21 crash/outcome scenarios PASS**
- RPC outcomes: acknowledged, timeout before network acceptance, timeout after network acceptance
- crash points cover construction, durable persistence, network acceptance, RPC result, pre-commit and post-commit boundaries
- recovery preserves one transaction identity and at most one durable balance commit

### Deterministic fuzz matrix
Main V2 CI matrix:

- `0x57414D` — 2,500 cases PASS
- `0x352` — 2,500 cases PASS
- `0xC0FFEE` — 2,500 cases PASS
- `0xDEADBEEF` — 2,500 cases PASS

The unit/fault job additionally executes a 500-case seed run. Fuzzing is local byte/state generation only; it opens no attack sockets.

### Runtime source regression
The pinned WAM source retains the reviewed baseline controls checked by V2:

- Stratum pre-parse buffer bound
- Stratum message-rate limit
- global connection limit
- per-IP connection limit
- authorization timeout
- API read-only method gate
- bounded API cache
- daemon RPC timeout

This is a regression claim, not a proof that these values are globally optimal.

## GitHub Actions evidence

### V2 functional run
- Run ID: `37088771680`
- Head: `c6769ae186ec0ef2d7859d1835c9a02ffcd6d0ba`
- Result: **SUCCESS**
- Jobs: unit/fault matrix, runtime regression, four independent fuzz-seed jobs

### V1 regression on V2 head
- Run ID: `37088771687`
- Head: `c6769ae186ec0ef2d7859d1835c9a02ffcd6d0ba`
- Result: **SUCCESS**

## Interpretation

V2 makes runtime safety assumptions executable and replayable. It does not authorize testing public infrastructure and it does not publish unresolved exploit material. Higher assurance for consensus internals, sanitizers, independent DGW/RandomX models and deeper reorg testing belongs to V3.
