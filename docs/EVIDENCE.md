# V1 Evidence Index

This file records the evidence that made the initial WAM Security V1 baseline operational.

## Audited upstream

- Repository: `wamcoin-core-dev/wam-coin`
- Pinned commit: `012f3d38570de232a750458e9cf6c91e985db6a1`
- Pin record: `upstream.lock.json`

The CI job checks out this exact commit in detached-HEAD mode and asserts the resulting HEAD equals the lock value before auditing it.

## Security framework commits

- `12dd18bb05da94c096a657a276447695ce119cc6` — threat model, invariants, roadmap, upstream lock
- `40cd47e69f3705c1ace04b119c50ca1e2dc06db7` — independent monetary/payment models and source auditor
- `3eaea8417d0f51075700843273972b23bb20d937` — invariant/unit tests
- `9f448d36fdaf47d58571477a04b59c18410e61de` — pinned-source CI and baseline enforcement
- `7dad542e5a3081a9e3f6321c9e2fb6dd677d9b04` — consensus drift detector, pre-sync invariant model, disclosure policy

## Local verification

Before push, the branch passed:

- Python compile checks
- 17 unit / invariant tests
- monetary boundary tests at genesis, treasury sunset, halving boundaries and terminal emission
- payout unknown-state / deterministic-identity safety tests
- source-auditor detection tests
- consensus-constant drift tests
- pre-sync claimed-work invariant tests

## GitHub Actions verification

### Run 1
- Run ID: `37088036099`
- Result: **SUCCESS**
- Verified: compile, 12 tests, pinned upstream checkout, source audit, baseline verification, report summary

### Run 2
- Run ID: `37088170695`
- Result: **SUCCESS**
- Verified: compile, 17 tests, pinned upstream checkout, consensus/source/supply-chain audit, baseline verification, report summary

## Baseline semantics

`baseline/expected_findings.json` is not an allowlist saying known findings are acceptable forever. It is a drift detector:

- expected finding disappears → CI fails until reviewed;
- new modeled finding appears → CI fails until reviewed;
- audited target changes → CI fails until reviewed.

This prevents silent changes to the evidence set.

## Disclosure boundary

Unresolved high-impact finding details and weaponized reproductions are not intended for public commits. Upstream WAM private reporting instructions are mirrored in `SECURITY.md`.
