# Integration Security Harness

The V1-V7 architecture remains the stable assurance framework. Ongoing work is a
maintenance track that points those invariants at real upstream WAM changes rather
than creating another version number.

## Released-patch review

The first integration target is WAM Core commit:

`bd71b0bd645286a3867dad6b2bfefd911ec8a5b6`

The runner `scripts/run_integration_payout_patch.py` combines independent WAM
Security money-safety models with the regression tests shipped by the WAM patch.
It verifies the released behavior around:

- unknown money-RPC outcomes stopping failover instead of creating a second spend;
- retention of the durable payout intent when the RPC outcome is unknown;
- fail-closed restart behavior while an unresolved intent exists;
- Redis transaction use for the final accounting commit;
- the exactly-once economic-payment invariant under crash/restart fault injection.

Run it against an exact checkout:

```bash
PYTHONPATH=src python scripts/run_integration_payout_patch.py /path/to/wam-coin
```

For a later WAM checkout that contains the released patch:

```bash
PYTHONPATH=src python scripts/run_integration_payout_patch.py /path/to/wam-coin \
  --allow-descendant
```

The runner writes machine-readable evidence to
`security-reports/integration-payout-patch.json` by default.

## Disclosure boundary

This public harness contains regression coverage for already-released fixes and
generic safety invariants. New high-impact hypotheses are validated privately first.
Specific failure conditions, reproduction detail and candidate fixes remain outside
the public repository until upstream maintainers have triaged or fixed them.

That boundary is intentional: the project exists to make defensive guarantees
reproducible, not to publish an exploitation kit.

## Next integration targets

After payout-patch verification, the maintenance queue is:

1. Redis persistence/recovery semantics and accounting conservation;
2. RandomX/header pre-sync measurement on local/regtest fixtures;
3. wallet/RPC safety;
4. sync/header validation;
5. installer/service startup and release/config safety.

The same rule applies to each target: define the invariant, reproduce locally, emit
evidence, and only publish unresolved details after maintainer handling.
