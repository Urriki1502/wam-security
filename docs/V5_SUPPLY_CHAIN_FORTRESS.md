# V5 — Supply Chain Fortress

V5 extends WAM Security from source/runtime assurance to the release trust chain.

## Threat boundary

A correct source tree is not sufficient if a release can execute mutable CI code,
resolve different dependency commits, build under a drifting toolchain, publish a
different artifact set, or distribute bytes that cannot be tied back to the audited
source commit.

## V5 invariants

1. Every externally executed CI action has one immutable reviewed commit identity.
2. Bitcoin Core and RandomX refs are independently locked to exact commits.
3. Build jobs do not inherit repository write permission needed only for publication.
4. Release publication is a separate, explicitly protected transition.
5. Release composition is deterministic and declared before signing.
6. Archive bytes are reproducible from identical logical payloads.
7. Every artifact is bound to source/dependency identities by machine-readable provenance.
8. Every release carries a machine-readable SPDX SBOM.
9. Offline signing authenticates a manifest assembled by automation, not by hand.
10. Drift of any reviewed identity fails closed and requires a deliberate lock update.

## Audited WAM target

- repository: `wamcoin-core-dev/wam-coin`
- commit: `012f3d38570de232a750458e9cf6c91e985db6a1`
- observed current main: 2026-10-03

## Independent trust lock

`supply-chain-lock.json` records exact commits for Bitcoin Core v28.1, RandomX
v1.2.1, actions/checkout v5, actions/upload-artifact v7 and
actions/download-artifact v7.

V5 CI resolves each remote ref again and compares it to the reviewed commit.
A tag move is therefore a review event, not an invisible build input change.

## Evidence layers

- deep release source audit
- remote ref identity verification
- deterministic SLSA-style provenance serialization
- deterministic SPDX 2.3 SBOM serialization
- subject hash tamper detection
- byte-for-byte reproducible reference archives under perturbed mtimes/order
- current WAM release packaging reproducibility probe

V5 does not publish or modify WAM releases. The heavyweight probe builds and
packages only inside an isolated CI runner.
