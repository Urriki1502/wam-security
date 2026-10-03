# WAM Security

Independent, executable security assurance for WAM Coin.

> **Framework status:** V1 → V7 operational  
> **Framework version:** `0.7.0`  
> **Framework baseline snapshot:** `wamcoin-core-dev/wam-coin@012f3d38570de232a750458e9cf6c91e985db6a1`  
> **Current integration-security target:** `wamcoin-core-dev/wam-coin@bd71b0bd645286a3867dad6b2bfefd911ec8a5b6`  
> **Current full-suite result:** **91/91 tests PASS**  
> **Review state:** **FROZEN FOR MAINTAINER REVIEW** — no further scope expansion is planned for this revision.

WAM Security is an independent verification framework for consensus, runtime,
money movement, release integrity, formal safety properties and continuous
security monitoring around WAM Coin.

It does **not** replace WAM Core, its maintainers, its security policy, bug bounty,
release signing or code review. The purpose of this repository is to make
security assumptions executable, reproducible and independently testable.

## Maintainer quick status

The V1 → V7 framework is the long-lived assurance baseline. The integration-security
track then points those invariants at the exact reviewed WAM implementation and
validates high-risk lifecycle boundaries with deterministic local evidence.

| Area | Review | Result | Maintainer status |
|---|---:|---|---|
| RandomX header pre-sync | [PR #10](https://github.com/Urriki1502/wam-security/pull/10) | **PASS** | Evidence complete |
| Startup / reindex RandomX state | [PR #11](https://github.com/Urriki1502/wam-security/pull/11) | **PASS** | Evidence complete |
| Pool job / Stratum template integrity | [PR #12](https://github.com/Urriki1502/wam-security/pull/12) | **Harness PASS** | Upstream maintainer follow-up pending |
| Wallet transaction / state integrity | [PR #13](https://github.com/Urriki1502/wam-security/pull/13) | **PASS** | Evidence complete |

All integration-security work in this review track is constrained to exact source
revisions, local fixtures, mocked failure boundaries, isolated regtest, and GitHub
Actions. It does not use real wallets, real funds, public mining infrastructure,
third-party credentials, or disruptive external testing.

For detailed evidence, scope boundaries, classifications, run IDs and artifact
digests, open the corresponding Draft PR. Sensitive unresolved implementation
details remain subject to `SECURITY.md`.

---

## Security architecture

```text
WAM Core source / release / public health endpoints
                     |
                     v
+------------------------------------------------------+
| V1  Security Baseline                               |
| V2  Adversarial Runtime                             |
| V3  Consensus Assurance                             |
| V4  Money Safety                                    |
| V5  Supply Chain Fortress                           |
| V6  Formal & Independent Assurance                  |
| V7  Continuous Security Fabric                      |
+------------------------------------------------------+
                     |
                     v
        machine-readable security evidence
                     |
                     v
             GREEN / YELLOW / RED
                     |
                     v
              release security gate
```

The layers are cumulative. Every later stage preserves the guarantees and
regression coverage established by the earlier stages.

---

## V1 — Security Baseline

V1 establishes the independent security baseline and the first set of executable
invariants.

Implemented:

- threat model and trust-boundary documentation;
- monetary reference model;
- WAM consensus-constant drift detection;
- payout safety reference model;
- P2P pre-sync security model;
- targeted WAM-owned source audit;
- supply-chain/workflow audit;
- expected-finding baseline enforcement;
- machine-readable Markdown and JSON security reports;
- responsible-disclosure boundary.

Verified at V1 completion:

- **17 unit/invariant tests PASS**
- pinned WAM source audit PASS
- baseline drift enforcement PASS

Primary locations:

```text
src/wam_security/model/
src/wam_security/audit/
baseline/
docs/THREAT_MODEL.md
docs/INVARIANTS.md
docs/EVIDENCE.md
```

---

## V2 — Adversarial Runtime

V2 adds deterministic hostile-input, failure and resource-pressure testing around
runtime-facing components.

Implemented:

- protocol envelope validation;
- explicit resource-budget model;
- deterministic adversarial input generation;
- connection/message/in-flight limits;
- dependency watchdog behavior;
- restart-loop circuit budgeting;
- payout crash/restart fault matrix;
- WAM Stratum/API/RPC runtime-control auditing.

Verified at V2 completion:

- **33 unit/invariant tests PASS**
- **21 crash/failure scenarios PASS**
- deterministic multi-seed adversarial fuzz PASS
- runtime-control baseline PASS
- V1 regression PASS

Primary locations:

```text
src/wam_security/adversarial/
src/wam_security/audit/runtime.py
scripts/run_v2_adversarial.py
tests/test_fault_matrix.py
tests/test_protocol_guards.py
tests/test_resource_budget.py
tests/test_watchdog.py
```

---

## V3 — Consensus Assurance

V3 independently models and differentially verifies WAM-specific consensus
behavior.

Implemented:

- Bitcoin compact-target codec;
- proof-of-work target-boundary checks;
- independent DGW model;
- RandomX seed-height and network-profile model;
- reorg/epoch-boundary coverage;
- WAM consensus-semantic source audit;
- native C++ consensus harness;
- ASan/UBSan differential runs;
- build and execution of the actual patched `wamd`;
- isolated regtest RandomX epoch-transition probe.

Verified at V3 completion:

- **50 unit/invariant tests PASS**
- **6,684 cross-language consensus vectors PASS**
- **35 native WAM C++ consensus tests PASS**
- patched `wamd` build PASS
- RandomX regtest seed transition PASS
- V1 regression PASS

Boundary coverage includes:

```text
height 0 / 1
199999 / 200000 / 200001
399999 / 400000 / 400001
RandomX epoch-1 / epoch / epoch+1
reorg-sensitive RandomX seed boundaries
PoW hash == target
PoW hash == target + 1
DGW bootstrap / clamp / powLimit behavior
```

Primary locations:

```text
src/wam_security/consensus/
src/wam_security/audit/consensus.py
src/wam_security/audit/consensus_semantics.py
native/v3_consensus_harness.cpp
scripts/run_v3_differential.py
formal/
```

---

## V4 — Money Safety

V4 treats payout handling as a distributed-systems safety problem rather than a
single RPC call.

Implemented:

- durable payout-intent model;
- deterministic transaction identity before broadcast;
- persistent raw transaction + txid recovery state;
- ambiguous-RPC recovery;
- exactly-once economic-payment invariant;
- dedicated payout-wallet policy;
- recipient, batch, fee and daily-spend limits;
- accounting-conservation checks;
- atomic Redis accounting reference implementation;
- current WAM money-path audit;
- actual patched-`wamd` raw-transaction identity probe.

Verified at V4 completion:

- **64 unit/invariant tests PASS**
- **15,000 crash/restart payout scenarios PASS**
- current WAM payment regression tests PASS
- Redis atomic commit PASS
- Redis replay rejection PASS
- failed-precondition rollback PASS
- patched `wamd` payout-wallet isolation PASS
- lost-response recovery with identical raw transaction PASS
- one economic transaction observed after rebroadcast
- V1 regression PASS

Core invariants:

```text
one logical payout -> at most one transaction identity
one logical payout -> at most one accounting commit
unknown broadcast state -> identity is retained
accounting commit -> transaction must already be observed
failed reconciliation -> money movement remains fail-closed
```

Primary locations:

```text
src/wam_security/money/
src/wam_security/audit/money.py
reference/redis/commit_payment.lua
scripts/run_v4_money_faults.py
scripts/run_v4_redis_atomicity.py
scripts/run_v4_wamd_money_probe.sh
```

Sensitive unresolved upstream findings are handled through responsible disclosure;
this README intentionally describes security classes and guarantees rather than
publishing exploit instructions.

---

## V5 — Supply Chain Fortress

V5 extends assurance from source correctness to release trust.

Implemented:

- deep release/workflow audit;
- exact reviewed dependency identity lock;
- remote-ref drift verification;
- exact GitHub Action commit identities;
- deterministic release-control evidence;
- SLSA-style provenance statement generation;
- SPDX 2.3 SBOM generation;
- provenance subject-digest verification;
- deterministic tar.gz reference builder;
- current WAM packaging reproducibility probe.

Locked identities include:

- Bitcoin Core v28.1;
- RandomX v1.2.1;
- checkout/upload/download workflow actions;
- build-provenance attestation action.

Verified at V5 completion:

- **71 unit/invariant tests PASS**
- reviewed remote identity lock PASS
- provenance generation PASS
- SPDX SBOM generation PASS
- tamper detection PASS
- deterministic reference archive PASS
- current WAM release-path packaging probe PASS
- V1 regression PASS

The current WAM packaging probe independently demonstrated that two archives can
contain identical logical payload bytes while the resulting archive bytes differ.
The reference packager removes that ambiguity by normalizing archive metadata.

Primary locations:

```text
src/wam_security/supplychain/
src/wam_security/audit/supply_chain.py
supply-chain-lock.json
scripts/verify_v5_remote_identities.py
scripts/run_v5_release_surface.py
scripts/run_v5_current_packaging_probe.sh
```

---

## V6 — Formal & Independent Assurance

V6 adds executable state-machine verification and independent build witnesses.

Implemented:

- payout TLA+ state-machine specification;
- release TLA+ state-machine specification;
- independent Python explicit-state checker;
- deliberate unsafe mutations and counterexample tests;
- machine-readable critical-review policy;
- independent-assurance source audit;
- independent builders on Ubuntu 22.04 and Ubuntu 24.04;
- byte-for-byte evidence comparison;
- non-weaponized red-team regression corpus;
- exact TLA+ tool artifact hash lock.

Verified at V6 completion:

- **77 unit/invariant tests PASS**
- payout explicit model: **7 distinct states / 20 transitions PASS**
- release explicit model: **18 distinct states / 28 transitions PASS**
- **4/4 deliberate unsafe mutations caught**
- TLA+/TLC payout model PASS
- TLA+/TLC release model PASS
- red-team regression corpus **8/8 PASS**
- Ubuntu 22.04 == Ubuntu 24.04 evidence **byte-for-byte**
- V1 regression PASS

Formal safety properties include:

```text
AtMostOneIdentity
AtMostOneCommit
UnknownRetainsIdentity
CommitOnlyAfterSeen
AttemptNeverForgetsIdentity
BuildUsesLockedInputs
ApprovalRequiresEvidence
PublishRequiresTwoReviews
PublishRequiresProvenance
PublishRequiresSBOM
PublishRequiresLockedInputs
```

Primary locations:

```text
formal/
src/wam_security/formal/
src/wam_security/audit/independent_assurance.py
redteam/corpus.json
review/critical-paths.json
reference/review/CODEOWNERS.template
scripts/run_v6_formal.py
scripts/run_v6_tlc.sh
scripts/compare_v6_builders.py
```

---

## V7 — Continuous Security Fabric

V7 converts the previous point-in-time gates into continuously refreshed security
evidence.

Implemented:

- versioned machine-readable `security-status.json`;
- GREEN / YELLOW / RED policy engine;
- hard release blocking on critical failures;
- WAM source-drift monitoring;
- fail-closed behavior when source drift cannot be classified;
- audit-baseline drift monitoring;
- official explorer health monitoring;
- live supply-cap verification;
- explorer/pool chain-height agreement;
- official pool health monitoring;
- payout telemetry visibility;
- latest-release integrity monitoring;
- scheduled adversarial fuzz and money-fault rotations;
- scheduled chaos exercises;
- provenance attestation of trusted security-status artifacts.

Status semantics:

| State | Meaning | Release gate |
|---|---|---|
| **GREEN** | All measured gates pass | Allowed |
| **YELLOW** | Missing/stale/noncritical evidence requires attention | Not automatically blocked |
| **RED** | A critical invariant failed | **Blocked** |

Verified on the V7 final operational head:

- **91/91 unit + invariant tests PASS**
- live fabric **8/8 checks PASS**
- overall status **GREEN**
- `release_blocked=false`
- **12,000 adversarial fuzz cases PASS**
- **9,000 exactly-once money fault cases PASS**
- **63 crash/resource scenarios PASS**
- synthetic RED status blocks release
- synthetic YELLOW status degrades without blocking
- V6 formal models replay PASS
- security-status artifact attestation PASS
- transparency-log upload PASS
- V1 regression PASS
- V5 supply-chain regression on V7 head PASS

Live checks:

```text
source.drift
audit.baseline
live.explorer
consensus.supply
live.pool
payout.visibility
consensus.fork-agreement
release.integrity
```

Recurring cadence:

```text
hourly  -> security-fabric snapshot
daily   -> adversarial fuzz + money fault rotation
weekly  -> chaos/release-block proof + formal-model replay
```

Primary locations:

```text
src/wam_security/fabric/
src/wam_security/audit/continuous_fabric.py
scripts/run_v7_fabric.py
scripts/run_v7_chaos.py
scripts/verify_v7_release_gate.py
.github/workflows/security-v7.yml
```

---

## Final verification stack

```text
source
  |
  v
V1 baseline invariants
  |
  v
V2 adversarial runtime
  |
  v
V3 consensus differential + native node
  |
  v
V4 money safety + fault recovery
  |
  v
V5 supply-chain provenance + reproducibility
  |
  v
V6 formal verification + independent builders
  |
  v
V7 continuous monitoring + release gate
  |
  v
machine-readable security evidence
```

The framework is designed so that a failure in one trust domain cannot be hidden by
success in another. Source, runtime, consensus, money movement, build provenance,
formal properties and live operational state are checked independently.

---

## Repository layout

```text
wam-security/
├── .github/workflows/        CI and recurring security gates
├── baseline/                 Reviewed finding baseline
├── docs/                     Threat model, evidence and V1-V7 design documents
├── formal/                   TLA+ specifications and TLC configurations
├── native/                   Native consensus differential harness
├── redteam/                  Non-weaponized security regression corpus
├── reference/
│   ├── redis/                Atomic accounting reference
│   └── review/               Critical-path review templates
├── review/                   Machine-readable review policy
├── scripts/                  Audit, differential, fault, formal and fabric runners
├── src/wam_security/
│   ├── adversarial/          Runtime fault and fuzz models
│   ├── audit/                Source/security control auditors
│   ├── consensus/            Independent consensus models
│   ├── fabric/               Continuous status and policy engine
│   ├── formal/               Explicit-state verification
│   ├── model/                Baseline monetary/payment/P2P models
│   ├── money/                Exactly-once payout model
│   └── supplychain/          Identity, provenance and reproducibility logic
├── tests/                    Unit, invariant and regression tests
├── supply-chain-lock.json    Reviewed immutable source/action identities
├── upstream.lock.json        Audited WAM upstream revision
├── SECURITY.md               Disclosure policy
└── pyproject.toml            Python package metadata
```

---

## Run locally

Requirements:

- Python 3.10+
- Git
- additional native/build dependencies only for the heavyweight V3/V4/V5 gates
- Java runtime only for TLA+/TLC execution

Run the complete Python test suite:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Audit a local WAM checkout:

```bash
PYTHONPATH=src python -m wam_security.cli audit /path/to/wam-coin \
  --out security-reports \
  --target <commit>
```

Run adversarial runtime checks:

```bash
PYTHONPATH=src python scripts/run_v2_adversarial.py \
  --seed 0x57414D \
  --cases 2500
```

Run consensus differential checks:

```bash
PYTHONPATH=src python scripts/run_v3_differential.py --help
```

Run money-safety fault testing:

```bash
PYTHONPATH=src python scripts/run_v4_money_faults.py \
  --seed 0x57414D \
  --cases 5000
```

Verify locked supply-chain identities:

```bash
PYTHONPATH=src python scripts/verify_v5_remote_identities.py
```

Run the independent formal checker:

```bash
PYTHONPATH=src python scripts/run_v6_formal.py
```

Run TLA+/TLC:

```bash
bash scripts/run_v6_tlc.sh
```

Build a continuous security status from a WAM checkout:

```bash
PYTHONPATH=src python scripts/run_v7_fabric.py /path/to/wam-coin \
  --report security-reports/security-report.json \
  --out security-status
```

Enforce the release gate:

```bash
python scripts/verify_v7_release_gate.py \
  security-status/security-status.json \
  --block-red
```

---

## Design principles

### Independent verification

The framework intentionally does not copy WAM Core into this repository. Independent
models must be capable of disagreeing with the implementation; otherwise the same
defect can be reproduced on both sides and incorrectly pass.

### Fail closed on critical uncertainty

Critical source drift, monetary ambiguity, supply-cap violations and critical
security-state failures are not converted into success when evidence is missing.

### Deterministic evidence

Critical reference outputs use deterministic serialization, fixed identities and
cryptographic digests so independent builders can compare evidence byte-for-byte.

### Responsible disclosure

Do not publish unresolved high-impact vulnerabilities or operational exploit
instructions in public issues or pull requests. Use the disclosure process in
`SECURITY.md`.

### Read-only public monitoring

Continuous public probes are read-only. The security fabric does not send funds,
mine through hosted CI, modify public WAM infrastructure or require production
wallet credentials.

---

## Security evidence

The framework produces and/or verifies:

- security audit reports;
- expected-finding baselines;
- consensus differential results;
- native WAM test results;
- payout fault-matrix results;
- Redis atomicity evidence;
- SBOM documents;
- build provenance statements;
- independent-builder comparisons;
- formal model-checking results;
- red-team regression results;
- continuous security-status snapshots;
- cryptographic status digests;
- provenance attestations.

Security evidence describes the tested revision and test scope. It is not a claim
that any software system is free from defects.

---

## Current stage

```text
V1  Security Baseline                 OPERATIONAL
V2  Adversarial Runtime               OPERATIONAL
V3  Consensus Assurance               OPERATIONAL
V4  Money Safety                      OPERATIONAL
V5  Supply Chain Fortress             OPERATIONAL
V6  Formal & Independent Assurance    OPERATIONAL
V7  Continuous Security Fabric        OPERATIONAL
```

The V1 → V7 roadmap is complete. Future work should focus on review, upstream
integration, regression prevention, independent verification and maintenance of
the continuous evidence chain rather than adding version numbers without a new
security trust boundary.

## Integration-security maintenance track

The integration-security track is the maintainer-facing bridge between the independent
V1 → V7 assurance framework and the exact WAM implementation under review.

Current locked target:

```text
wamcoin-core-dev/wam-coin
bd71b0bd645286a3867dad6b2bfefd911ec8a5b6
```

Coverage in the current frozen review set includes:

- payout recovery and exactly-once accounting regression;
- RandomX header pre-sync lifecycle;
- startup, restart, `-reindex-chainstate` and full `-reindex` state recovery;
- pool job / Stratum template / RandomX binding and stale-job lifecycle;
- wallet transaction construction, fee/change conservation, broadcast ambiguity,
  restart, rejection, reorg, rescan, locking and backup/restore behavior.

The integration gates reuse the existing independent invariants rather than replacing
them. A green workflow is not treated as sufficient by itself: the exact target,
source contract, native/runtime behavior, scope boundaries and machine-readable
evidence must agree.

Representative local entry point:

```bash
PYTHONPATH=src python scripts/run_integration_payout_patch.py /path/to/wam-coin
```

Current review PRs:

- [#10 — RandomX header pre-sync invariants](https://github.com/Urriki1502/wam-security/pull/10)
- [#11 — startup and reindex RandomX state](https://github.com/Urriki1502/wam-security/pull/11)
- [#12 — pool job and Stratum template integrity](https://github.com/Urriki1502/wam-security/pull/12)
- [#13 — wallet transaction and state integrity](https://github.com/Urriki1502/wam-security/pull/13)

PR #12 intentionally remains a maintainer-follow-up point. The README does not
publish unnecessary unresolved implementation detail; the regression harness is
the closure mechanism for any upstream fix.

No additional V-number is planned for this review cycle. New work should only open
a new track when it crosses a distinct security trust boundary or validates an
upstream change against existing invariants.

See:

- `docs/THREAT_MODEL.md`
- `docs/INVARIANTS.md`
- `docs/EVIDENCE.md`
- `docs/ROADMAP.md`
- `docs/V2_ADVERSARIAL_RUNTIME.md`
- `docs/V3_CONSENSUS_ASSURANCE.md`
- `docs/V4_MONEY_SAFETY.md`
- `docs/V5_SUPPLY_CHAIN_FORTRESS.md`
- `docs/V6_FORMAL_INDEPENDENT_ASSURANCE.md`
- `docs/V7_CONTINUOUS_SECURITY_FABRIC.md`
- `SECURITY.md`
