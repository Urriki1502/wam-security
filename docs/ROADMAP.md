# WAM Security Roadmap

## V1 — Security Baseline
Threat model, invariants, independent monetary model, targeted source audit, payout safety model, pinned upstream evidence, CI gates.

## V2 — Adversarial Runtime
P2P/RPC/Stratum fuzzing, malformed-input harnesses, connection/resource exhaustion, crash/restart/network fault injection, runtime limits and fail-closed paths.

## V3 — Consensus Assurance
Independent DGW and RandomX seed models, differential tests against `wamd`, reorg/epoch boundary suites, ASan/UBSan/TSan, libFuzzer harnesses.

## V4 — Money Safety
Exactly-once pool payment architecture, deterministic raw transaction identity, crash-at-every-boundary tests, wallet isolation, spend caps, Silent Payments adversarial recovery/scanning tests.

## V5 — Supply Chain Fortress
Immutable action/dependency pins, SBOM, provenance attestations, reproducible-build comparison, protected release environments, independent artifact verification.

## V6 — Formal & Independent Assurance
TLA+/model checking for payout and release state machines, two-person review for security-critical paths, independent builders, external audit/red-team corpus.

## V7 — Continuous Security Fabric
Live consensus/supply/fork/payout/release monitoring, signed machine-readable security status, continuous fuzzing, periodic chaos exercises and release blocking on critical invariant failure.
