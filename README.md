# WAM Security

**Independent, executable security assurance for WAM Coin.**

> Current stage: **V1 — Security Baseline**  
> Audited upstream snapshot: `wamcoin-core-dev/wam-coin@012f3d38570de232a750458e9cf6c91e985db6a1`

WAM already has a security policy, bug bounty, code review, CI and release controls. This project does **not** replace them. Its job is to make important assumptions independently testable: monetary invariants, payout safety, WAM-specific source risks, P2P hardening and release supply-chain evidence.

## V1 status

| Gate | Status | Evidence |
|---|---|---|
| Threat model | ✅ implemented | `docs/THREAT_MODEL.md` |
| Security invariants | ✅ implemented | `docs/INVARIANTS.md` |
| Independent monetary model | ✅ local PASS | next commit |
| Exactly-once payout reference model | ✅ local PASS | next commit |
| Targeted WAM source auditor | ✅ local PASS | next commit |
| Reproducible reports | ✅ local PASS | next commit |
| CI security gate | ⬜ next | workflow commit |
| RandomX pre-sync reproduction | ⬜ next V1 gate | local/regtest only |
| Pool ambiguous-RPC reproduction | ⬜ next V1 gate | local fixture only |

## Scope

The baseline tracks security conditions found in WAM-owned code without claiming that inherited Bitcoin Core code is bug-free. Findings always identify an exact audited WAM revision and distinguish confirmed logic risks from issues that still require controlled reproduction.

## Design rule

`wam-security` stays an **independent verifier**, not another copy of `wam-coin`. The WAM implementation and the security reference model must be able to disagree; otherwise a shared bug can make both sides pass.

## Safety

Adversarial tests are restricted to local fixtures, regtest/testnet, or project-owned infrastructure. This repository is for defensive verification and reproducible security research.

See `docs/ROADMAP.md` for V1 → V7.
