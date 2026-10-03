# WAM Security

**Independent, executable security assurance for WAM Coin.**

> Current stage: **V1 — Security Baseline (operational)**  
> Audited upstream snapshot: `wamcoin-core-dev/wam-coin@012f3d38570de232a750458e9cf6c91e985db6a1`

WAM already has a security policy, bug bounty, code review, CI and release controls. This project does **not** replace them. Its job is to make important assumptions independently testable: monetary invariants, payout safety, WAM-specific source risks, P2P hardening and release supply-chain evidence.

## V1 status

| Gate | Status | Evidence |
|---|---|---|
| Threat model | ✅ PASS | `docs/THREAT_MODEL.md` |
| Security invariants | ✅ PASS | `docs/INVARIANTS.md` |
| Independent monetary model | ✅ PASS | `src/wam_security/model/monetary.py` |
| Consensus constant drift detection | ✅ PASS | `src/wam_security/audit/consensus.py` |
| Exactly-once payout reference model | ✅ PASS | `src/wam_security/model/payment.py` |
| P2P pre-sync security model | ✅ PASS | `src/wam_security/model/presync.py` |
| Targeted WAM source auditor | ✅ PASS | `src/wam_security/audit/` |
| Unit / invariant suite | ✅ 17 tests | `tests/` |
| Pinned upstream integration audit | ✅ PASS | GitHub Actions |
| Finding baseline enforcement | ✅ PASS | `baseline/expected_findings.json` |
| Responsible disclosure boundary | ✅ PASS | `SECURITY.md` |

## What V1 proves

V1 does not claim that WAM is bug-free. It establishes a reproducible baseline that can fail when:

- monetary or RandomX consensus constants drift without matching security review;
- payout-safety invariants regress;
- known WAM-owned security conditions disappear or new modeled conditions appear unexpectedly;
- supply-chain controls become weaker;
- the audited source no longer matches the pinned revision.

## Run locally

No third-party runtime dependency is required for the test suite:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Audit a WAM checkout:

```bash
PYTHONPATH=src python -m wam_security.cli audit /path/to/wam-coin \
  --out security-reports \
  --target <commit>
```

## Design rule

`wam-security` stays an **independent verifier**, not another copy of `wam-coin`. The WAM implementation and the security reference model must be able to disagree; otherwise a shared bug can make both sides pass.

## Disclosure and safety

Do not publish unresolved high-impact WAM vulnerabilities here. Follow `SECURITY.md` and upstream WAM responsible disclosure. Adversarial tests are restricted to local fixtures, regtest/testnet, or project-owned infrastructure.

See `docs/EVIDENCE.md` for the V1 evidence chain and `docs/ROADMAP.md` for V1 → V7.
