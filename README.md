# WAM Security

**Independent, executable security assurance for WAM Coin.**

> Current stage: **V2 — Adversarial Runtime (operational)**  
> Audited upstream snapshot: `wamcoin-core-dev/wam-coin@012f3d38570de232a750458e9cf6c91e985db6a1`  
> Framework version: `0.2.0`

WAM already has a security policy, bug bounty, code review, CI and release controls. This project does **not** replace them. Its job is to make important assumptions independently testable and to keep those assumptions true under hostile input, dependency failure and process crashes.

## V1 baseline

V1 remains mandatory underneath V2:

- threat model and release-blocking invariants
- independent monetary model
- consensus-constant drift detection
- payout safety reference model
- targeted WAM source/supply-chain auditor
- pinned upstream evidence and baseline drift enforcement

## V2 operational gates

| Gate | Status | Evidence |
|---|---|---|
| Full unit / invariant suite | ✅ **33 tests** | `tests/` |
| Payout crash/restart matrix | ✅ **21 scenarios** | `adversarial/faults.py` |
| Deterministic hostile-input fuzz | ✅ **4 CI seeds × 2,500 cases** | `adversarial/fuzz.py` |
| Protocol envelope bounds | ✅ PASS | `adversarial/protocol.py` |
| Resource budget model | ✅ PASS | `adversarial/resource.py` |
| Fail-closed dependency watchdog | ✅ PASS | `adversarial/watchdog.py` |
| Restart-loop circuit budget | ✅ PASS | `adversarial/watchdog.py` |
| WAM Stratum/API/RPC runtime guard audit | ✅ PASS | `audit/runtime.py` |
| V1 regression on V2 head | ✅ PASS | GitHub Actions |
| V2 adversarial matrix | ✅ PASS | GitHub Actions |

## What V2 proves

V2 does **not** claim that no denial-of-service or runtime bug exists. It establishes executable reference properties:

- oversized/malformed protocol input is rejected with bounded reference work;
- connection, message-rate and in-flight counters remain inside explicit budgets;
- ambiguous RPC outcomes never imply "nothing happened";
- a payout retry retains one deterministic transaction identity;
- crashes at modeled payout boundaries recover without more than one balance commit;
- unknown/failed money dependencies pause money movement;
- repeated restarts are circuit-bounded;
- reviewed WAM Stratum/API/RPC hardening controls cannot silently disappear without CI detecting drift.

## Run locally

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python scripts/run_v2_adversarial.py --seed 0x57414D --cases 2500
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

See `docs/EVIDENCE.md` for V1, `docs/V2_EVIDENCE.md` for V2, and `docs/ROADMAP.md` for V1 → V7.
