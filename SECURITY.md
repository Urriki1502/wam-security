# Security policy

`wam-security` is a defensive assurance project for WAM Coin.

## Reporting WAM vulnerabilities

Do **not** open a public issue containing an unresolved WAM consensus, node, pool, wallet or funds-safety vulnerability. Follow the upstream WAM disclosure policy and report privately to:

**wam.coin.official@proton.me**

The public repository may contain generic security models, invariant tests and already-safe regression coverage. Weaponized proof-of-concept code or detailed exploitation instructions for an unresolved high-impact finding are intentionally excluded until maintainer triage makes disclosure appropriate.

## Research boundary

Adversarial testing is limited to local fixtures, regtest/testnet and infrastructure owned by or explicitly provided for the project. Do not test public nodes, pools, wallets or third-party systems without authorization.

## Tooling bugs

Bugs in `wam-security` itself that do not reveal an unresolved WAM vulnerability may be filed normally in this repository.
