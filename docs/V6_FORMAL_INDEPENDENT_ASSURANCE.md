# V6 — Formal & Independent Assurance

V6 raises assurance from "tests pass" to "critical state transitions are modeled
and independently witnessed."

## Assurance layers

1. **TLA+/TLC** models for payout reconciliation and release publication.
2. **Independent explicit-state checker** in Python with mutation sensitivity.
3. **Two-person critical review policy** encoded as machine-readable paths.
4. **Independent builder witnesses** on Ubuntu 22.04 and 24.04.
5. **Red-team regression corpus** that replays public/accepted failure classes
   without publishing weaponized exploit material.

## Formal payout invariants

- at most one transaction identity per logical payout
- at most one accounting commit
- attempted payouts never forget transaction identity
- unknown outcomes retain identity
- accounting commits only after the transaction is observed

## Formal release invariants

- builds use locked source/dependency identities
- approval requires provenance + SBOM + two independent reviews
- publication requires two reviews
- publication requires provenance and SBOM
- publication cannot use unlocked inputs

## Review boundary

WAM currently has no repository-source `.github/CODEOWNERS` file at the audited
commit. GitHub branch/ruleset settings are not readable by this integration, so V6
does not claim anything about private repository settings. It audits what is
machine-verifiable from the repository and provides a reference critical-path
policy for maintainers to bind to repository rules.

## Safety

All V6 adversarial cases are abstract/local state machines or known public
regression classes. No public node, pool, wallet, release credential or third-party
system is attacked.
