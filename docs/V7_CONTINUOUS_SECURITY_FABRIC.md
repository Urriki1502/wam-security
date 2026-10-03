# V7 — Continuous Security Fabric

V7 turns V1–V6 from point-in-time assurance into continuously refreshed evidence.

## Status semantics

The fabric emits `security-status.json` with one of three states:

- **GREEN** — all measured gates pass and no reviewed source/audit drift exists.
- **YELLOW** — data is missing/stale, a noncritical service is unavailable, or
  a noncritical/baseline change requires review.
- **RED** — a critical invariant fails. RED sets `release_blocked=true` and
  the release gate exits non-zero.

Known findings already captured by the reviewed baseline are not treated as new
incidents. New HIGH/CRITICAL findings are RED.

## Continuous evidence

The reference workflow measures:

- WAM source HEAD vs the last fully audited commit
- audit finding drift vs the reviewed baseline
- official explorer health
- live 22,000,000 WAM supply-cap invariant
- explorer vs pool height agreement as fork evidence
- official pool health
- public payout telemetry presence
- latest GitHub release signed-checksum integrity

Unreachable live endpoints are **UNKNOWN**, never silently converted to PASS.

## Signing / attestation

The JSON status and SHA-256 digest are uploaded as CI artifacts. On trusted
non-PR runs, GitHub OIDC artifact attestation binds the status file to the
repository/workflow identity. No long-lived signing private key is committed to
this repository.

## Recurring assurance

- hourly: fabric status
- daily: rotating adversarial fuzz + money fault matrix
- weekly: chaos exercise proving a synthetic critical failure creates RED and
  blocks the release gate

V7 never sends money, mines on hosted CI, mutates public infrastructure, or
attacks live services. Live probes are read-only HTTP GETs.
