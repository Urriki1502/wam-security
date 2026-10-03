# V2 — Adversarial Runtime

V2 asks a different question from V1:

> What happens when inputs are malformed, peers are noisy, dependencies time out, and the process dies at the worst possible instruction boundary?

## Scope

V2 is defensive and local-first. It does not scan or attack public WAM infrastructure.

The V2 assurance layers are:

1. **Protocol envelope guards** — reject oversized, malformed, excessively deep, or over-wide JSON-RPC / Stratum messages with bounded work.
2. **Resource budgets** — explicit global/per-IP connection, message-rate, size and in-flight request limits.
3. **Fault injection** — crash/restart and ambiguous RPC outcomes across a payout state machine.
4. **Runtime source regression** — verify reviewed WAM Stratum/API/RPC bounds do not silently disappear.
5. **Deterministic fuzzing** — seeded corpora that are reproducible in CI rather than random failures nobody can replay.
6. **Fail-closed watchdog** — unknown/failed money dependencies pause money movement while read-only observability remains available.
7. **Restart budget** — repeated process failures trip a bounded restart circuit instead of creating an infinite crash loop.

## Exit gates

V2 is operational only when:

- all V1 gates remain green;
- the payout crash matrix settles every scenario with one transaction identity and at most one balance commit;
- malformed protocol cases never escape as unhandled parser failures;
- oversized input is rejected before expensive parsing in the reference guard;
- resource counters never exceed configured bounds;
- multiple deterministic fuzz seeds pass in GitHub Actions;
- any unknown/failed money dependency pauses money movement;
- restart loops are bounded by policy;
- the pinned WAM snapshot retains its reviewed Stratum/API/RPC runtime guards;
- V2 evidence is recorded with exact CI run IDs.

## Safety boundary

Fuzzers in this repository operate on local byte strings and reference state machines. Network-facing experiments belong on local fixtures, regtest/testnet, or project-owned infrastructure only.
