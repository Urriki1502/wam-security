# V3 — Consensus Assurance

V3 adds independent consensus implementations and cross-language differential testing around the WAM-specific proof-of-work surface.

## Mandatory gates

- exact Bitcoin compact-target encode/decode model
- WAM DGW recurrence and clamp model
- RandomX seed-height profiles for mainnet/testnet/regtest
- reorg boundary tests around seed activation
- semantic source regression against pinned WAM code
- independent C++ harness built with AddressSanitizer + UndefinedBehaviorSanitizer
- Python ↔ C++ differential vectors for compact targets, DGW and RandomX seed heights
- all V1/V2 unit and invariant tests remain green

## Native node gate

A separate heavyweight job fetches Bitcoin Core v28.1 and RandomX v1.2.1 through WAM's own pinned build path, builds the patched node, runs WAM consensus tests, starts a regtest node and probes RandomX RPC state across an epoch transition.

This job is deliberately separate from the fast differential gate because a full node build takes substantially longer. Its result is evidence about the actual patched implementation rather than only the independent models.

## Safety

All chain experiments use a private regtest datadir on the CI runner. No public peer, pool, seed or mainnet/testnet node is contacted for adversarial testing.
