# WAM Security V1 Threat Model

## Mission

WAM Security is an independent verifier for the WAM ecosystem. It does not replace `wam-coin` security policy, reviews, or bug bounty. It turns critical security assumptions into executable invariants and reproducible evidence.

## Protected assets

1. **Consensus integrity** — honest nodes given the same valid history must reach the same result.
2. **Monetary integrity** — issued supply never exceeds policy; treasury is carved from subsidy, never added to it.
3. **Funds safety** — a logical payout or wallet intent must never create more than one economic payment.
4. **Network availability** — unauthenticated peers/miners/API callers must not cheaply exhaust node or pool resources.
5. **Release integrity** — an artifact must be traceable to reviewed source and immutable dependencies.
6. **Privacy** — public infrastructure must not enumerate miner identities, wallet secrets, or silent-payment scan secrets.

## Adversaries

- remote unauthenticated P2P peer;
- hostile or malformed Stratum miner;
- malicious HTTP/API client;
- compromised dependency or mutable CI action;
- partial infrastructure failure (RPC timeout, Redis outage, process crash, disk full);
- honest operator making a dangerous retry after ambiguous state;
- malicious contributor attempting to hide a consensus or release change inside a normal patch.

## V1 trust boundaries

V1 treats Bitcoin Core inherited code as upstream and focuses automated review on WAM-owned deltas, integrations and release machinery. This is a prioritization boundary, not a claim that upstream code is bug-free.

V1 scans a pinned upstream WAM commit. Findings must name that commit and distinguish:

- **confirmed logic risk** — source is sufficient to establish the unsafe state transition;
- **review required** — security property is weakened, but exploitability/severity still requires a controlled reproduction;
- **hardening gap** — not a demonstrated vulnerability, but avoidable trust remains.

## Safety rule

No finding is validated against public production infrastructure. Reproduction belongs on local fixtures, regtest/testnet, or code owned by the project.
