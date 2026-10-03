"""Local model of WAM/Bitcoin-Core header pre-sync work accounting.

This module does not perform network I/O or RandomX hashing.  It models the
security invariant relevant to the pre-sync anti-DoS gate: work may only be
credited after proof-of-work evidence for that header has been established.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SyntheticHeader:
    """Synthetic local fixture.

    claimed_work is an abstract positive work unit derived from nBits.
    pow_valid represents whether the header has independently-established PoW
    evidence.  No real header, peer, node, or network traffic is involved.
    """

    claimed_work: int
    pow_valid: bool

    def __post_init__(self) -> None:
        if self.claimed_work <= 0:
            raise ValueError("claimed_work must be positive")


@dataclass(frozen=True)
class PresyncResult:
    credited_work: int
    verified_work: int
    reached_threshold: bool
    invalid_headers_credited: int


def model_presync(
    headers: Iterable[SyntheticHeader],
    threshold: int,
    *,
    require_pow_evidence: bool,
) -> PresyncResult:
    """Model the work-accounting consequence of the pre-sync PoW gate.

    When require_pow_evidence=False this represents the current WAM patch shape
    where the early HasValidProofOfWork gate unconditionally succeeds and
    pre-sync can account work from nBits before contextual RandomX validation.

    When require_pow_evidence=True this represents the invariant we want to
    hold: only headers with established PoW evidence may contribute work.
    """

    if threshold <= 0:
        raise ValueError("threshold must be positive")

    credited = 0
    verified = 0
    invalid_credited = 0

    for header in headers:
        if header.pow_valid:
            verified += header.claimed_work

        if require_pow_evidence and not header.pow_valid:
            continue

        credited += header.claimed_work
        if not header.pow_valid:
            invalid_credited += 1

    return PresyncResult(
        credited_work=credited,
        verified_work=verified,
        reached_threshold=credited >= threshold,
        invalid_headers_credited=invalid_credited,
    )


def contextual_randomx_accepts(header: SyntheticHeader) -> bool:
    """Model the later contextual RandomX validity decision.

    The WAM source performs its real RandomX check with chain context later in
    ContextualCheckBlockHeader.  This keeps consensus acceptance separate from
    the earlier anti-DoS accounting question.
    """

    return header.pow_valid
