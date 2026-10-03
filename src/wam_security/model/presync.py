"""Minimal model for the header pre-sync anti-DoS security property.

This intentionally does not implement networking or RandomX. It captures the
invariant that claimed chainwork is not equivalent to verified proof of work.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class HeaderClaim:
    claimed_work: int
    pow_verified: bool


def validated_work(headers: list[HeaderClaim], require_pow: bool = True) -> int:
    total = 0
    for header in headers:
        if header.claimed_work <= 0:
            raise ValueError("claimed work must be positive")
        if require_pow and not header.pow_verified:
            raise ValueError("unverified proof of work cannot contribute security work")
        total += header.claimed_work
    return total
