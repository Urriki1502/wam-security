"""Independent DarkGravityWave v3 model matching WAM's consensus recurrence."""

from __future__ import annotations

from dataclasses import dataclass

from wam_security.consensus.compact import compact_to_target, target_to_compact


@dataclass(frozen=True)
class DgwBlock:
    height: int
    timestamp: int
    bits: int


@dataclass(frozen=True)
class DgwParams:
    pow_limit: int
    target_spacing: int = 120
    past_blocks: int = 24
    clamp_factor: int = 3


def dark_gravity_wave(history_newest_first: list[DgwBlock], params: DgwParams) -> int:
    """Return compact target for the block after history[0].

    The model intentionally follows WAM's exact integer recurrence rather than
    replacing it with a mathematically nicer average.
    """
    if not history_newest_first:
        return target_to_compact(params.pow_limit)

    last = history_newest_first[0]
    if last.height < params.past_blocks:
        return target_to_compact(params.pow_limit)
    if len(history_newest_first) < params.past_blocks:
        raise ValueError("DGW history is incomplete for a retargeting height")

    window = history_newest_first[: params.past_blocks]
    average = 0
    for count, block in enumerate(window, start=1):
        target, negative, overflow = compact_to_target(block.bits)
        if negative or overflow or target <= 0:
            raise ValueError(f"invalid compact target at height {block.height}")
        if count == 1:
            average = target
        else:
            average = (average * count + target) // (count + 1)

    actual = window[0].timestamp - window[-1].timestamp
    expected = params.past_blocks * params.target_spacing
    minimum = expected // params.clamp_factor
    maximum = expected * params.clamp_factor
    actual = max(minimum, min(maximum, actual))

    new_target = average * actual // expected
    new_target = min(new_target, params.pow_limit)
    return target_to_compact(new_target)


def check_pow_hash(hash_value: int, bits: int, pow_limit: int) -> bool:
    target, negative, overflow = compact_to_target(bits)
    if negative or overflow or target == 0 or target > pow_limit:
        return False
    return 0 <= hash_value <= target
