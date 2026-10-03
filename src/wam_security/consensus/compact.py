"""Bitcoin-style compact target encoding used by WAM proof of work."""

from __future__ import annotations


def compact_to_target(compact: int) -> tuple[int, bool, bool]:
    if compact < 0 or compact > 0xFFFFFFFF:
        raise ValueError("compact must fit uint32")

    size = compact >> 24
    word = compact & 0x007FFFFF
    negative = bool(word and (compact & 0x00800000))

    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))

    overflow = bool(
        word
        and (
            size > 34
            or (word > 0xFF and size > 33)
            or (word > 0xFFFF and size > 32)
        )
    )
    return target, negative, overflow


def target_to_compact(target: int, negative: bool = False) -> int:
    if target < 0:
        raise ValueError("target must be non-negative")
    if target == 0:
        return 0

    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))

    if compact & 0x00800000:
        compact >>= 8
        size += 1

    compact &= 0x007FFFFF
    compact |= size << 24
    if negative and (compact & 0x007FFFFF):
        compact |= 0x00800000
    return compact & 0xFFFFFFFF
