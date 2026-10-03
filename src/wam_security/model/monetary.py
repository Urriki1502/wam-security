"""Independent monetary-policy reference model for WAM."""

from __future__ import annotations

from wam_security.constants import (
    DEVFEE_LAST_HEIGHT,
    DEVFEE_PERCENT,
    DEVFEE_START_HEIGHT,
    GENESIS_PREMINE,
    HALVING_INTERVAL,
    INITIAL_BLOCK_SUBSIDY,
    MAX_HALVINGS,
    MAX_MONEY,
)


def block_subsidy(height: int) -> int:
    """Return subsidy in base units for height using only integer arithmetic."""
    if height < 0:
        return 0
    if height == 0:
        return GENESIS_PREMINE
    halvings = (height - 1) // HALVING_INTERVAL
    if halvings >= MAX_HALVINGS:
        return 0
    return INITIAL_BLOCK_SUBSIDY >> halvings


def treasury_amount(subsidy: int, height: int) -> int:
    """Return the consensus treasury floor in base units."""
    if subsidy <= 0:
        return 0
    if not (DEVFEE_START_HEIGHT <= height <= DEVFEE_LAST_HEIGHT):
        return 0
    return (subsidy * DEVFEE_PERCENT) // 100


def miner_subsidy(height: int) -> int:
    subsidy = block_subsidy(height)
    return subsidy - treasury_amount(subsidy, height)


def total_supply_at_height(height: int) -> int:
    """Closed-form supply model mirroring the intended schedule, not C++ code."""
    if height < 0:
        return 0
    supply = GENESIS_PREMINE
    if height == 0:
        return supply

    completed_epochs = (height - 1) // HALVING_INTERVAL
    for epoch in range(min(completed_epochs, MAX_HALVINGS)):
        supply += HALVING_INTERVAL * (INITIAL_BLOCK_SUBSIDY >> epoch)

    if completed_epochs < MAX_HALVINGS:
        blocks_into_epoch = ((height - 1) % HALVING_INTERVAL) + 1
        supply += blocks_into_epoch * (INITIAL_BLOCK_SUBSIDY >> completed_epochs)

    if supply > MAX_MONEY:
        raise AssertionError(f"supply invariant violated: {supply} > {MAX_MONEY}")
    return supply


def lifetime_treasury() -> int:
    total = 0
    for epoch in range(MAX_HALVINGS):
        subsidy = INITIAL_BLOCK_SUBSIDY >> epoch
        if subsidy == 0:
            break
        first = epoch * HALVING_INTERVAL + 1
        if first > DEVFEE_LAST_HEIGHT:
            break
        last = min((epoch + 1) * HALVING_INTERVAL, DEVFEE_LAST_HEIGHT)
        total += (last - first + 1) * treasury_amount(subsidy, first)
    return total
