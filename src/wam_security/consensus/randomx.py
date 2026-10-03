"""Independent RandomX epoch/seed and reorg-boundary model."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RandomXProfile:
    name: str
    epoch_blocks: int
    epoch_lag: int

    def __post_init__(self) -> None:
        if self.epoch_blocks <= 0:
            raise ValueError("epoch_blocks must be positive")
        if self.epoch_lag < 0 or self.epoch_lag >= self.epoch_blocks:
            raise ValueError("epoch_lag must satisfy 0 <= lag < epoch")


MAINNET = RandomXProfile("mainnet", 2048, 64)
TESTNET = RandomXProfile("testnet", 256, 16)
REGTEST = RandomXProfile("regtest", 64, 4)


def seed_height(height: int, profile: RandomXProfile) -> int:
    if height < 0:
        raise ValueError("height must be non-negative")
    if height <= profile.epoch_lag:
        return 0
    lagged = height - profile.epoch_lag
    return (lagged // profile.epoch_blocks) * profile.epoch_blocks


def seed_hash_for_candidate(
    candidate_height: int,
    ancestor_hashes: dict[int, str],
    profile: RandomXProfile,
    bootstrap_seed: str = "bootstrap",
) -> str:
    """Model GetRandomXSeedHash using the candidate's parent ancestry."""
    sh = seed_height(candidate_height, profile)
    if sh == 0:
        return bootstrap_seed
    return ancestor_hashes.get(sh, bootstrap_seed)


def reorg_changes_seed(
    candidate_height: int,
    parent_height: int,
    reorg_depth: int,
    profile: RandomXProfile,
) -> bool:
    """Whether replacing the last reorg_depth parent-chain blocks can touch seed."""
    if reorg_depth < 0:
        raise ValueError("reorg_depth must be non-negative")
    sh = seed_height(candidate_height, profile)
    if sh == 0 or reorg_depth == 0:
        return False
    first_replaced = parent_height - reorg_depth + 1
    return first_replaced <= sh <= parent_height
