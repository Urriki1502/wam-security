"""Independent copies of WAM monetary constants used by the reference model.

These values are intentionally not imported from wam-coin. Differential testing
is useful only when the implementation and reference model can disagree.
"""

COIN = 100_000_000
MAX_MONEY = 22_000_000 * COIN
GENESIS_PREMINE = 2_000_000 * COIN
INITIAL_BLOCK_SUBSIDY = 50 * COIN
HALVING_INTERVAL = 200_000
MAX_HALVINGS = 33
DEVFEE_PERCENT = 5
DEVFEE_START_HEIGHT = 1
DEVFEE_LAST_HEIGHT = 400_000
RANDOMX_EPOCH_BLOCKS = 2_048
RANDOMX_EPOCH_LAG = 64
