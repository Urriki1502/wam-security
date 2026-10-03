import tempfile
import unittest
from pathlib import Path

from wam_security.audit.consensus_semantics import audit_consensus_semantics


GOOD_POW = """
const int64_t nPastBlocks = WAM_DGW_PAST_BLOCKS;
bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);
nActualTimespan = nTargetTimespan / WAM_DGW_CLAMP_FACTOR;
nActualTimespan = nTargetTimespan * WAM_DGW_CLAMP_FACTOR;
if (bnNew > bnPowLimit) bnNew = bnPowLimit;
"""

GOOD_RX = """
const int nEpoch = params.nRandomXEpochBlocks;
const int nLag = params.nRandomXEpochLag;
if (nHeight <= nLag) return 0;
const int nLagged = nHeight - nLag;
return (nLagged / nEpoch) * nEpoch;
pindexPrev->GetAncestor(nSeedHeight);
"""

GOOD_CHAIN = """
consensus.nRandomXEpochBlocks = WAM_RANDOMX_EPOCH_BLOCKS;
consensus.nRandomXEpochLag = WAM_RANDOMX_EPOCH_LAG;
consensus.nRandomXEpochBlocks = 256;
consensus.nRandomXEpochLag = 16;
consensus.nRandomXEpochBlocks = 64;
consensus.nRandomXEpochLag = 4;
"""


class ConsensusSemanticsAuditTests(unittest.TestCase):
    def _tree(self, pow_text=GOOD_POW, rx_text=GOOD_RX, chain_text=GOOD_CHAIN):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "src/wam/crypto").mkdir(parents=True)
        (root / "src/wam/pow.cpp").write_text(pow_text, encoding="utf-8")
        (root / "src/wam/crypto/randomx_hash.cpp").write_text(rx_text, encoding="utf-8")
        (root / "src/wam/chainparams.cpp").write_text(chain_text, encoding="utf-8")
        return td, root

    def test_expected_semantics_are_clean(self):
        td, root = self._tree()
        self.addCleanup(td.cleanup)
        self.assertEqual(audit_consensus_semantics(root), [])

    def test_dgw_recurrence_drift_is_high(self):
        td, root = self._tree(pow_text=GOOD_POW.replace(
            "(bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1)",
            "(bnPastTargetAvg + bnTarget) / 2",
        ))
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_consensus_semantics(root)}
        self.assertIn("WS-CONS-101", ids)

    def test_randomx_profile_drift_is_high(self):
        td, root = self._tree(chain_text=GOOD_CHAIN.replace(
            "consensus.nRandomXEpochBlocks = 64;",
            "consensus.nRandomXEpochBlocks = 65;",
        ))
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_consensus_semantics(root)}
        self.assertIn("WS-CONS-103", ids)


if __name__ == "__main__":
    unittest.main()
