import tempfile
import unittest
from pathlib import Path

from wam_security.audit.consensus import audit_consensus_constants, parse_wam_params
from wam_security.constants import COIN


GOOD_HEADER = """
static constexpr int64_t WAM_COIN = 100'000'000;
static constexpr int64_t WAM_MAX_MONEY = 22'000'000 * WAM_COIN;
static constexpr int64_t WAM_GENESIS_PREMINE = 2'000'000 * WAM_COIN;
static constexpr int64_t WAM_INITIAL_BLOCK_SUBSIDY = 50 * WAM_COIN;
static constexpr int WAM_SUBSIDY_HALVING_INTERVAL = 200'000;
static constexpr int WAM_MAX_HALVINGS = 33;
static constexpr int64_t WAM_DEVFEE_PERCENT = 5;
static constexpr int WAM_DEVFEE_START_HEIGHT = 1;
static constexpr int WAM_DEVFEE_LAST_HEIGHT = 400'000;
static constexpr int WAM_RANDOMX_EPOCH_BLOCKS = 2048;
static constexpr int WAM_RANDOMX_EPOCH_LAG = 64;
"""


class ConsensusAuditTests(unittest.TestCase):
    def test_parser_evaluates_named_integer_expressions(self):
        parsed = parse_wam_params(GOOD_HEADER)
        self.assertEqual(parsed["WAM_COIN"], COIN)
        self.assertEqual(parsed["WAM_MAX_MONEY"], 22_000_000 * COIN)

    def test_good_constants_do_not_emit_drift(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "src/wam"
            p.mkdir(parents=True)
            (p / "wam-params.h").write_text(GOOD_HEADER, encoding="utf-8")
            self.assertEqual(audit_consensus_constants(td), [])

    def test_changed_halving_interval_is_release_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "src/wam"
            p.mkdir(parents=True)
            (p / "wam-params.h").write_text(
                GOOD_HEADER.replace("200'000", "210'000"), encoding="utf-8"
            )
            findings = audit_consensus_constants(td)
            self.assertTrue(any(f.finding_id == "WS-CONS-001" for f in findings))


if __name__ == "__main__":
    unittest.main()
