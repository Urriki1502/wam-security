import unittest

from wam_security.fabric.core import Check, build_status, evaluate
from wam_security.fabric.status import (
    baseline_check,
    explorer_health_check,
    fork_check,
    payout_visibility_check,
    pool_health_check,
    release_integrity_check,
    source_drift_check,
    supply_check,
)


class FabricPolicyTests(unittest.TestCase):
    def test_red_only_on_critical_failure(self):
        self.assertEqual(evaluate([
            Check("a", "x", "FAIL", False, "x", {}),
        ]), ("YELLOW", False))
        self.assertEqual(evaluate([
            Check("a", "x", "FAIL", True, "x", {}),
        ]), ("RED", True))
        self.assertEqual(evaluate([
            Check("a", "x", "PASS", True, "x", {}),
        ]), ("GREEN", False))

    def test_status_digest_is_stable_for_same_inputs(self):
        checks = [Check("a", "x", "PASS", True, "ok", {})]
        a = build_status(
            generated_at="2026-10-03T00:00:00Z",
            fabric_version="0.7.0",
            target_repository="repo",
            target_head="1" * 40,
            audited_head="1" * 40,
            checks=checks,
        )
        b = build_status(
            generated_at="2026-10-03T00:00:00Z",
            fabric_version="0.7.0",
            target_repository="repo",
            target_head="1" * 40,
            audited_head="1" * 40,
            checks=checks,
        )
        self.assertEqual(a, b)

    def test_known_baseline_is_not_red(self):
        findings = [
            {"finding_id": "A", "severity": "HIGH"},
            {"finding_id": "B", "severity": "MEDIUM"},
        ]
        c = baseline_check(findings=findings, expected_ids={"A", "B"})
        self.assertEqual(c.state, "PASS")

    def test_new_high_finding_is_critical(self):
        findings = [
            {"finding_id": "A", "severity": "HIGH"},
            {"finding_id": "NEW", "severity": "HIGH"},
        ]
        c = baseline_check(findings=findings, expected_ids={"A"})
        self.assertEqual((c.state, c.critical), ("FAIL", True))

    def test_critical_source_drift_blocks(self):
        c = source_drift_check(
            current_head="2" * 40,
            audited_head="1" * 40,
            changed_paths=["README.md", "src/wam/pow.cpp"],
        )
        self.assertEqual((c.state, c.critical), ("FAIL", True))

    def test_noncritical_source_drift_warns(self):
        c = source_drift_check(
            current_head="2" * 40,
            audited_head="1" * 40,
            changed_paths=["docs/guide.md"],
        )
        self.assertEqual(c.state, "WARN")

    def test_unclassifiable_source_drift_fails_closed(self):
        c = source_drift_check(
            current_head="2" * 40,
            audited_head="1" * 40,
            changed_paths=["<diff-unavailable>"],
        )
        self.assertEqual((c.state, c.critical), ("FAIL", True))

    def test_supply_cap_violation_is_red_class(self):
        c = supply_check({
            "supply": {
                "circulating": 22_000_001 * 100_000_000,
                "maxSupply": 22_000_000 * 100_000_000,
                "source": "node",
            }
        })
        self.assertEqual((c.state, c.critical), ("FAIL", True))

    def test_live_happy_path(self):
        explorer = {
            "nodeOnline": True,
            "staleSeconds": 0,
            "chain": {"blocks": 123},
            "supply": {
                "circulating": 2_100_000 * 100_000_000,
                "maxSupply": 22_000_000 * 100_000_000,
                "source": "node",
            },
        }
        pool = {
            "network": {"height": 124},
            "pool": {"recentPayments": []},
        }
        self.assertEqual(explorer_health_check(explorer).state, "PASS")
        self.assertEqual(supply_check(explorer).state, "PASS")
        self.assertEqual(fork_check(explorer, pool).state, "PASS")
        self.assertEqual(payout_visibility_check(pool).state, "PASS")
        self.assertEqual(pool_health_check({"ok": True}).state, "PASS")

    def test_release_requires_signature_manifest(self):
        ok = release_integrity_check([{
            "tag_name": "v1",
            "assets": [
                {"name": "SHA256SUMS"},
                {"name": "SHA256SUMS.asc"},
                {"name": "wam.tar.gz"},
            ],
        }])
        bad = release_integrity_check([{
            "tag_name": "v1",
            "assets": [{"name": "wam.tar.gz"}],
        }])
        self.assertEqual(ok.state, "PASS")
        self.assertEqual((bad.state, bad.critical), ("FAIL", True))


if __name__ == "__main__":
    unittest.main()
