import tempfile
import unittest
from pathlib import Path

from wam_security.audit.source import audit_wam_source
from wam_security.audit.workflow import audit_workflows


class SourceAuditTests(unittest.TestCase):
    def test_detects_ambiguous_sendmany_intent_delete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pool/lib").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "pool/lib/shareProcessor.js").write_text(
                "try { txid = await this.daemon.cmd('sendmany', ['', sendMany]); } "
                "catch (err) { await this.redis.del(this.k('payment:inflight')); }",
                encoding="utf-8",
            )
            (root / "pool/lib/daemon.js").write_text(
                "async cmd(method, params=[]) { for (const d of ordered) { await this._request(d, method, params); } }",
                encoding="utf-8",
            )
            findings = audit_wam_source(root)
            ids = {f.finding_id for f in findings}
            self.assertIn("WS-POOL-001", ids)
            self.assertIn("WS-POOL-002", ids)

    def test_detects_presync_pow_bypass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "scripts").mkdir(parents=True)
            (root / "scripts/patch_upstream.py").write_text(
                "bool HasValidProofOfWork(...) { // WAM_PRESYNC_POW_SKIPPED\n return true; }",
                encoding="utf-8",
            )
            ids = {f.finding_id for f in audit_wam_source(root)}
            self.assertIn("WS-P2P-001", ids)

    def test_detects_mutable_action_ref(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/ci.yml").write_text(
                "steps:\n - uses: actions/checkout@v5\n", encoding="utf-8"
            )
            ids = {f.finding_id for f in audit_workflows(root)}
            self.assertIn("WS-SC-001", ids)


if __name__ == "__main__":
    unittest.main()
