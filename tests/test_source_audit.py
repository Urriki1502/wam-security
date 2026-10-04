import tempfile
import unittest
from pathlib import Path

from wam_security.audit.source import audit_wam_source
from wam_security.audit.workflow import audit_workflows


PATCHED_SHARE = r"""
async _processPayments() {
  await this.redis.set(this.k('payment:inflight'), JSON.stringify(intent));
  try {
    txid = await this.daemon.cmd('sendmany', ['', sendMany]);
  } catch (err) {
    if (err.ambiguous !== false) {
      this.paused = true;
      return;
    }
    await this.redis.del(this.k('payment:inflight'));
    return;
  }
}
async pruneHashrateWindow() {}
"""

PATCHED_DAEMON = r"""
async cmd(method, params = []) {
  const ordered = [...this.daemons];
  const guarded = DaemonInterface.MONEY_RPCS.has(method);
  let anyAmbiguous = false;
  for (const d of ordered) {
    try {
      return await this._request(d, method, params);
    } catch (err) {
      anyAmbiguous = anyAmbiguous || Boolean(err.ambiguous);
      if (guarded && err.ambiguous) throw err;
    }
  }
  const e = new Error('all failed');
  e.ambiguous = anyAmbiguous;
  throw e;
}
DaemonInterface.MONEY_RPCS = new Set([
  'sendmany', 'sendtoaddress', 'sendfrom', 'send', 'sendall'
]);
"""


class SourceAuditTests(unittest.TestCase):
    def test_detects_ambiguous_sendmany_intent_delete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pool/lib").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "pool/lib/shareProcessor.js").write_text(
                "async _processPayments() { "
                "try { txid = await this.daemon.cmd('sendmany', ['', sendMany]); } "
                "catch (err) { await this.redis.del(this.k('payment:inflight')); } "
                "} async pruneHashrateWindow() {}",
                encoding="utf-8",
            )
            (root / "pool/lib/daemon.js").write_text(
                "async cmd(method, params=[]) { for (const d of ordered) { "
                "await this._request(d, method, params); } }",
                encoding="utf-8",
            )
            findings = audit_wam_source(root)
            ids = {f.finding_id for f in findings}
            self.assertIn("WS-POOL-001", ids)
            self.assertIn("WS-POOL-002", ids)

    def test_maintainer_guard_shape_clears_pool_findings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pool/lib").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "pool/lib/shareProcessor.js").write_text(
                PATCHED_SHARE, encoding="utf-8"
            )
            (root / "pool/lib/daemon.js").write_text(
                PATCHED_DAEMON, encoding="utf-8"
            )
            ids = {f.finding_id for f in audit_wam_source(root)}
            self.assertNotIn("WS-POOL-001", ids)
            self.assertNotIn("WS-POOL-002", ids)

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
