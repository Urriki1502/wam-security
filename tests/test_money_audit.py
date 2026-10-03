import tempfile
import unittest
from pathlib import Path

from wam_security.audit.money import audit_money_safety


SHARE = r"""
this.startupReconcile().catch((e) => this.log.error(e.message));
const intent = { startedAt: Date.now(), total: batchTotal, payouts: Object.fromEntries(batch) };
await this.redis.set(this.k('payment:inflight'), JSON.stringify(intent));
try {
  txid = await this.daemon.cmd('sendmany', ['', sendMany]);
} catch (err) {
  await this.redis.del(this.k('payment:inflight'));
}
const pipe = this.redis.pipeline();
pipe.hincrby(this.k('balances'), address, -amount);
pipe.hincrby(this.k('paid'), address, amount);
pipe.del(this.k('payment:inflight'));
"""

DAEMON = r"""
async cmd(method, params = []) {
  for (const d of ordered) {
    try { return await this._request(d, method, params); } catch (err) {}
  }
}
"""


class MoneyAuditTests(unittest.TestCase):
    def _tree(self, share=SHARE, daemon=DAEMON, config='{"wallet": "pool"}'):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "pool/lib").mkdir(parents=True)
        (root / "pool/lib/shareProcessor.js").write_text(share, encoding="utf-8")
        (root / "pool/lib/daemon.js").write_text(daemon, encoding="utf-8")
        (root / "pool/config.mainnet.json").write_text(config, encoding="utf-8")
        return td, root

    def test_current_shape_emits_money_findings(self):
        td, root = self._tree()
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_money_safety(root)}
        self.assertEqual(ids, {
            "WS-MONEY-101",
            "WS-MONEY-102",
            "WS-MONEY-103",
            "WS-MONEY-104",
            "WS-MONEY-105",
            "WS-MONEY-106",
        })

    def test_prebuilt_identity_atomic_commit_shape_clears_core_findings(self):
        safer = r"""
await this.startupReconcile();
const intent = { txid, raw_tx, payouts, wallet: 'pool' };
await this.redis.set(this.k('payment:inflight'), JSON.stringify(intent));
await this.daemon.broadcastRawTransaction(raw_tx);
await redis.eval(commitPaymentLua, 4, balances, paid, inflight, payments);
"""
        safe_daemon = r"""
async readCmd(method, params = []) {
  for (const d of ordered) { try { return await this._request(d, method, params); } catch (e) {} }
}
async broadcastRawTransaction(raw) { return this._request(this.payoutDaemon, 'sendrawtransaction', [raw]); }
"""
        td, root = self._tree(share=safer, daemon=safe_daemon)
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_money_safety(root)}
        self.assertTrue(ids.isdisjoint({
            "WS-MONEY-101", "WS-MONEY-102", "WS-MONEY-103", "WS-MONEY-104",
            "WS-MONEY-105", "WS-MONEY-106",
        }))

    def test_missing_named_wallet_is_high(self):
        td, root = self._tree(config='{}')
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_money_safety(root)}
        self.assertIn("WS-MONEY-107", ids)


if __name__ == "__main__":
    unittest.main()
