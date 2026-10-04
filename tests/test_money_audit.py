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


PATCHED_SHARE = r"""
start() {
  this.paused = true;
  this.startupReconcile().catch((e) => this.log.error(e.message));
}
stop() {}

async _processPayments() {
  const intent = { startedAt: Date.now(), total: batchTotal, payouts: Object.fromEntries(batch) };
  await this.redis.set(this.k('payment:inflight'), JSON.stringify(intent));

  let txid;
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

  const pipe = this.redis.multi();
  pipe.hincrby(this.k('balances'), address, -amount);
  pipe.hincrby(this.k('paid'), address, amount);
  pipe.del(this.k('payment:inflight'));
  await pipe.exec();
}

async pruneHashrateWindow() {}
"""

PATCHED_DAEMON = r"""
async cmd(method, params = []) {
  const ordered = [...this.daemons];
  const guarded = DaemonInterface.MONEY_RPCS.has(method);
  let lastError;
  let anyAmbiguous = false;
  for (const d of ordered) {
    try {
      return await this._request(d, method, params);
    } catch (err) {
      lastError = err;
      anyAmbiguous = anyAmbiguous || Boolean(err.ambiguous);
      if (guarded && err.ambiguous) {
        throw err;
      }
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
start() {
  await this.startupReconcile();
}
stop() {}

async _processPayments() {
  const intent = { txid, raw_tx, payouts, wallet: 'pool' };
  await this.redis.set(this.k('payment:inflight'), JSON.stringify(intent));
  await this.daemon.broadcastRawTransaction(raw_tx);
  await redis.eval(commitPaymentLua, 4, balances, paid, inflight, payments);
}
async pruneHashrateWindow() {}
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

    def test_maintainer_patch_closes_four_fixed_findings_but_keeps_identity_findings(self):
        td, root = self._tree(share=PATCHED_SHARE, daemon=PATCHED_DAEMON)
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_money_safety(root)}
        self.assertIn("WS-MONEY-101", ids)
        self.assertIn("WS-MONEY-102", ids)
        self.assertTrue(ids.isdisjoint({
            "WS-MONEY-103",
            "WS-MONEY-104",
            "WS-MONEY-105",
            "WS-MONEY-106",
        }))

    def test_comments_describing_old_pipeline_do_not_reopen_fixed_finding(self):
        share = PATCHED_SHARE.replace(
            "const pipe = this.redis.multi();",
            "// old code: const pipe = this.redis.pipeline();\n"
            "const pipe = this.redis.multi();",
        )
        td, root = self._tree(share=share, daemon=PATCHED_DAEMON)
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_money_safety(root)}
        self.assertNotIn("WS-MONEY-104", ids)

    def test_missing_named_wallet_is_high(self):
        td, root = self._tree(config='{}')
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_money_safety(root)}
        self.assertIn("WS-MONEY-107", ids)


if __name__ == "__main__":
    unittest.main()
