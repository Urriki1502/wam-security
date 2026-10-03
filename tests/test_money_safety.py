import unittest

from wam_security.money.model import (
    COIN,
    ChainSimulator,
    IntentState,
    MoneyLedger,
    PaymentPolicy,
)


def policy(**kw):
    values = dict(
        payout_wallet="pool",
        max_recipients=5,
        max_batch=10_000,
        max_recipient=8_000,
        max_fee=100,
        max_daily_spend=20_000,
    )
    values.update(kw)
    return PaymentPolicy(**values)


class MoneySafetyModelTests(unittest.TestCase):
    def test_timeout_after_accept_reconciles_same_identity(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        chain = ChainSimulator()
        intent = ledger.reserve({"alice": 600}, wallet="pool")
        txid = ledger.sign(fee=10)
        raw = intent.raw_tx
        self.assertIsNone(ledger.broadcast(chain, "accept-timeout"))
        self.assertEqual(ledger.active.state, IntentState.BROADCAST_UNKNOWN)

        restarted = MoneyLedger.restore(ledger.snapshot())
        self.assertTrue(restarted.reconcile(chain))
        self.assertEqual(restarted.active.txid, txid)
        self.assertEqual(restarted.active.raw_tx, raw)
        restarted.commit_atomic()
        chain.assert_at_most_once(intent.intent_id)
        self.assertEqual(restarted.balances["alice"], 400)
        self.assertEqual(restarted.paid["alice"], 600)

    def test_timeout_before_accept_rebroadcasts_same_raw_transaction(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        chain = ChainSimulator()
        intent = ledger.reserve({"alice": 600}, wallet="pool")
        txid = ledger.sign()
        raw = intent.raw_tx
        ledger.broadcast(chain, "drop-timeout")
        self.assertFalse(ledger.reconcile(chain))
        ledger.broadcast(chain, "accept-ack")
        self.assertEqual(ledger.active.txid, txid)
        self.assertEqual(ledger.active.raw_tx, raw)
        ledger.commit_atomic()
        chain.assert_at_most_once(intent.intent_id)

    def test_same_intent_cannot_be_re_signed_to_new_identity(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        intent = ledger.reserve({"alice": 500}, wallet="pool")
        first = ledger.sign(fee=10)
        raw = intent.raw_tx
        second = ledger.sign(fee=10)
        self.assertEqual(first, second)
        self.assertEqual(raw, intent.raw_tx)

    def test_new_credit_during_inflight_is_not_erased(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        chain = ChainSimulator()
        ledger.reserve({"alice": 600}, wallet="pool")
        ledger.sign()
        ledger.credit("alice", 250)
        ledger.broadcast(chain, "accept-ack")
        ledger.commit_atomic()
        self.assertEqual(ledger.balances["alice"], 650)
        ledger.assert_conservation()

    def test_unresolved_intent_blocks_concurrent_payment(self):
        ledger = MoneyLedger({"alice": 1000, "bob": 1000}, policy=policy())
        ledger.reserve({"alice": 500}, wallet="pool")
        with self.assertRaises(RuntimeError):
            ledger.reserve({"bob": 500}, wallet="pool")

    def test_attempted_intent_cannot_be_cancelled(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        chain = ChainSimulator()
        ledger.reserve({"alice": 500}, wallet="pool")
        ledger.sign()
        ledger.broadcast(chain, "drop-timeout")
        with self.assertRaises(RuntimeError):
            ledger.cancel_before_broadcast()

    def test_policy_rejects_wrong_wallet_and_limits(self):
        ledger = MoneyLedger({"alice": 20_000, "bob": 20_000}, policy=policy())
        with self.assertRaises(PermissionError):
            ledger.reserve({"alice": 100}, wallet="default")
        with self.assertRaises(ValueError):
            ledger.reserve({"alice": 9_000}, wallet="pool")
        with self.assertRaises(ValueError):
            ledger.reserve({"alice": 6_000, "bob": 6_000}, wallet="pool")

    def test_fee_limit_is_enforced_before_broadcast(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        ledger.reserve({"alice": 500}, wallet="pool")
        with self.assertRaises(ValueError):
            ledger.sign(fee=101)

    def test_atomic_commit_requires_observed_transaction(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        ledger.reserve({"alice": 500}, wallet="pool")
        ledger.sign()
        with self.assertRaises(RuntimeError):
            ledger.commit_atomic()

    def test_commit_response_loss_does_not_recreate_debt(self):
        ledger = MoneyLedger({"alice": 1000}, policy=policy())
        chain = ChainSimulator()
        intent = ledger.reserve({"alice": 500}, wallet="pool")
        ledger.sign()
        ledger.broadcast(chain, "accept-ack")
        txid = ledger.commit_atomic()
        durable = ledger.snapshot()  # caller "crashes" before seeing success

        restarted = MoneyLedger.restore(durable)
        self.assertIsNone(restarted.active)
        self.assertIn(txid, restarted.completed_txids)
        self.assertEqual(restarted.balances["alice"], 500)
        chain.assert_at_most_once(intent.intent_id)

    def test_wam_scale_policy_uses_base_units(self):
        p = PaymentPolicy(payout_wallet="pool")
        self.assertEqual(p.max_batch, 100_000 * COIN)


if __name__ == "__main__":
    unittest.main()
