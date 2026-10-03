import unittest

from wam_security.model.payment import PaymentState, new_intent


class PaymentStateMachineTests(unittest.TestCase):
    def test_timeout_never_discards_identity(self):
        p = new_intent({"wam1alice": 100, "wam1bob": 200})
        txid = p.prepare()
        p.broadcast_result(None)
        self.assertEqual(p.state, PaymentState.BROADCAST_UNKNOWN)
        self.assertEqual(p.prepare(), txid)
        p.assert_safe()

    def test_unknown_then_seen_commits_once(self):
        p = new_intent({"wam1alice": 100})
        p.prepare()
        p.broadcast_result(None)
        p.reconcile(True)
        p.commit()
        p.assert_safe()
        self.assertEqual(p.economic_payments, 1)

    def test_unknown_then_not_seen_reuses_same_transaction_identity(self):
        p = new_intent({"wam1alice": 100})
        txid = p.prepare()
        raw = p.raw_tx
        p.broadcast_result(None)
        p.reconcile(False)
        self.assertEqual(p.state, PaymentState.PREPARED)
        self.assertEqual(p.txid, txid)
        self.assertEqual(p.raw_tx, raw)
        p.broadcast_result(True)
        p.commit()
        p.assert_safe()

    def test_cannot_clear_balance_while_broadcast_is_unknown(self):
        p = new_intent({"wam1alice": 100})
        p.prepare()
        p.broadcast_result(None)
        with self.assertRaises(ValueError):
            p.commit()


if __name__ == "__main__":
    unittest.main()
