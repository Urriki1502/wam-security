import unittest

from wam_security.block_spool.model import (
    AccountingLedger,
    AccountingWriteError,
    DurableStore,
    DurableWriteError,
    Phase,
    RecoveryContext,
    RecoveryEngine,
)


def context(block_hash="11" * 32):
    return RecoveryContext(
        block_hash=block_hash,
        raw_hex="deadbeef",
        share={
            "height": 20001,
            "worker": "alice",
            "difficulty": 0.001,
            "jobId": "job-20001",
            "distributableValue": 4_750_000_000,
            "coinbaseValue": 5_000_000_000,
            "devFeeAmount": 250_000_000,
            "time": 1_791_156_800_000,
        },
    )


class BlockSpoolRecoveryModel(unittest.TestCase):
    def engine(self, ctx=None):
        store = DurableStore()
        ledger = AccountingLedger()
        engine = RecoveryEngine(store, ledger)
        ctx = ctx or context()
        engine.prepare_candidate(ctx)
        return engine, ctx

    def test_crash_after_spool_before_submit_recovers(self):
        engine, ctx = self.engine()
        self.assertTrue(engine.store.submit_ready(ctx.block_hash))

        # Restart: durable store/ledger survive, process-local call stack does not.
        restarted = RecoveryEngine(engine.store, engine.ledger)
        self.assertEqual(restarted.recover(ctx.block_hash, "accepted"), "ACCOUNTED")
        self.assertIn(ctx.block_hash, restarted.ledger.pending_blocks)
        self.assertNotIn(ctx.block_hash, restarted.store.live)

    def test_crash_after_node_accept_before_state_update_recovers_via_duplicate(self):
        engine, ctx = self.engine()

        # Node accepted, process died before mark_accepted. The spool is still
        # SPOOLED. On restart the same bytes are offered again and node says duplicate.
        restarted = RecoveryEngine(engine.store, engine.ledger)
        self.assertEqual(
            restarted.recover(ctx.block_hash, "duplicate", active_chain=True),
            "ACCOUNTED",
        )
        self.assertEqual(restarted.ledger.accounting_applications, 1)

    def test_crash_after_acceptance_before_accounting_record(self):
        engine, ctx = self.engine()
        engine.store.mark_accepted(ctx.block_hash)

        restarted = RecoveryEngine(engine.store, engine.ledger)
        self.assertEqual(restarted.resume_accepted(ctx.block_hash), "ACCOUNTED")
        self.assertEqual(restarted.ledger.accounting_applications, 1)

    def test_restart_duplicate_requires_chain_membership_and_accounts_once(self):
        engine, ctx = self.engine()
        self.assertEqual(
            engine.recover(ctx.block_hash, "duplicate", active_chain=None),
            "CHAIN_STATUS_REQUIRED",
        )
        self.assertIn(ctx.block_hash, engine.store.live)
        self.assertEqual(
            engine.recover(ctx.block_hash, "duplicate", active_chain=True),
            "ACCOUNTED",
        )

    def test_restart_inconclusive_active_and_inactive_are_distinct(self):
        active, ctx = self.engine()
        self.assertEqual(
            active.recover(ctx.block_hash, "inconclusive", active_chain=True),
            "ACCOUNTED",
        )

        inactive_ctx = context("22" * 32)
        inactive, _ = self.engine(inactive_ctx)
        self.assertEqual(
            inactive.recover(
                inactive_ctx.block_hash,
                "inconclusive",
                active_chain=False,
            ),
            "LOST_RACE",
        )
        self.assertNotIn(inactive_ctx.block_hash, inactive.ledger.accounted)
        self.assertEqual(
            inactive.store.terminal[inactive_ctx.block_hash].phase,
            Phase.LOST_RACE,
        )

    def test_restart_duplicate_inconclusive_uses_same_chain_check(self):
        engine, ctx = self.engine()
        self.assertEqual(
            engine.recover(
                ctx.block_hash,
                "duplicate-inconclusive",
                active_chain=True,
            ),
            "ACCOUNTED",
        )
        self.assertEqual(engine.ledger.accounting_applications, 1)

    def test_repeated_drain_after_accounting_is_idempotent(self):
        engine, ctx = self.engine()
        self.assertEqual(
            engine.recover(
                ctx.block_hash,
                "accepted",
                crash_after_accounting=True,
            ),
            "CRASHED_AFTER_ACCOUNTING",
        )
        self.assertEqual(engine.ledger.accounting_applications, 1)
        self.assertIn(ctx.block_hash, engine.store.live)

        restarted = RecoveryEngine(engine.store, engine.ledger)
        self.assertEqual(restarted.resume_accepted(ctx.block_hash), "ALREADY_ACCOUNTED")
        self.assertEqual(restarted.ledger.accounting_applications, 1)
        self.assertNotIn(ctx.block_hash, restarted.store.live)

    def test_accounting_write_failure_keeps_accepted_recovery_entry(self):
        engine, ctx = self.engine()
        with self.assertRaises(AccountingWriteError):
            engine.recover(
                ctx.block_hash,
                "accepted",
                accounting_fail_before=True,
            )

        self.assertIn(ctx.block_hash, engine.store.live)
        self.assertEqual(
            engine.store.live[ctx.block_hash].phase,
            Phase.ACCEPTED_UNACCOUNTED,
        )
        self.assertNotIn(ctx.block_hash, engine.ledger.accounted)

        restarted = RecoveryEngine(engine.store, engine.ledger)
        self.assertEqual(restarted.resume_accepted(ctx.block_hash), "ACCOUNTED")

    def test_lost_accounting_ack_is_safe_to_retry(self):
        engine, ctx = self.engine()
        self.assertEqual(
            engine.recover(
                ctx.block_hash,
                "accepted",
                accounting_fail_after=True,
            ),
            "ACCOUNTED",
        )
        self.assertEqual(engine.ledger.accounting_applications, 1)
        self.assertNotIn(ctx.block_hash, engine.store.live)

    def test_spool_write_failure_never_crosses_submission_barrier(self):
        store = DurableStore()
        ledger = AccountingLedger()
        engine = RecoveryEngine(store, ledger)
        ctx = context()

        with self.assertRaises(DurableWriteError):
            engine.prepare_candidate(ctx, fail_spool=True)

        self.assertFalse(store.submit_ready(ctx.block_hash))
        self.assertNotIn(ctx.block_hash, store.live)
        self.assertEqual(ledger.accounting_applications, 0)

    def test_malformed_or_incomplete_spool_entry_is_refused(self):
        with self.assertRaisesRegex(ValueError, "SHARE_CONTEXT_MISSING"):
            RecoveryContext(
                block_hash="33" * 32,
                raw_hex="deadbeef",
                share={
                    "height": 1,
                    "worker": "alice",
                },
            )

        with self.assertRaisesRegex(ValueError, "RECOVERY_RECORD"):
            RecoveryContext.from_record(
                {
                    "blockHash": "33" * 32,
                    "hex": "deadbeef",
                }
            )

    def test_final_refusal_archives_without_accounting(self):
        engine, ctx = self.engine()
        self.assertEqual(engine.recover(ctx.block_hash, "refused"), "REFUSED")
        self.assertNotIn(ctx.block_hash, engine.store.live)
        self.assertEqual(
            engine.store.terminal[ctx.block_hash].phase,
            Phase.REFUSED,
        )
        self.assertNotIn(ctx.block_hash, engine.ledger.accounted)

    def test_rpc_failure_is_not_final(self):
        engine, ctx = self.engine()
        self.assertEqual(engine.recover(ctx.block_hash, "rpc-error"), "RETRY_LATER")
        self.assertIn(ctx.block_hash, engine.store.live)
        self.assertNotIn(ctx.block_hash, engine.ledger.accounted)


if __name__ == "__main__":
    unittest.main()
