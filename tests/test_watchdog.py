import unittest

from wam_security.adversarial.watchdog import (
    Health,
    RestartBudget,
    RuntimeHealth,
    evaluate_runtime,
)


class WatchdogTests(unittest.TestCase):
    def test_unknown_money_dependency_fails_closed(self):
        for field in ("redis", "daemon_rpc", "wallet", "durable_journal"):
            kwargs = {field: Health.UNKNOWN}
            d = evaluate_runtime(RuntimeHealth(**kwargs))
            self.assertFalse(d.allow_money_movement)
            self.assertTrue(d.allow_read_only)

    def test_failed_redis_pauses_mining_ingress_and_money(self):
        d = evaluate_runtime(RuntimeHealth(redis=Health.FAILED))
        self.assertFalse(d.allow_mining_ingress)
        self.assertFalse(d.allow_money_movement)
        self.assertTrue(d.allow_read_only)

    def test_all_healthy_allows_money_path(self):
        d = evaluate_runtime(RuntimeHealth())
        self.assertTrue(d.allow_money_movement)
        self.assertEqual(d.reason, "healthy")

    def test_restart_budget_breaks_crash_loop(self):
        b = RestartBudget(max_restarts=3, window_ms=1_000)
        self.assertTrue(b.allow_restart(0))
        self.assertTrue(b.allow_restart(100))
        self.assertTrue(b.allow_restart(200))
        self.assertFalse(b.allow_restart(300))
        b.assert_bounded()
        self.assertTrue(b.allow_restart(1_100))
        b.assert_bounded()


if __name__ == "__main__":
    unittest.main()
