import unittest

from wam_security.adversarial.resource import AdmissionController, BudgetExceeded, RuntimeLimits


class ResourceBudgetTests(unittest.TestCase):
    def test_per_ip_connection_limit(self):
        c = AdmissionController(RuntimeLimits(max_connections=4, max_connections_per_ip=2))
        c.connect("192.0.2.1")
        c.connect("192.0.2.1")
        with self.assertRaises(BudgetExceeded):
            c.connect("192.0.2.1")
        c.assert_bounded()

    def test_message_rate_window(self):
        c = AdmissionController(RuntimeLimits(max_messages_per_10s=3))
        for i in range(3):
            c.record_message("192.0.2.1", 10, i * 100)
        with self.assertRaises(BudgetExceeded):
            c.record_message("192.0.2.1", 10, 500)
        c.record_message("192.0.2.1", 10, 11_000)
        c.assert_bounded()

    def test_inflight_limit(self):
        c = AdmissionController(RuntimeLimits(max_inflight_per_ip=2))
        c.begin_request("192.0.2.2")
        c.begin_request("192.0.2.2")
        with self.assertRaises(BudgetExceeded):
            c.begin_request("192.0.2.2")
        c.end_request("192.0.2.2")
        c.assert_bounded()


if __name__ == "__main__":
    unittest.main()
