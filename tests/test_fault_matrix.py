import unittest

from wam_security.adversarial.faults import (
    CrashPoint,
    DurablePayout,
    ExactlyOncePayoutRuntime,
    NetworkTruth,
    RpcOutcome,
    SimulatedCrash,
    exercise_crash_matrix,
)


class FaultMatrixTests(unittest.TestCase):
    def test_full_crash_matrix_settles_safely(self):
        self.assertEqual(
            exercise_crash_matrix(),
            len(RpcOutcome) * (len(CrashPoint) + 1),
        )

    def test_timeout_after_accept_recovers_same_identity(self):
        durable = DurablePayout({"wam-test": 123})
        network = NetworkTruth()
        runtime = ExactlyOncePayoutRuntime(durable, network)

        with self.assertRaises(SimulatedCrash):
            runtime.execute(RpcOutcome.TIMEOUT_AFTER_ACCEPT, CrashPoint.AFTER_NETWORK_ACCEPT)

        original = durable.txid
        ExactlyOncePayoutRuntime(durable, network).recover_and_complete()

        self.assertEqual(durable.txid, original)
        self.assertEqual(len(network.accepted_txids), 1)
        self.assertEqual(durable.committed_count, 1)


if __name__ == "__main__":
    unittest.main()
