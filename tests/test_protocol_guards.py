import json
import unittest

from wam_security.adversarial.protocol import (
    ProtocolLimits,
    validate_header_batch,
    validate_json_rpc_line,
)


class ProtocolGuardTests(unittest.TestCase):
    def setUp(self):
        self.limits = ProtocolLimits()

    def test_rejects_oversized_before_parse(self):
        payload = b"{" + b"a" * self.limits.max_line_bytes + b"}"
        d = validate_json_rpc_line(payload, self.limits)
        self.assertFalse(d.accepted)
        self.assertEqual(d.reason, "oversized-line")
        self.assertEqual(d.work_units, 1)

    def test_malformed_json_is_rejected_not_raised(self):
        d = validate_json_rpc_line(b'{"method":', self.limits)
        self.assertFalse(d.accepted)
        self.assertEqual(d.reason, "malformed-json")

    def test_valid_stratum_envelope_is_accepted(self):
        payload = json.dumps(
            {"id": 1, "method": "mining.subscribe", "params": []},
            separators=(",", ":"),
        ).encode()
        self.assertTrue(validate_json_rpc_line(payload, self.limits).accepted)

    def test_header_batch_is_bounded(self):
        self.assertFalse(
            validate_header_batch(self.limits.max_header_count + 1, 1, self.limits).accepted
        )
        self.assertFalse(
            validate_header_batch(1, self.limits.max_header_batch_bytes + 1, self.limits).accepted
        )


if __name__ == "__main__":
    unittest.main()
