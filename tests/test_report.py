import json
import tempfile
import unittest

from wam_security.audit.findings import Finding
from wam_security.report import write_reports


class ReportTests(unittest.TestCase):
    def test_json_and_markdown_are_emitted(self):
        f = Finding("X-1", "HIGH", "CONFIRMED", "title", "x", "evidence", "impact", "fix")
        with tempfile.TemporaryDirectory() as td:
            jp, mp = write_reports([f], td, "abc123")
            self.assertTrue(jp.exists())
            self.assertTrue(mp.exists())
            data = json.loads(jp.read_text())
            self.assertEqual(data["target"], "abc123")
            self.assertEqual(data["findings"][0]["finding_id"], "X-1")


if __name__ == "__main__":
    unittest.main()
