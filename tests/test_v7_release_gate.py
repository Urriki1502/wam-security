import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from wam_security.fabric.core import Check, build_status


class ReleaseGateTests(unittest.TestCase):
    def _run(self, status):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "status.json"
            path.write_text(json.dumps(status), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    "scripts/verify_v7_release_gate.py",
                    str(path),
                    "--block-red",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

    def test_red_blocks(self):
        status = build_status(
            generated_at="2026-10-03T00:00:00Z",
            fabric_version="0.7.0",
            target_repository="r",
            target_head="1" * 40,
            audited_head="1" * 40,
            checks=[Check("x", "x", "FAIL", True, "bad", {})],
        )
        self.assertEqual(self._run(status).returncode, 2)

    def test_yellow_does_not_block(self):
        status = build_status(
            generated_at="2026-10-03T00:00:00Z",
            fabric_version="0.7.0",
            target_repository="r",
            target_head="1" * 40,
            audited_head="1" * 40,
            checks=[Check("x", "x", "UNKNOWN", False, "unknown", {})],
        )
        self.assertEqual(self._run(status).returncode, 0)


if __name__ == "__main__":
    unittest.main()
