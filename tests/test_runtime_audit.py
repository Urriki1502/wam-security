import tempfile
import unittest
from pathlib import Path

from wam_security.audit.runtime import audit_runtime_controls


class RuntimeAuditTests(unittest.TestCase):
    def test_detects_missing_stratum_runtime_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pool/lib"
            p.mkdir(parents=True)
            (p / "stratumServer.js").write_text("function onData() {}", encoding="utf-8")
            ids = {f.finding_id for f in audit_runtime_controls(td)}
            self.assertIn("WS-RUNTIME-001", ids)

    def test_accepts_expected_stratum_guard_shape(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pool/lib"
            p.mkdir(parents=True)
            (p / "stratumServer.js").write_text(
                """
                if (this._buffer.length > 16384) disconnect();
                const n = this.config.maxMessagesPer10s;
                const a = this.config.maxConnections;
                const b = this.config.maxConnectionsPerIp;
                this._authTimer = setTimeout(() => disconnect(), 30000);
                """,
                encoding="utf-8",
            )
            ids = {f.finding_id for f in audit_runtime_controls(td)}
            self.assertNotIn("WS-RUNTIME-001", ids)


if __name__ == "__main__":
    unittest.main()
