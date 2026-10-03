import tempfile
import unittest
from pathlib import Path

from wam_security.audit.continuous_fabric import audit_continuous_fabric


class ContinuousFabricAuditTests(unittest.TestCase):
    def test_current_event_only_shape_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            w = root / ".github/workflows"
            w.mkdir(parents=True)
            (w / "release.yml").write_text(
                "on: [push]\njobs:\n  release:\n    steps:\n      - run: gh release create\n",
                encoding="utf-8",
            )
            ids = {f.finding_id for f in audit_continuous_fabric(root)}
            self.assertEqual(ids, {
                "WS-FABRIC-301",
                "WS-FABRIC-302",
                "WS-FABRIC-303",
                "WS-FABRIC-304",
                "WS-FABRIC-305",
            })

    def test_reference_continuous_shape_is_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            w = root / ".github/workflows"
            w.mkdir(parents=True)
            (w / "security.yml").write_text(
                """
on:
  schedule:
    - cron: '17 * * * *'
jobs:
  status:
    steps:
      - run: curl https://explorer.wamcoin.org/api/health
      - run: echo fork-agreement getsupplyinfo
      - run: python run_fuzz.py
      - run: python chaos.py
      - run: python security-status.json --block-red
      - run: echo release_blocked
""",
                encoding="utf-8",
            )
            self.assertEqual(audit_continuous_fabric(root), [])


if __name__ == "__main__":
    unittest.main()
