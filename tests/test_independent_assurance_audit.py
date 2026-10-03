import tempfile
import unittest
from pathlib import Path

from wam_security.audit.independent_assurance import audit_independent_assurance


class IndependentAssuranceAuditTests(unittest.TestCase):
    def test_current_shape_without_controls_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/release.yml").write_text("jobs: {}\n", encoding="utf-8")
            (root / "CONTRIBUTING.md").write_text("review patches before merge\n", encoding="utf-8")
            ids = {f.finding_id for f in audit_independent_assurance(root)}
            self.assertEqual(ids, {
                "WS-ASSURE-201",
                "WS-ASSURE-202",
                "WS-ASSURE-203",
                "WS-ASSURE-204",
                "WS-ASSURE-205",
            })

    def test_hardened_shape_is_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".github/workflows").mkdir(parents=True)
            (root / "formal").mkdir()
            (root / "redteam").mkdir()
            (root / ".github/CODEOWNERS").write_text(
                "\n".join([
                    "scripts/patch_upstream.py @core @security",
                    "src/wam/ @core @security",
                    "pool/lib/shareProcessor.js @core @security",
                    ".github/workflows/ @core @security",
                    "scripts/fetch-upstream.sh @core @security",
                    "scripts/package_release.sh @core @security",
                ]),
                encoding="utf-8",
            )
            (root / "CONTRIBUTING.md").write_text(
                "Security-critical changes require two independent reviewers.\n",
                encoding="utf-8",
            )
            (root / ".github/workflows/release.yml").write_text(
                "name: independent builder compare-builders\n",
                encoding="utf-8",
            )
            (root / "formal/X.tla").write_text("---- MODULE X ----\n====\n", encoding="utf-8")
            (root / "redteam/corpus.json").write_text("[]\n", encoding="utf-8")
            self.assertEqual(audit_independent_assurance(root), [])


if __name__ == "__main__":
    unittest.main()
