import tempfile
import unittest
from pathlib import Path

from wam_security.audit.supply_chain import audit_supply_chain


RELEASE = r"""
name: release
permissions:
  contents: write        # release publication token
jobs:
  build:
    steps:
      - uses: actions/checkout@v5
      - name: The graphical wallet
        continue-on-error: true
        run: sudo apt-get install -y qtbase5-dev
      - run: gh release create "$VERSION"
"""

PLATFORM = r"""
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@v7
      - uses: actions/download-artifact@v7
"""

FETCH = r'''
UPSTREAM_TAG="v28.1"
RANDOMX_TAG="v1.2.1"
git clone --quiet --depth 1 --branch "$UPSTREAM_TAG" "$UPSTREAM_REPO" "$CORE_DIR"
git clone --quiet --depth 1 --branch "$RANDOMX_TAG" "$RANDOMX_REPO" "$RANDOMX_DIR"
'''

PACKAGE = r'''
tar -czf "$OUT/$TARBALL_NODE" -C "$WORK/stage" "wam-coin-$VERSION"
'''

SIGN = r'''
say "The Windows archives are NOT -- they come from the platform-build workflow and have to be added to SHA256SUMS by hand"
'''


class SupplyChainAuditTests(unittest.TestCase):
    def _tree(self, *, release=RELEASE, platform=PLATFORM, fetch=FETCH, package=PACKAGE, signer=SIGN):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / ".github/workflows").mkdir(parents=True)
        (root / "scripts").mkdir()
        (root / ".github/workflows/release.yml").write_text(release, encoding="utf-8")
        (root / ".github/workflows/platform-build.yml").write_text(platform, encoding="utf-8")
        (root / "scripts/fetch-upstream.sh").write_text(fetch, encoding="utf-8")
        (root / "scripts/package_release.sh").write_text(package, encoding="utf-8")
        (root / "scripts/sign_release.sh").write_text(signer, encoding="utf-8")
        return td, root

    def test_current_release_shape_emits_all_v5_findings(self):
        td, root = self._tree()
        self.addCleanup(td.cleanup)
        ids = {f.finding_id for f in audit_supply_chain(root)}
        self.assertEqual(ids, {
            "WS-SC-101", "WS-SC-102", "WS-SC-103", "WS-SC-104", "WS-SC-105",
            "WS-SC-106", "WS-SC-107", "WS-SC-108", "WS-SC-109",
        })

    def test_hardened_shape_clears_v5_findings(self):
        release = r"""
name: release
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
      - run: echo "build deterministic node"
  publish:
    environment: release
    permissions:
      contents: write
    steps:
      - run: echo "generate SBOM provenance attestation"
      - run: gh release create "$VERSION"
"""
        platform = r"""
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
"""
        fetch = r'''
UPSTREAM_TAG="v28.1"
RANDOMX_TAG="v1.2.1"
EXPECTED_UPSTREAM_COMMIT=32efe850438ef22e2de39e562af557872a402c31
RANDOMX_COMMIT_EXPECTED=102f8acf90a7649ada410de5499a7ec62e49e1da
git clone --quiet --depth 1 --branch "$UPSTREAM_TAG" "$UPSTREAM_REPO" "$CORE_DIR"
'''
        package = r'''
SOURCE_DATE_EPOCH=1
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 -cf out.tar stage
gzip -n out.tar
'''
        signer = 'echo "manifest assembled automatically from CI provenance"'
        td, root = self._tree(release=release, platform=platform, fetch=fetch, package=package, signer=signer)
        self.addCleanup(td.cleanup)
        self.assertEqual(audit_supply_chain(root), [])


if __name__ == "__main__":
    unittest.main()
