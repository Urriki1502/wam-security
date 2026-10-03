import json
import tempfile
import unittest
from pathlib import Path

from wam_security.supplychain.identities import identity_map, load_identity_lock
from wam_security.supplychain.provenance import (
    canonical_json_bytes,
    create_provenance,
    create_spdx_sbom,
    provenance_digest,
    verify_subjects,
)


LOCK = {
    "schema": "wam-security-supply-chain-lock/v1",
    "target_wam": {
        "repository": "https://github.com/wamcoin-core-dev/wam-coin",
        "commit": "0" * 40,
    },
    "identities": [{
        "name": "dep",
        "repository": "https://github.com/example/dep.git",
        "ref": "refs/tags/v1",
        "commit": "1" * 40,
        "kind": "source-dependency",
    }],
}


class ProvenanceTests(unittest.TestCase):
    def test_lock_requires_full_commit_identities(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "lock.json"
            p.write_text(json.dumps(LOCK), encoding="utf-8")
            loaded = load_identity_lock(p)
            self.assertEqual(identity_map(loaded)["dep"], "1" * 40)

    def test_provenance_is_deterministic_and_detects_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "release.tar.gz"
            artifact.write_bytes(b"release-bytes")
            a = create_provenance(
                source_repository="https://github.com/wamcoin-core-dev/wam-coin",
                source_commit="0" * 40,
                lock=LOCK,
                artifacts=[artifact],
                artifact_base=root,
                parameters={"profile": "linux"},
            )
            b = create_provenance(
                source_repository="https://github.com/wamcoin-core-dev/wam-coin",
                source_commit="0" * 40,
                lock=LOCK,
                artifacts=[artifact],
                artifact_base=root,
                parameters={"profile": "linux"},
            )
            self.assertEqual(canonical_json_bytes(a), canonical_json_bytes(b))
            self.assertEqual(provenance_digest(a), provenance_digest(b))
            verify_subjects(a, root)

            artifact.write_bytes(b"tampered")
            with self.assertRaises(AssertionError):
                verify_subjects(a, root)

    def test_spdx_is_stable(self):
        a = create_spdx_sbom(
            document_name="WAM V5",
            namespace="https://wamcoin.org/spdx/v5/test",
            wam_repository="https://github.com/wamcoin-core-dev/wam-coin",
            wam_commit="0" * 40,
            lock=LOCK,
        )
        b = create_spdx_sbom(
            document_name="WAM V5",
            namespace="https://wamcoin.org/spdx/v5/test",
            wam_repository="https://github.com/wamcoin-core-dev/wam-coin",
            wam_commit="0" * 40,
            lock=LOCK,
        )
        self.assertEqual(canonical_json_bytes(a), canonical_json_bytes(b))
        self.assertEqual(a["spdxVersion"], "SPDX-2.3")


if __name__ == "__main__":
    unittest.main()
