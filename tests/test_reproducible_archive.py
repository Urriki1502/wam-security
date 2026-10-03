import os
import tempfile
import time
import unittest
from pathlib import Path

from wam_security.supplychain.provenance import sha256_file
from wam_security.supplychain.repro import build_reproducible_tar_gz


class ReproducibleArchiveTests(unittest.TestCase):
    def test_mtime_and_creation_order_do_not_change_archive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a"
            b = root / "b"
            a.mkdir()
            b.mkdir()

            (a / "z.txt").write_text("z\n", encoding="utf-8")
            (a / "bin").mkdir()
            tool = a / "bin/tool"
            tool.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            tool.chmod(0o755)
            (a / "a.txt").write_text("a\n", encoding="utf-8")

            (b / "a.txt").write_text("a\n", encoding="utf-8")
            (b / "bin").mkdir()
            tool2 = b / "bin/tool"
            tool2.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            tool2.chmod(0o755)
            (b / "z.txt").write_text("z\n", encoding="utf-8")

            now = int(time.time())
            for p in a.rglob("*"):
                os.utime(p, (now - 1000, now - 1000), follow_symlinks=False)
            for p in b.rglob("*"):
                os.utime(p, (now + 1000, now + 1000), follow_symlinks=False)

            out1 = root / "one.tar.gz"
            out2 = root / "two.tar.gz"
            build_reproducible_tar_gz(a, out1, root_name="payload", source_date_epoch=1_700_000_000)
            build_reproducible_tar_gz(b, out2, root_name="payload", source_date_epoch=1_700_000_000)
            self.assertEqual(sha256_file(out1), sha256_file(out2))
            self.assertEqual(out1.read_bytes(), out2.read_bytes())

    def test_payload_change_changes_archive(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            f = src / "data"
            f.write_text("one", encoding="utf-8")
            a = root / "a.tar.gz"
            b = root / "b.tar.gz"
            build_reproducible_tar_gz(src, a, root_name="x", source_date_epoch=1)
            f.write_text("two", encoding="utf-8")
            build_reproducible_tar_gz(src, b, root_name="x", source_date_epoch=1)
            self.assertNotEqual(sha256_file(a), sha256_file(b))


if __name__ == "__main__":
    unittest.main()
