#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from wam_security.supplychain.identities import load_identity_lock
from wam_security.supplychain.provenance import (
    canonical_json_bytes,
    create_provenance,
    create_spdx_sbom,
    provenance_digest,
    sha256_file,
    verify_subjects,
)
from wam_security.supplychain.repro import build_reproducible_tar_gz

CONTROL_FILES = [
    ".github/workflows/release.yml",
    ".github/workflows/platform-build.yml",
    "scripts/fetch-upstream.sh",
    "scripts/package_release.sh",
    "scripts/sign_release.sh",
    "scripts/verify_release.sh",
    "pool/package.json",
]


def git(checkout: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(checkout), *args], text=True).strip()


def copy_surface(checkout: Path, dst: Path, *, reverse: bool, mtime: int) -> None:
    paths = list(reversed(CONTROL_FILES)) if reverse else list(CONTROL_FILES)
    for rel in paths:
        src = checkout / rel
        if not src.is_file():
            raise FileNotFoundError(rel)
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, out)
        mode = src.stat().st_mode & 0o777
        out.chmod(mode)
        os.utime(out, (mtime, mtime))
    for directory in sorted((p for p in dst.rglob("*") if p.is_dir()), reverse=True):
        os.utime(directory, (mtime, mtime))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("checkout", type=Path)
    p.add_argument("--lock", type=Path, default=Path("supply-chain-lock.json"))
    p.add_argument("--out", type=Path, default=Path("v5-artifacts"))
    args = p.parse_args()

    checkout = args.checkout.resolve()
    lock = load_identity_lock(args.lock)
    target = lock["target_wam"]
    head = git(checkout, "rev-parse", "HEAD").lower()
    if head != target["commit"].lower():
        raise SystemExit(f"target mismatch: checkout={head} lock={target['commit']}")

    epoch = int(git(checkout, "show", "-s", "--format=%ct", "HEAD"))
    args.out.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        a = temp / "surface-a"
        b = temp / "surface-b"
        a.mkdir()
        b.mkdir()
        copy_surface(checkout, a, reverse=False, mtime=epoch - 100000)
        copy_surface(checkout, b, reverse=True, mtime=epoch + 100000)

        one = temp / "one.tar.gz"
        two = temp / "two.tar.gz"
        build_reproducible_tar_gz(a, one, root_name="wam-release-surface", source_date_epoch=epoch)
        build_reproducible_tar_gz(b, two, root_name="wam-release-surface", source_date_epoch=epoch)

        if one.read_bytes() != two.read_bytes():
            raise AssertionError("reference reproducible archive changed under mtime/order perturbation")

        bundle = args.out / "wam-release-surface.tar.gz"
        shutil.copyfile(one, bundle)

    provenance = create_provenance(
        source_repository=target["repository"],
        source_commit=head,
        lock=lock,
        artifacts=[bundle],
        artifact_base=args.out.resolve(),
        parameters={
            "surface": "release-control",
            "sourceDateEpoch": epoch,
            "format": "tar.gz",
        },
    )
    verify_subjects(provenance, args.out)

    sbom = create_spdx_sbom(
        document_name="WAM Coin V5 release-control SBOM",
        namespace=f"https://wamcoin.org/spdx/v5/{head}",
        wam_repository=target["repository"],
        wam_commit=head,
        lock=lock,
    )

    prov_path = args.out / "provenance.json"
    sbom_path = args.out / "sbom.spdx.json"
    summary_path = args.out / "summary.json"
    prov_path.write_bytes(canonical_json_bytes(provenance) + b"\n")
    sbom_path.write_bytes(canonical_json_bytes(sbom) + b"\n")

    summary = {
        "schema": "wam-security-v5-evidence/v1",
        "wam_commit": head,
        "source_date_epoch": epoch,
        "release_surface_sha256": sha256_file(bundle),
        "provenance_sha256": provenance_digest(provenance),
        "sbom_sha256": sha256_file(sbom_path),
        "control_files": CONTROL_FILES,
        "reproducible_reference": True,
    }
    summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    print("V5 release-surface provenance/SBOM/reproducibility: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
