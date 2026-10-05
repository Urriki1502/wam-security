#!/usr/bin/env python3
"""Exercise WAM's published release verifier as a first-time user with an empty keyring."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from wam_security.release_trust import assert_anchor_consistency

WAM_COMMIT = "bb6d5214f2f5de3b7464587cc1b2949d221dcd18"


def git_head(root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def run(cmd, *, env=None, cwd=None, check=True):
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def verifier_case(upstream: Path, release_dir: Path, artifact: str, mutate=None):
    case = Path(tempfile.mkdtemp(prefix="wam-release-trust-"))
    home = case / "home"
    home.mkdir(mode=0o700)
    for name in ("SHA256SUMS", "SHA256SUMS.asc", artifact):
        shutil.copy2(release_dir / name, case / name)
    shutil.copy2(upstream / "scripts/verify_release.sh", case / "verify_release.sh")
    shutil.copy2(upstream / "SIGNING-KEY.asc", case / "SIGNING-KEY.asc")
    if mutate:
        mutate(case)
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["GNUPGHOME"] = str(home / ".gnupg-empty")
    Path(env["GNUPGHOME"]).mkdir(mode=0o700)
    proc = run(
        ["bash", "verify_release.sh", "."],
        cwd=case,
        env=env,
        check=False,
    )
    return case, proc


def flip_first_byte(path: Path):
    raw = bytearray(path.read_bytes())
    if not raw:
        raise ValueError("EMPTY_RELEASE_ARTIFACT")
    raw[0] ^= 1
    path.write_bytes(raw)


def wrong_signer(case: Path):
    gnupg = case / "wrong-signer"
    gnupg.mkdir(mode=0o700)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupg)
    run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            "WAM regression impostor <nobody.invalid@example.invalid>",
            "ed25519",
            "sign",
            "0",
        ],
        env=env,
    )
    exported = run(
        ["gpg", "--batch", "--armor", "--export"],
        env=env,
    ).stdout
    (case / "SIGNING-KEY.asc").write_text(exported, encoding="utf-8")
    run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--armor",
            "--detach-sign",
            "--output",
            str(case / "SHA256SUMS.asc"),
            str(case / "SHA256SUMS"),
        ],
        env=env,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("release_dir", type=Path)
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/release-trust.json"),
    )
    args = ap.parse_args()

    upstream = args.wam_root.resolve()
    release_dir = args.release_dir.resolve()
    if git_head(upstream) != args.expected_commit:
        raise SystemExit("WAM source is not the locked reviewed commit")
    for path in (
        release_dir / "SHA256SUMS",
        release_dir / "SHA256SUMS.asc",
        release_dir / args.artifact,
    ):
        if not path.is_file():
            raise SystemExit(f"missing release fixture: {path}")

    sums = (release_dir / "SHA256SUMS").read_text(encoding="utf-8")
    if args.artifact not in sums:
        raise SystemExit("selected artifact is not named in SHA256SUMS")

    fingerprint = assert_anchor_consistency(
        (upstream / "SECURITY.md").read_text(encoding="utf-8"),
        (upstream / "scripts/verify_release.sh").read_text(encoding="utf-8"),
        upstream / "SIGNING-KEY.asc",
    )

    cases = {}
    paths = []
    try:
        case, good = verifier_case(upstream, release_dir, args.artifact)
        paths.append(case)
        cases["fresh_empty_keyring_published_flow"] = good.returncode == 0

        def tamper_artifact(root):
            flip_first_byte(root / args.artifact)

        case, tampered = verifier_case(
            upstream,
            release_dir,
            args.artifact,
            tamper_artifact,
        )
        paths.append(case)
        cases["tampered_artifact_rejected"] = tampered.returncode != 0

        def tamper_sums(root):
            text = (root / "SHA256SUMS").read_text(encoding="utf-8")
            first, rest = text[0], text[1:]
            (root / "SHA256SUMS").write_text(
                ("0" if first != "0" else "1") + rest,
                encoding="utf-8",
            )

        case, bad_signature = verifier_case(
            upstream,
            release_dir,
            args.artifact,
            tamper_sums,
        )
        paths.append(case)
        cases["modified_signed_manifest_rejected"] = bad_signature.returncode != 0

        case, wrong_identity = verifier_case(
            upstream,
            release_dir,
            args.artifact,
            wrong_signer,
        )
        paths.append(case)
        cases["valid_signature_wrong_key_identity_rejected"] = (
            wrong_identity.returncode != 0
        )

        if not all(cases.values()):
            raise AssertionError(
                "release trust regression failed: "
                + json.dumps(cases, sort_keys=True)
            )

        evidence = {
            "schema": "wam-security-release-trust/v1",
            "target": {
                "repository": "wamcoin-core-dev/wam-coin",
                "commit": args.expected_commit,
            },
            "fixture": {
                "artifact": args.artifact,
                "real_release_metadata": True,
            },
            "expected_fingerprint": fingerprint,
            "checks": cases,
            "trust_root_observation": (
                "SECURITY.md is described as the sole fingerprint publication point, "
                "while the verifier must also embed the same literal fingerprint to "
                "enforce identity. This is an implementation copy, not an independent "
                "administrative trust anchor."
            ),
            "result": "PASS",
        }
        out = args.out.resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print("fresh-user release trust regression: PASS")
        print(f"evidence: {out}")
        return 0
    finally:
        for path in paths:
            shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
