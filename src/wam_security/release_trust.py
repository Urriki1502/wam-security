"""Release trust primitives for WAM verification regressions."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_FPR_RE = re.compile(r"(?:[0-9A-F]{4}[ ]+){9}[0-9A-F]{4}")
_EXPECT_RE = re.compile(r'^EXPECT="([0-9A-F]{40})"$', re.MULTILINE)


def normalize_fingerprint(value: str) -> str:
    normalized = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[0-9A-F]{40}", normalized):
        raise ValueError("INVALID_FINGERPRINT")
    return normalized


def security_fingerprint(text: str) -> str:
    marker = "## The signing key"
    start = text.find(marker)
    if start < 0:
        raise ValueError("SIGNING_KEY_SECTION_MISSING")
    match = _FPR_RE.search(text, start)
    if not match:
        raise ValueError("SIGNING_FINGERPRINT_MISSING")
    return normalize_fingerprint(match.group(0))


def verifier_fingerprint(text: str) -> str:
    match = _EXPECT_RE.search(text)
    if not match:
        raise ValueError("VERIFIER_FINGERPRINT_MISSING")
    return normalize_fingerprint(match.group(1))


def public_key_fingerprints(path: Path) -> tuple[str, ...]:
    proc = subprocess.run(
        [
            "gpg",
            "--batch",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            str(path),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ValueError("SIGNING_KEY_PARSE_FAILED")
    result = tuple(
        line.split(":")[9].upper()
        for line in proc.stdout.splitlines()
        if line.startswith("fpr:") and len(line.split(":")) > 9
    )
    if not result:
        raise ValueError("SIGNING_KEY_FINGERPRINT_MISSING")
    return result


def assert_anchor_consistency(
    security_text: str,
    verifier_text: str,
    key_path: Path,
) -> str:
    security = security_fingerprint(security_text)
    verifier = verifier_fingerprint(verifier_text)
    key_fprs = public_key_fingerprints(key_path)
    if security != verifier or security not in key_fprs:
        raise ValueError("RELEASE_TRUST_ANCHOR_MISMATCH")
    return security
