"""Deep release and supply-chain audit for WAM Security V5."""

from __future__ import annotations

from pathlib import Path
import re

from wam_security.audit.findings import Finding

_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.M)
_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _finding(
    fid: str,
    severity: str,
    title: str,
    path: str,
    evidence: str,
    impact: str,
    recommendation: str,
) -> Finding:
    return Finding(
        finding_id=fid,
        severity=severity,
        confidence="CONFIRMED-SUPPLY-CHAIN-GAP",
        title=title,
        path=path,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
    )


def _external_action_specs(text: str) -> list[str]:
    specs: list[str] = []
    for spec in _ACTION.findall(text):
        if "@" not in spec or spec.startswith("./"):
            continue
        _, ref = spec.rsplit("@", 1)
        if not _SHA.fullmatch(ref):
            specs.append(spec)
    return specs


def audit_supply_chain(root: str | Path) -> list[Finding]:
    root = Path(root)
    release = _read(root, ".github/workflows/release.yml")
    platform = _read(root, ".github/workflows/platform-build.yml")
    fetch = _read(root, "scripts/fetch-upstream.sh")
    package = _read(root, "scripts/package_release.sh")
    signer = _read(root, "scripts/sign_release.sh")

    findings: list[Finding] = []

    pre_jobs = release.split("\njobs:", 1)[0] if release else ""
    workflow_write = any(
        re.fullmatch(r"\s*contents:\s*write(?:\s+#.*)?", line)
        for line in pre_jobs.splitlines()
    )
    if workflow_write:
        findings.append(_finding(
            "WS-SC-101",
            "HIGH",
            "Release build inherits repository write permission before publish",
            ".github/workflows/release.yml",
            "workflow-level permissions grant contents: write to the build job",
            "A compromised build step or mutable dependency runs inside a job whose token can modify release content.",
            "Split build and publish into separate jobs. Keep build at contents: read and grant contents: write only to a protected publish job.",
        ))

    mutable = sorted(set(_external_action_specs(release) + _external_action_specs(platform)))
    if mutable:
        findings.append(_finding(
            "WS-SC-102",
            "HIGH",
            "Release and platform workflows execute mutable GitHub Action refs",
            ".github/workflows/",
            ", ".join(mutable),
            "A moved action tag can change code executed in release jobs without any WAM source commit changing.",
            "Pin every external action to an audited 40-hex commit SHA and retain the human tag only as a comment.",
        ))

    tag_only = (
        'UPSTREAM_TAG="' in fetch
        and 'RANDOMX_TAG="' in fetch
        and "git clone --quiet --depth 1 --branch" in fetch
    )
    commit_gate = (
        "EXPECTED_UPSTREAM_COMMIT" in fetch
        or "UPSTREAM_COMMIT_EXPECTED" in fetch
        or "RANDOMX_COMMIT_EXPECTED" in fetch
    )
    if tag_only and not commit_gate:
        findings.append(_finding(
            "WS-SC-103",
            "HIGH",
            "Bitcoin Core and RandomX are selected by mutable tag names without an independent commit lock",
            "scripts/fetch-upstream.sh",
            "upstream refs are cloned by tag; resolved commits are logged but not compared to reviewed expected SHAs",
            "A moved or substituted upstream tag can silently change consensus or PoW source code in a later build of the same WAM commit.",
            "Maintain an independently reviewed dependency lock containing exact commits and fail the build if remote refs resolve differently.",
        ))

    nondeterministic_tar = (
        "tar -czf" in package
        and "SOURCE_DATE_EPOCH" not in package
        and "--sort=name" not in package
        and "--mtime=" not in package
    )
    if nondeterministic_tar:
        findings.append(_finding(
            "WS-SC-104",
            "MEDIUM",
            "Release archives do not normalize metadata for reproducible byte output",
            "scripts/package_release.sh",
            "tar -czf is used without SOURCE_DATE_EPOCH, stable ordering, normalized uid/gid, or deterministic gzip metadata",
            "Two builds with identical payload bytes can produce different release hashes, preventing independent byte-for-byte reproduction.",
            "Create archives with sorted paths, fixed mtime, normalized ownership/modes and gzip mtime/name normalization.",
        ))

    manual_merge = (
        "Windows archives" in signer
        and "added to SHA256SUMS by hand" in signer
    )
    if manual_merge:
        findings.append(_finding(
            "WS-SC-105",
            "MEDIUM",
            "Cross-platform release artifacts are merged into the signed manifest manually",
            "scripts/sign_release.sh",
            "the signing runbook states Windows archives must be added to SHA256SUMS by hand",
            "Manual manifest assembly can omit, mix or misattribute platform artifacts and provides no machine binding to their source commit.",
            "Collect platform artifacts automatically into one release manifest with source SHA, workflow run identity and artifact digest before offline signing.",
        ))

    if "continue-on-error: true" in release and "graphical wallet" in release.lower():
        findings.append(_finding(
            "WS-SC-106",
            "MEDIUM",
            "The same release tag may publish a different artifact set depending on optional wallet build success",
            ".github/workflows/release.yml",
            "graphical wallet build is continue-on-error and packaging includes it only when present",
            "A release name does not uniquely determine its artifact composition; transient toolchain/package failures can silently omit the wallet.",
            "Make release composition explicit in a signed manifest and require an intentional release profile rather than success-dependent inclusion.",
        ))

    if "gh release create" in release and not re.search(r"(?m)^\s*environment:\s*\S+", release):
        findings.append(_finding(
            "WS-SC-107",
            "MEDIUM",
            "Release publication is not bound to a protected GitHub environment in workflow source",
            ".github/workflows/release.yml",
            "publish step creates GitHub releases but no job declares environment:",
            "Repository write permission can publish without the workflow-level approval boundary normally used for release credentials and deployment policy.",
            "Move publication to a dedicated job using a protected release environment with required reviewers where repository settings support it.",
        ))

    lower_release = release.lower()
    if release and not any(word in lower_release for word in ("sbom", "provenance", "attestation", "attest-build-provenance")):
        findings.append(_finding(
            "WS-SC-108",
            "MEDIUM",
            "Release emits checksums but no machine-readable SBOM or build provenance",
            ".github/workflows/release.yml",
            "release assets contain packages and SHA256SUMS but no SBOM/provenance generation step",
            "A verifier can authenticate bytes but cannot automatically determine which source commit, dependency identities and build invocation produced them.",
            "Generate an SPDX SBOM plus SLSA/in-toto style provenance statement and bind their digests into the signed release manifest.",
        ))

    if (
        "apt-get install" in release
        and not re.search(r"apt-get install[^\n]*=[0-9]", release)
    ):
        findings.append(_finding(
            "WS-SC-109",
            "MEDIUM",
            "Release toolchain packages are resolved from moving apt repositories",
            ".github/workflows/release.yml",
            "apt-get install is used without version pins or an immutable package snapshot",
            "The same WAM commit built on different days can receive different compilers/libraries and produce different binaries.",
            "Record exact toolchain/package versions and use an immutable container or snapshot repository for release builds.",
        ))

    return findings
