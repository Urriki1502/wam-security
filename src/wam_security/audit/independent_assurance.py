"""V6 audit for formal and independent assurance controls."""

from __future__ import annotations

from pathlib import Path
import json
import re

from wam_security.audit.findings import Finding


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _finding(fid: str, severity: str, title: str, path: str, evidence: str, recommendation: str) -> Finding:
    return Finding(
        finding_id=fid,
        severity=severity,
        confidence="CONFIRMED-INDEPENDENT-ASSURANCE-GAP",
        title=title,
        path=path,
        evidence=evidence,
        impact="A security-critical change can cross review or release boundaries without an independent machine-enforced assurance layer.",
        recommendation=recommendation,
    )


def audit_independent_assurance(root: str | Path) -> list[Finding]:
    root = Path(root)
    codeowners = _read(root, ".github/CODEOWNERS")
    contributing = _read(root, "CONTRIBUTING.md")
    workflows = "\n".join(
        p.read_text(encoding="utf-8")
        for p in (root / ".github/workflows").glob("*.yml")
    ) if (root / ".github/workflows").exists() else ""
    formal_files = list(root.glob("formal/*.tla"))
    corpus_files = list(root.glob("redteam/*.json"))

    findings: list[Finding] = []

    critical_tokens = [
        "scripts/patch_upstream.py",
        "src/wam/",
        "pool/lib/shareProcessor.js",
        ".github/workflows/",
        "scripts/fetch-upstream.sh",
        "scripts/package_release.sh",
    ]
    if not codeowners or sum(token in codeowners for token in critical_tokens) < 4:
        findings.append(_finding(
            "WS-ASSURE-201",
            "HIGH",
            "Security-critical paths have no repository CODEOWNERS coverage",
            ".github/CODEOWNERS",
            "CODEOWNERS is absent or does not cover consensus, money and release-critical paths",
            "Add explicit security-critical ownership groups and protect the default branch so owner review is required.",
        ))

    two_review = re.search(
        r"(two|2)\s+(independent\s+)?(reviewers|approvals|reviews)",
        contributing,
        re.I,
    )
    if not two_review:
        findings.append(_finding(
            "WS-ASSURE-202",
            "MEDIUM",
            "Repository policy does not require two independent reviews for security-critical changes",
            "CONTRIBUTING.md",
            "no two-review/two-approval rule detected",
            "Document a two-person review rule for consensus, wallet/payout and release-trust paths and enforce it with repository rulesets.",
        ))

    independent_builder_markers = (
        "independent builder",
        "reproducible-build",
        "compare-builders",
        "builder-a",
        "builder-b",
    )
    if not any(marker in workflows.lower() for marker in independent_builder_markers):
        findings.append(_finding(
            "WS-ASSURE-203",
            "MEDIUM",
            "Release pipeline has no independent-builder comparison gate",
            ".github/workflows/",
            "no workflow marker for two independent build witnesses/comparison",
            "Generate the same signed release evidence on two isolated builders and require byte/hash agreement before publication.",
        ))

    if not formal_files:
        findings.append(_finding(
            "WS-ASSURE-204",
            "MEDIUM",
            "No executable formal state-machine specification is present",
            "formal/",
            "no .tla specification files found",
            "Model payout/reconciliation and release publication as explicit state machines and check their invariants in CI.",
        ))

    if not corpus_files:
        findings.append(_finding(
            "WS-ASSURE-205",
            "MEDIUM",
            "No machine-readable red-team regression corpus is present",
            "redteam/",
            "no JSON security regression corpus found",
            "Keep accepted/public failure classes as non-weaponized regression cases and require every release to replay them.",
        ))

    return findings
