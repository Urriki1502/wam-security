"""Supply-chain checks for GitHub Actions and lockfiles."""

from __future__ import annotations

from pathlib import Path
import re

from wam_security.audit.findings import Finding

_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.M)
_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)


def audit_workflows(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    workflows = root / ".github" / "workflows"
    if workflows.exists():
        for wf in sorted(workflows.glob("*.y*ml")):
            text = wf.read_text(encoding="utf-8")
            for spec in _ACTION.findall(text):
                if "@" not in spec:
                    continue
                action, ref = spec.rsplit("@", 1)
                if action.startswith("./"):
                    continue
                if not _SHA.fullmatch(ref):
                    findings.append(Finding(
                        finding_id="WS-SC-001",
                        severity="MEDIUM",
                        confidence="CONFIRMED-HARDENING-GAP",
                        title="GitHub Action is not pinned to an immutable commit SHA",
                        path=str(wf.relative_to(root)),
                        evidence=spec,
                        impact="A mutable action tag increases release supply-chain trust surface.",
                        recommendation=("Pin third-party actions to an audited 40-hex commit SHA and record the "
                                        "human tag in a comment."),
                    ))

    package = root / "pool" / "package.json"
    lock = root / "pool" / "package-lock.json"
    if package.exists() and not lock.exists():
        findings.append(Finding(
            finding_id="WS-SC-002",
            severity="MEDIUM",
            confidence="CONFIRMED-HARDENING-GAP",
            title="Pool dependency graph is not locked",
            path="pool/package.json",
            evidence="package.json exists but pool/package-lock.json does not",
            impact="Fresh installs can resolve a different transitive dependency graph over time.",
            recommendation="Commit a reviewed lockfile and use npm ci in CI/release builds.",
        ))
    return findings
