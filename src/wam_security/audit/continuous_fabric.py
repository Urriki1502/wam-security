"""V7 audit for continuous-security fabric controls in WAM Core."""

from __future__ import annotations

from pathlib import Path
import re

from wam_security.audit.findings import Finding


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _workflow_text(root: Path) -> str:
    w = root / ".github/workflows"
    if not w.exists():
        return ""
    return "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted(w.glob("*.yml"))
    )


def _finding(fid: str, severity: str, title: str, evidence: str, rec: str) -> Finding:
    return Finding(
        finding_id=fid,
        severity=severity,
        confidence="CONFIRMED-CONTINUOUS-ASSURANCE-GAP",
        title=title,
        path=".github/workflows/",
        evidence=evidence,
        impact="Security assurances can silently become stale between releases or after source/infrastructure drift.",
        recommendation=rec,
    )


def audit_continuous_fabric(root: str | Path) -> list[Finding]:
    root = Path(root)
    workflows = _workflow_text(root)
    lower = workflows.lower()
    findings: list[Finding] = []

    if "schedule:" not in workflows:
        findings.append(_finding(
            "WS-FABRIC-301",
            "MEDIUM",
            "Security assurance runs only on repository events, not continuously",
            "no scheduled security workflow detected",
            "Run a read-only security fabric on an hourly/daily schedule and preserve each machine-readable status snapshot.",
        ))

    if "security-status.json" not in workflows and "wam-security-status" not in lower:
        findings.append(_finding(
            "WS-FABRIC-302",
            "MEDIUM",
            "No machine-readable aggregate security status is produced",
            "workflows do not emit a security-status document",
            "Aggregate source, audit, live consensus, money and release checks into a versioned JSON status envelope.",
        ))

    if not any(token in lower for token in ("explorer.wamcoin.org", "/api/health", "fork-agreement", "getsupplyinfo")):
        findings.append(_finding(
            "WS-FABRIC-303",
            "MEDIUM",
            "No continuous live consensus/supply/fork health aggregation is present",
            "no live read-only WAM health probe markers detected",
            "Continuously measure official read-only endpoints and mark unavailable data UNKNOWN rather than healthy.",
        ))

    release_block = (
        "release_blocked" in workflows
        or "release-blocked" in lower
        or "block-red" in lower
        or "security gate" in lower
    )
    if not release_block:
        findings.append(_finding(
            "WS-FABRIC-304",
            "HIGH",
            "Release automation is not gated by aggregate critical security status",
            "no workflow consumes a RED/critical security status before publication",
            "Make critical invariant failure a hard release-blocking condition.",
        ))

    fuzzish = any(token in lower for token in ("fuzz", "chaos", "fault matrix", "fault-matrix"))
    scheduled_fuzz = fuzzish and "schedule:" in workflows
    if not scheduled_fuzz:
        findings.append(_finding(
            "WS-FABRIC-305",
            "MEDIUM",
            "Fuzzing and chaos exercises are not scheduled as recurring assurance",
            "no recurring fuzz/chaos workflow detected",
            "Rotate deterministic fuzz seeds daily and run a periodic chaos exercise that proves RED status blocks release.",
        ))

    return findings
