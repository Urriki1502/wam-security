"""Deterministic JSON and Markdown reporting."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from wam_security.audit.findings import Finding


def write_reports(findings: list[Finding], out_dir: str | Path, target: str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ordered = sorted(findings, key=lambda f: (f.finding_id, f.path, f.evidence))
    payload = {
        "schema": "wam-security-report/v1",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in ordered],
    }
    json_path = out / "security-report.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = ["# WAM Security Report", "", f"Target: {target}", "", f"Findings: **{len(ordered)}**", ""]
    if not ordered:
        lines.append("No modeled findings were detected by this baseline scanner.")
    for f in ordered:
        lines += [
            f"## {f.finding_id} — {f.title}", "",
            f"- Severity: **{f.severity}**",
            f"- Confidence: **{f.confidence}**",
            f"- Path: {f.path}",
            f"- Evidence: {f.evidence}",
            f"- Impact: {f.impact}",
            f"- Recommendation: {f.recommendation}", "",
        ]
    md_path = out / "security-report.md"
    md_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return json_path, md_path
