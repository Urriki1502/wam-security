"""Targeted source-level security checks for WAM-owned code paths."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable

from wam_security.audit.findings import Finding


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _strip_js_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _method_body(text: str, start_marker: str, end_marker: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        return ""
    end = text.find(end_marker, start + len(start_marker))
    return text[start:] if end < 0 else text[start:end]


def _money_rpc_failover_is_guarded(daemon: str) -> bool:
    code = _strip_js_comments(daemon)
    money_set = re.search(
        r"DaemonInterface\.MONEY_RPCS\s*=\s*new Set\s*\(\s*\[(?P<body>.*?)\]\s*\)",
        code,
        re.S,
    )
    if not money_set or "'sendmany'" not in money_set.group("body"):
        return False
    return all(
        re.search(pattern, code, re.S)
        for pattern in (
            r"const\s+guarded\s*=\s*DaemonInterface\.MONEY_RPCS\.has\(method\)",
            r"if\s*\(\s*guarded\s*&&\s*err\.ambiguous\s*\).*?throw\s+err",
            r"anyAmbiguous\s*=\s*anyAmbiguous\s*\|\|\s*Boolean\(err\.ambiguous\)",
        )
    )


def audit_wam_source(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []

    share = _read(root, "pool/lib/shareProcessor.js")
    daemon = _read(root, "pool/lib/daemon.js")
    patcher = _read(root, "scripts/patch_upstream.py")

    share_code = _strip_js_comments(share)
    payment = _method_body(
        share_code,
        "async _processPayments()",
        "async pruneHashrateWindow()",
    )

    has_delete = bool(
        re.search(
            r"catch\s*\(err\).*?redis\.del\([^\n]*payment:inflight",
            payment,
            re.S,
        )
    )
    guarded_delete = bool(
        re.search(
            r"catch\s*\(err\).*?"
            r"if\s*\(\s*err\.ambiguous\s*!==\s*false\s*\)\s*\{.*?"
            r"return\s*;.*?\}.*?"
            r"redis\.del\([^\n]*payment:inflight",
            payment,
            re.S,
        )
    )
    if (
        "sendmany" in payment
        and "payment:inflight" in payment
        and has_delete
        and not guarded_delete
    ):
        findings.append(Finding(
            finding_id="WS-POOL-001",
            severity="HIGH",
            confidence="CONFIRMED-LOGIC-RISK",
            title="Ambiguous sendmany failure can discard payout intent",
            path="pool/lib/shareProcessor.js",
            evidence="sendmany failure path can delete payment:inflight without proving non-execution",
            impact=("If wamd accepts or broadcasts a payment but the HTTP response is lost or times out, "
                    "the next run can construct another economic payment for the same debt."),
            recommendation=("Keep the durable intent on unknown outcomes and only clear it after a failure "
                            "that proves the money-moving RPC did not execute."),
        ))

    if (
        "async cmd(method" in daemon
        and "for (const d of ordered)" in daemon
        and "sendmany" in payment
        and "daemon.cmd('sendmany'" in payment
        and not _money_rpc_failover_is_guarded(daemon)
    ):
        findings.append(Finding(
            finding_id="WS-POOL-002",
            severity="HIGH",
            confidence="CONFIRMED-ARCHITECTURE-RISK",
            title="Generic daemon failover includes non-idempotent sendmany",
            path="pool/lib/daemon.js",
            evidence="cmd() can retry sendmany across daemons after an outcome-ambiguous failure",
            impact="A timeout after execution on daemon A can cause the same logical payout to execute again on daemon B.",
            recommendation=("Classify RPC failures at the transport boundary and prevent money-moving RPC "
                            "failover whenever the first daemon's execution outcome is unknown."),
        ))

    if (
        "WAM_PRESYNC_POW_SKIPPED" in patcher
        and "bool HasValidProofOfWork" in patcher
        and re.search(r"WAM_PRESYNC_POW_SKIPPED.*?return true;", patcher, re.S)
    ):
        findings.append(Finding(
            finding_id="WS-P2P-001",
            severity="HIGH-PRIORITY",
            confidence="REVIEW-REQUIRED",
            title="Headers pre-sync PoW anti-DoS gate is bypassed for RandomX",
            path="scripts/patch_upstream.py",
            evidence="WAM_PRESYNC_POW_SKIPPED replaces HasValidProofOfWork with unconditional success",
            impact=("Consensus validation later still checks RandomX, but pre-sync can account claimed header work "
                    "before proving equivalent RandomX work, expanding remote resource-exhaustion surface."),
            recommendation=("Add a RandomX-aware pre-sync verifier with enough candidate-chain context to derive "
                            "the correct seed, then fuzz/header-spam test it before changing severity."),
        ))

    return findings


def worst_severity(findings: Iterable[Finding]) -> int:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH-PRIORITY": 3, "HIGH": 4, "CRITICAL": 5}
    return max((order.get(f.severity, 0) for f in findings), default=0)
