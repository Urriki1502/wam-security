"""Targeted source-level security checks for WAM-owned code paths."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable

from wam_security.audit.findings import Finding


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def audit_wam_source(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []

    share = _read(root, "pool/lib/shareProcessor.js")
    daemon = _read(root, "pool/lib/daemon.js")
    patcher = _read(root, "scripts/patch_upstream.py")

    if (
        "sendmany" in share
        and "payment:inflight" in share
        and re.search(r"catch\s*\(err\).*?payment:inflight", share, re.S)
        and re.search(r"catch\s*\(err\).*?redis\.del\([^\n]*payment:inflight", share, re.S)
    ):
        findings.append(Finding(
            finding_id="WS-POOL-001",
            severity="HIGH",
            confidence="CONFIRMED-LOGIC-RISK",
            title="Ambiguous sendmany failure can discard payout intent",
            path="pool/lib/shareProcessor.js",
            evidence="sendmany failure path deletes payment:inflight while balances remain owed",
            impact=("If wamd accepts or broadcasts a payment but the HTTP response is lost or times out, "
                    "the next run can construct another economic payment for the same debt."),
            recommendation=("Pre-build and sign one deterministic transaction, persist raw tx plus txid before "
                            "broadcast, and reconcile ambiguous outcomes by txid before retry or balance mutation."),
        ))

    if (
        "async cmd(method" in daemon
        and "for (const d of ordered)" in daemon
        and "sendmany" in share
        and "daemon.cmd('sendmany'" in share
    ):
        findings.append(Finding(
            finding_id="WS-POOL-002",
            severity="HIGH",
            confidence="CONFIRMED-ARCHITECTURE-RISK",
            title="Generic daemon failover includes non-idempotent sendmany",
            path="pool/lib/daemon.js",
            evidence="cmd() retries methods across daemons and payout code invokes sendmany through cmd()",
            impact="A timeout after execution on daemon A can cause the same logical payout to execute again on daemon B.",
            recommendation=("Separate read/idempotent RPC failover from money-moving RPCs. Broadcast one precomputed "
                            "raw transaction identity and make retries idempotent."),
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
