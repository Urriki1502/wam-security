"""V2 source checks for runtime resource and fail-closed controls."""

from __future__ import annotations

from pathlib import Path
import re

from wam_security.audit.findings import Finding


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def audit_runtime_controls(root: str | Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []

    stratum = _read(root, "pool/lib/stratumServer.js")
    api = _read(root, "pool/lib/api.js")
    daemon = _read(root, "pool/lib/daemon.js")

    required_stratum = {
        "buffer-cap": r"_buffer\.length\s*>\s*\d+",
        "message-rate-limit": r"maxMessagesPer10s",
        "global-connection-limit": r"maxConnections(?!PerIp)",
        "per-ip-connection-limit": r"maxConnectionsPerIp",
        "authorization-timeout": r"_authTimer\s*=\s*setTimeout\(",
    }
    if stratum:
        missing = [name for name, pat in required_stratum.items() if not re.search(pat, stratum)]
        if missing:
            findings.append(Finding(
                finding_id="WS-RUNTIME-001",
                severity="HIGH-PRIORITY",
                confidence="CONFIRMED-HARDENING-REGRESSION",
                title="Stratum runtime bounds are incomplete",
                path="pool/lib/stratumServer.js",
                evidence="missing controls: " + ", ".join(sorted(missing)),
                impact="An internet-facing miner socket may regain an avoidable memory, connection, or request-flood surface.",
                recommendation="Restore explicit pre-parse size/rate/connection/authentication bounds and regression-test each limit.",
            ))

    if api:
        missing_api = []
        if "only GET is supported" not in api:
            missing_api.append("read-only-method-gate")
        if "apiCacheEntries" not in api:
            missing_api.append("bounded-cache")
        if missing_api:
            findings.append(Finding(
                finding_id="WS-RUNTIME-002",
                severity="MEDIUM",
                confidence="CONFIRMED-HARDENING-REGRESSION",
                title="Pool API lost a documented runtime bound",
                path="pool/lib/api.js",
                evidence="missing controls: " + ", ".join(sorted(missing_api)),
                impact="Public API work or retained cache state may become less bounded than the reviewed baseline.",
                recommendation="Keep the API read-only and explicitly bound retained cache state.",
            ))

    if daemon and "req.on('timeout'" not in daemon and 'req.on("timeout"' not in daemon:
        findings.append(Finding(
            finding_id="WS-RUNTIME-003",
            severity="MEDIUM",
            confidence="CONFIRMED-HARDENING-REGRESSION",
            title="Daemon RPC client has no explicit request timeout",
            path="pool/lib/daemon.js",
            evidence="request timeout handler not detected",
            impact="A wedged local daemon can indefinitely consume pool request capacity.",
            recommendation="Keep an explicit finite RPC timeout and treat ambiguous money-moving RPC results as unknown.",
        ))

    return findings
