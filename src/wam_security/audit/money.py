"""V4 money-path source audit for WAM-owned payout code."""

from __future__ import annotations

from pathlib import Path
import re

from wam_security.audit.findings import Finding


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _f(fid: str, severity: str, title: str, path: str, evidence: str, impact: str, rec: str) -> Finding:
    return Finding(
        finding_id=fid,
        severity=severity,
        confidence="CONFIRMED-MONEY-PATH-RISK",
        title=title,
        path=path,
        evidence=evidence,
        impact=impact,
        recommendation=rec,
    )


def _strip_js_comments(text: str) -> str:
    """Remove comments before shape matching so historical prose does not look like live code."""
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


def audit_money_safety(root: str | Path) -> list[Finding]:
    root = Path(root)
    share = _read(root, "pool/lib/shareProcessor.js")
    daemon = _read(root, "pool/lib/daemon.js")
    mainnet = _read(root, "pool/config.mainnet.json")
    findings: list[Finding] = []

    share_code = _strip_js_comments(share)
    payment = _method_body(
        share_code,
        "async _processPayments()",
        "async pruneHashrateWindow()",
    )
    start = _method_body(share_code, "start()", "stop()")

    if "daemon.cmd('sendmany'" in payment:
        findings.append(_f(
            "WS-MONEY-101", "HIGH",
            "Payout transaction identity is created inside sendmany",
            "pool/lib/shareProcessor.js",
            "payment path calls daemon.cmd('sendmany', ...) after persisting only payout amounts",
            "A timeout can leave the caller unable to prove which exact transaction was created or broadcast.",
            "Create/fund/sign one transaction first, persist raw transaction plus txid, then broadcast only that identity.",
        ))

    intent_match = re.search(
        r"const intent\s*=\s*\{(?P<body>.*?)\};\s*await this\.redis\.set\(this\.k\('payment:inflight'\)",
        payment,
        re.S,
    )
    if intent_match:
        body = intent_match.group("body")
        if "txid" not in body and "rawTx" not in body and "raw_tx" not in body:
            findings.append(_f(
                "WS-MONEY-102", "HIGH",
                "Durable inflight record has no transaction identity",
                "pool/lib/shareProcessor.js",
                "payment:inflight stores startedAt/total/payouts but no txid or signed raw transaction",
                "Crash recovery can identify the economic intent but cannot idempotently rebroadcast the same transaction.",
                "Persist signed raw transaction, txid, intent id, wallet name and policy snapshot before first broadcast.",
            ))

    # A delete inside catch is only unsafe when ambiguous outcomes can reach it.
    # The maintainer patch keeps the intent on every unknown outcome and returns;
    # only err.ambiguous === false (proved refusal/non-execution) may clear it.
    has_inflight_delete = bool(
        re.search(r"catch\s*\(err\).*?redis\.del\(this\.k\('payment:inflight'\)\)", payment, re.S)
    )
    guarded_delete = bool(
        re.search(
            r"catch\s*\(err\).*?"
            r"if\s*\(\s*err\.ambiguous\s*!==\s*false\s*\)\s*\{.*?"
            r"return\s*;.*?\}.*?"
            r"redis\.del\(this\.k\('payment:inflight'\)\)",
            payment,
            re.S,
        )
    )
    if has_inflight_delete and not guarded_delete:
        findings.append(_f(
            "WS-MONEY-103", "HIGH",
            "Ambiguous RPC failure deletes the payout recovery record",
            "pool/lib/shareProcessor.js",
            "sendmany catch path can delete payment:inflight without proving non-execution",
            "HTTP timeout/connection loss does not prove the node failed before accepting the spend; deleting identity permits a later duplicate payment.",
            "Never discard an attempted payment identity on transport failure; reconcile or rebroadcast the exact same raw transaction.",
        ))

    # Scope the accounting primitive to _processPayments(). Other pipelines in
    # share accounting/block maturation are intentionally unrelated.
    if (
        "const pipe = this.redis.pipeline();" in payment
        and "pipe.hincrby(this.k('balances'), address, -amount);" in payment
        and "pipe.hincrby(this.k('paid'), address, amount);" in payment
        and "pipe.del(this.k('payment:inflight'));" in payment
    ):
        findings.append(_f(
            "WS-MONEY-104", "HIGH",
            "Payment accounting commit uses non-atomic Redis pipeline",
            "pool/lib/shareProcessor.js",
            "balance deduction, paid increment, payment journal and inflight deletion are grouped with pipeline(), not MULTI/EXEC or Lua",
            "A process or connection failure can expose partially applied accounting and make restart reconciliation ambiguous.",
            "Commit payment accounting with a single Lua script or Redis transaction that validates the active intent and applies all ledger mutations atomically.",
        ))

    if (
        "async cmd(method" in daemon
        and "for (const d of ordered)" in daemon
        and "daemon.cmd('sendmany'" in payment
        and not _money_rpc_failover_is_guarded(daemon)
    ):
        findings.append(_f(
            "WS-MONEY-105", "HIGH",
            "Non-idempotent wallet spend inherits generic RPC failover",
            "pool/lib/daemon.js",
            "generic cmd() can retry sendmany across daemons after an outcome-ambiguous failure",
            "A timeout after daemon A accepted a spend can cause daemon B to create a second transaction for the same debt.",
            "Fail over money-moving RPCs only after failures that prove non-execution; unknown outcomes must stop before another daemon.",
        ))

    if "this.startupReconcile().catch" in start:
        fail_closed_start = bool(
            re.search(
                r"this\.paused\s*=\s*true\s*;\s*"
                r"this\.startupReconcile\(\)\.catch",
                start,
                re.S,
            )
        )
        if not fail_closed_start:
            findings.append(_f(
                "WS-MONEY-106", "MEDIUM",
                "Startup reconciliation failure is logged instead of failing the money path closed",
                "pool/lib/shareProcessor.js",
                "start() launches startupReconcile asynchronously without first forcing payments paused",
                "If the initial Redis reconciliation check fails transiently, later payment ticks can resume without proving there is no unresolved prior intent.",
                "Start with payments paused and only release them after successful reconciliation proves there is no unresolved intent.",
            ))

    if '"wallet": "pool"' not in mainnet:
        findings.append(_f(
            "WS-MONEY-107", "HIGH",
            "Mainnet payout daemon does not declare a dedicated wallet",
            "pool/config.mainnet.json",
            "expected named payout wallet is absent",
            "Pool funds can be mixed with unrelated wallet funds and wallet routing becomes ambiguous.",
            "Require a dedicated named payout wallet and verify ownership of poolAddress at startup.",
        ))

    return findings
