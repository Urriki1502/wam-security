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


def audit_money_safety(root: str | Path) -> list[Finding]:
    root = Path(root)
    share = _read(root, "pool/lib/shareProcessor.js")
    daemon = _read(root, "pool/lib/daemon.js")
    mainnet = _read(root, "pool/config.mainnet.json")
    findings: list[Finding] = []

    if "daemon.cmd('sendmany'" in share:
        findings.append(_f(
            "WS-MONEY-101", "HIGH",
            "Payout transaction identity is created inside sendmany",
            "pool/lib/shareProcessor.js",
            "payment path calls daemon.cmd('sendmany', ...) after persisting only payout amounts",
            "A timeout can leave the caller unable to prove which exact transaction was created or broadcast.",
            "Create/fund/sign one transaction first, persist raw transaction plus txid, then broadcast only that identity.",
        ))

    intent_match = re.search(r"const intent\s*=\s*\{(?P<body>.*?)\};\s*await this\.redis\.set\(this\.k\('payment:inflight'\)", share, re.S)
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

    if re.search(r"catch\s*\(err\).*?redis\.del\(this\.k\('payment:inflight'\)\)", share, re.S):
        findings.append(_f(
            "WS-MONEY-103", "HIGH",
            "Ambiguous RPC failure deletes the payout recovery record",
            "pool/lib/shareProcessor.js",
            "sendmany catch path deletes payment:inflight",
            "HTTP timeout/connection loss does not prove the node failed before accepting the spend; deleting identity permits a later duplicate payment.",
            "Never discard an attempted payment identity on transport failure; reconcile or rebroadcast the exact same raw transaction.",
        ))

    if (
        "const pipe = this.redis.pipeline();" in share
        and "pipe.hincrby(this.k('balances'), address, -amount);" in share
        and "pipe.hincrby(this.k('paid'), address, amount);" in share
        and "pipe.del(this.k('payment:inflight'));" in share
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
        and "daemon.cmd('sendmany'" in share
    ):
        findings.append(_f(
            "WS-MONEY-105", "HIGH",
            "Non-idempotent wallet spend inherits generic RPC failover",
            "pool/lib/daemon.js",
            "generic cmd() retries the same method across daemons and the payout path sends sendmany through cmd()",
            "A timeout after daemon A accepted a spend can cause daemon B to create a second transaction for the same debt.",
            "Use failover for read/idempotent RPCs only. Money movement must broadcast one precomputed raw transaction identity.",
        ))

    if "this.startupReconcile().catch" in share and "this.paused = true" in share:
        findings.append(_f(
            "WS-MONEY-106", "MEDIUM",
            "Startup reconciliation failure is logged instead of failing the money path closed",
            "pool/lib/shareProcessor.js",
            "start() launches startupReconcile asynchronously and its rejection handler only logs",
            "If the initial Redis reconciliation check fails transiently, later payment ticks can resume without proving there is no unresolved prior intent.",
            "Await reconciliation before scheduling payments and keep the money path paused on reconciliation errors until a successful check completes.",
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
