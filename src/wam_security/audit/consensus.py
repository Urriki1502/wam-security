"""Compare WAM consensus constants against the independent security model."""

from __future__ import annotations

import ast
from pathlib import Path
import re

from wam_security import constants
from wam_security.audit.findings import Finding

_EXPECTED = {
    "WAM_COIN": constants.COIN,
    "WAM_MAX_MONEY": constants.MAX_MONEY,
    "WAM_GENESIS_PREMINE": constants.GENESIS_PREMINE,
    "WAM_INITIAL_BLOCK_SUBSIDY": constants.INITIAL_BLOCK_SUBSIDY,
    "WAM_SUBSIDY_HALVING_INTERVAL": constants.HALVING_INTERVAL,
    "WAM_MAX_HALVINGS": constants.MAX_HALVINGS,
    "WAM_DEVFEE_PERCENT": constants.DEVFEE_PERCENT,
    "WAM_DEVFEE_START_HEIGHT": constants.DEVFEE_START_HEIGHT,
    "WAM_DEVFEE_LAST_HEIGHT": constants.DEVFEE_LAST_HEIGHT,
    "WAM_RANDOMX_EPOCH_BLOCKS": constants.RANDOMX_EPOCH_BLOCKS,
    "WAM_RANDOMX_EPOCH_LAG": constants.RANDOMX_EPOCH_LAG,
}

_DECL = re.compile(
    r"static\s+constexpr\s+(?:int64_t|int|uint32_t)\s+(WAM_[A-Z0-9_]+)\s*=\s*([^;]+);"
)


def _eval_expr(expr: str, values: dict[str, int]) -> int:
    expr = expr.replace("'", "").strip()
    node = ast.parse(expr, mode="eval").body

    def walk(n: ast.AST) -> int:
        if isinstance(n, ast.Constant) and isinstance(n.value, int):
            return int(n.value)
        if isinstance(n, ast.Name) and n.id in values:
            return values[n.id]
        if isinstance(n, ast.BinOp):
            left, right = walk(n.left), walk(n.right)
            if isinstance(n.op, ast.Mult):
                return left * right
            if isinstance(n.op, ast.Add):
                return left + right
            if isinstance(n.op, ast.Sub):
                return left - right
            if isinstance(n.op, ast.LShift):
                return left << right
            if isinstance(n.op, ast.RShift):
                return left >> right
        raise ValueError(f"unsupported constant expression: {expr}")

    return walk(node)


def parse_wam_params(header_text: str) -> dict[str, int]:
    raw = {name: expr for name, expr in _DECL.findall(header_text)}
    values: dict[str, int] = {}
    unresolved = dict(raw)
    for _ in range(len(unresolved) + 1):
        progress = False
        for name, expr in list(unresolved.items()):
            try:
                values[name] = _eval_expr(expr, values)
            except (ValueError, KeyError):
                continue
            del unresolved[name]
            progress = True
        if not progress:
            break
    return values


def audit_consensus_constants(root: str | Path) -> list[Finding]:
    root = Path(root)
    path = root / "src/wam/wam-params.h"
    if not path.exists():
        return [Finding(
            finding_id="WS-CONS-000",
            severity="HIGH",
            confidence="CONFIRMED-INTEGRITY-GAP",
            title="WAM consensus parameter header is missing",
            path="src/wam/wam-params.h",
            evidence="file not found",
            impact="The independent model cannot establish which monetary/RandomX constants it is checking.",
            recommendation="Audit a complete WAM source checkout and fail closed when consensus inputs are unavailable.",
        )]

    parsed = parse_wam_params(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for name, expected in _EXPECTED.items():
        actual = parsed.get(name)
        if actual is None:
            findings.append(Finding(
                finding_id="WS-CONS-001",
                severity="HIGH",
                confidence="CONFIRMED-MODEL-DRIFT",
                title=f"Consensus constant {name} could not be independently parsed",
                path="src/wam/wam-params.h",
                evidence=f"expected model value {expected}; source value unavailable",
                impact="Security tests may be evaluating different consensus assumptions from the node.",
                recommendation="Review the source change and update the parser/model deliberately before release.",
            ))
        elif actual != expected:
            findings.append(Finding(
                finding_id="WS-CONS-001",
                severity="HIGH",
                confidence="CONFIRMED-MODEL-DRIFT",
                title=f"Consensus constant {name} differs from the independent model",
                path="src/wam/wam-params.h",
                evidence=f"source={actual} model={expected}",
                impact="Consensus economics or RandomX assumptions changed without a matching security-model review.",
                recommendation="Treat as a release-blocking change until the new value is reviewed and all boundary tests are updated.",
            ))
    return findings
