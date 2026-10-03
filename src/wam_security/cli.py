"""wam-security command line interface."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from wam_security.audit.consensus import audit_consensus_constants
from wam_security.audit.consensus_semantics import audit_consensus_semantics
from wam_security.audit.runtime import audit_runtime_controls
from wam_security.audit.money import audit_money_safety
from wam_security.audit.source import audit_wam_source
from wam_security.audit.workflow import audit_workflows
from wam_security.audit.supply_chain import audit_supply_chain
from wam_security.audit.independent_assurance import audit_independent_assurance
from wam_security.report import write_reports


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wam-security")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit", help="audit a WAM source checkout")
    a.add_argument("checkout", type=Path)
    a.add_argument("--out", type=Path, default=Path("security-reports"))
    a.add_argument("--target", default="local-checkout")
    a.add_argument("--fail-on-high", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    findings = (
        audit_consensus_constants(args.checkout)
        + audit_consensus_semantics(args.checkout)
        + audit_money_safety(args.checkout)
        + audit_runtime_controls(args.checkout)
        + audit_wam_source(args.checkout)
        + audit_workflows(args.checkout)
        + audit_supply_chain(args.checkout)
        + audit_independent_assurance(args.checkout)
    )
    write_reports(findings, args.out, args.target)
    for f in findings:
        print(f"[{f.severity}] {f.finding_id}: {f.title} ({f.path})")
    if args.fail_on_high and any(f.severity in {"HIGH", "CRITICAL"} for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
