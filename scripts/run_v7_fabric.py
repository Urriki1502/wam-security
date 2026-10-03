#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from hashlib import sha256
from pathlib import Path
import subprocess

from wam_security.fabric.core import build_status
from wam_security.fabric.live import fetch_json
from wam_security.fabric.status import (
    baseline_check,
    explorer_health_check,
    fork_check,
    payout_visibility_check,
    pool_health_check,
    release_integrity_check,
    source_drift_check,
    supply_check,
)
from wam_security.supplychain.identities import load_identity_lock


DEFAULT_EXPLORER = "https://explorer.wamcoin.org/api/status"
DEFAULT_POOL_HEALTH = "https://pool.wamcoin.org/api/health"
DEFAULT_POOL_STATS = "https://pool.wamcoin.org/api/stats"


def git(checkout: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(checkout), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def changed_paths(checkout: Path, old: str, new: str) -> list[str]:
    if old == new:
        return []
    try:
        subprocess.run(
            ["git", "-C", str(checkout), "cat-file", "-e", old + "^{commit}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        out = git(checkout, "diff", "--name-only", old + ".." + new)
        return [line for line in out.splitlines() if line]
    except Exception:
        return ["<diff-unavailable>"]


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("checkout", type=Path)
    p.add_argument("--report", type=Path, default=Path("security-reports/security-report.json"))
    p.add_argument("--baseline", type=Path, default=Path("baseline/expected_findings.json"))
    p.add_argument("--lock", type=Path, default=Path("supply-chain-lock.json"))
    p.add_argument("--release-json", type=Path)
    p.add_argument("--out", type=Path, default=Path("security-status"))
    p.add_argument("--offline", action="store_true")
    p.add_argument("--explorer-url", default=DEFAULT_EXPLORER)
    p.add_argument("--pool-health-url", default=DEFAULT_POOL_HEALTH)
    p.add_argument("--pool-stats-url", default=DEFAULT_POOL_STATS)
    args = p.parse_args()

    checkout = args.checkout.resolve()
    report = read_json(args.report)
    baseline = read_json(args.baseline)
    lock = load_identity_lock(args.lock)

    head = git(checkout, "rev-parse", "HEAD").lower()
    audited = str(lock["target_wam"]["commit"]).lower()
    paths = changed_paths(checkout, audited, head)

    if args.offline:
        explorer_probe = None
        pool_health_probe = None
        pool_stats_probe = None
    else:
        explorer_probe = fetch_json(args.explorer_url)
        pool_health_probe = fetch_json(args.pool_health_url)
        pool_stats_probe = fetch_json(args.pool_stats_url)

    explorer = explorer_probe.data if explorer_probe and explorer_probe.ok else None
    pool_health = pool_health_probe.data if pool_health_probe and pool_health_probe.ok else None
    pool_stats = pool_stats_probe.data if pool_stats_probe and pool_stats_probe.ok else None

    releases = None
    if args.release_json and args.release_json.exists():
        raw = read_json(args.release_json)
        releases = raw if isinstance(raw, list) else None

    checks = [
        source_drift_check(
            current_head=head,
            audited_head=audited,
            changed_paths=paths,
        ),
        baseline_check(
            findings=list(report.get("findings", [])),
            expected_ids=set(baseline.get("expected_finding_ids", [])),
        ),
        explorer_health_check(
            explorer,
            error=None if explorer_probe is None else explorer_probe.error,
        ),
        supply_check(explorer),
        pool_health_check(
            pool_health,
            error=None if pool_health_probe is None else pool_health_probe.error,
        ),
        payout_visibility_check(pool_stats),
        fork_check(explorer, pool_stats),
        release_integrity_check(releases),
    ]

    metrics = {
        "source_changed_paths": paths,
        "explorer_height": None if explorer is None else ((explorer.get("chain") or {}).get("blocks")),
        "pool_height": None if pool_stats is None else ((pool_stats.get("network") or {}).get("height") or (pool_stats.get("network") or {}).get("blocks")),
        "latest_release": None if not releases else releases[0].get("tag_name"),
        "live": {
            "explorer_status": None if explorer_probe is None else explorer_probe.status,
            "pool_health_status": None if pool_health_probe is None else pool_health_probe.status,
            "pool_stats_status": None if pool_stats_probe is None else pool_stats_probe.status,
        },
    }

    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    status = build_status(
        generated_at=generated,
        fabric_version="0.7.0",
        target_repository=lock["target_wam"]["repository"],
        target_head=head,
        audited_head=audited,
        checks=checks,
        metrics=metrics,
    )

    args.out.mkdir(parents=True, exist_ok=True)
    status_path = args.out / "security-status.json"
    status_path.write_text(json.dumps(status, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    artifact_digest = sha256(status_path.read_bytes()).hexdigest()
    (args.out / "security-status.sha256").write_text(
        f"{artifact_digest}  security-status.json\n",
        encoding="utf-8",
    )

    print(json.dumps({
        "overall": status["overall"],
        "release_blocked": status["release_blocked"],
        "body_sha256": status["body_sha256"],
        "artifact_sha256": artifact_digest,
        "checks": {
            c["check_id"]: c["state"] for c in status["checks"]
        },
    }, sort_keys=True))
    print(f"V7 continuous security fabric: {status['overall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
