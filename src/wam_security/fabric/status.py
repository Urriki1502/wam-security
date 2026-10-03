"""Build V7 policy checks from source, audit, release and live evidence."""

from __future__ import annotations

from typing import Any, Iterable

from wam_security.fabric.core import Check


CRITICAL_PATH_PREFIXES = (
    "scripts/patch_upstream.py",
    "src/wam/",
    "pool/lib/shareProcessor.js",
    "pool/lib/daemon.js",
    ".github/workflows/",
    "scripts/fetch-upstream.sh",
    "scripts/package_release.sh",
    "src/wam/consensus/",
    "src/wam/pow.cpp",
    "src/wam/crypto/",
)


def source_drift_check(
    *,
    current_head: str,
    audited_head: str,
    changed_paths: Iterable[str],
) -> Check:
    paths = sorted(set(changed_paths))
    if current_head == audited_head:
        return Check(
            "source.drift",
            "source",
            "PASS",
            True,
            "WAM main matches the last fully audited source commit.",
            {"head": current_head, "changed_paths": []},
        )

    if not paths or "<diff-unavailable>" in paths:
        return Check(
            "source.drift",
            "source",
            "FAIL",
            True,
            "WAM main moved but the fabric could not classify the source diff.",
            {
                "head": current_head,
                "audited_head": audited_head,
                "changed_paths": paths,
            },
        )

    critical = [
        path for path in paths
        if any(path == prefix or path.startswith(prefix) for prefix in CRITICAL_PATH_PREFIXES)
    ]
    if critical:
        return Check(
            "source.drift",
            "source",
            "FAIL",
            True,
            "Unaudited source drift touches security-critical paths.",
            {
                "head": current_head,
                "audited_head": audited_head,
                "changed_paths": paths,
                "critical_paths": critical,
            },
        )
    return Check(
        "source.drift",
        "source",
        "WARN",
        False,
        "WAM main moved beyond the audited commit on noncritical paths.",
        {
            "head": current_head,
            "audited_head": audited_head,
            "changed_paths": paths,
        },
    )


def baseline_check(
    *,
    findings: list[dict[str, Any]],
    expected_ids: set[str],
) -> Check:
    current_ids = {str(f.get("finding_id")) for f in findings}
    new_ids = sorted(current_ids - expected_ids)
    missing_ids = sorted(expected_ids - current_ids)
    by_id = {str(f.get("finding_id")): f for f in findings}

    critical_new = [
        fid for fid in new_ids
        if str(by_id.get(fid, {}).get("severity", "")).upper() in {"CRITICAL", "HIGH"}
    ]
    if critical_new:
        return Check(
            "audit.baseline",
            "audit",
            "FAIL",
            True,
            "New high/critical findings appeared outside the reviewed baseline.",
            {
                "new": new_ids,
                "new_high_or_critical": critical_new,
                "missing": missing_ids,
            },
        )
    if new_ids or missing_ids:
        return Check(
            "audit.baseline",
            "audit",
            "WARN",
            False,
            "Audit findings changed and require baseline review.",
            {"new": new_ids, "missing": missing_ids},
        )
    return Check(
        "audit.baseline",
        "audit",
        "PASS",
        True,
        "Current findings match the reviewed baseline exactly.",
        {"known_findings": len(current_ids)},
    )


def explorer_health_check(explorer: dict[str, Any] | None, *, error: str | None = None) -> Check:
    if explorer is None:
        return Check(
            "live.explorer",
            "live",
            "UNKNOWN",
            False,
            "Explorer status could not be measured.",
            {"error": error},
        )
    online = explorer.get("nodeOnline")
    stale = explorer.get("staleSeconds")
    if online is False:
        return Check(
            "live.explorer",
            "live",
            "FAIL",
            False,
            "The official explorer reports its backing node offline.",
            {"stale_seconds": stale, "error": explorer.get("error")},
        )
    if online is not True:
        return Check(
            "live.explorer",
            "live",
            "UNKNOWN",
            False,
            "Explorer response did not expose a definitive nodeOnline state.",
            {},
        )
    if isinstance(stale, (int, float)) and stale > 180:
        return Check(
            "live.explorer",
            "live",
            "WARN",
            False,
            "Explorer data is stale.",
            {"stale_seconds": stale},
        )
    return Check(
        "live.explorer",
        "live",
        "PASS",
        False,
        "Official explorer node is reachable and current.",
        {"height": _height(explorer), "stale_seconds": stale},
    )


def supply_check(explorer: dict[str, Any] | None) -> Check:
    if not explorer or not isinstance(explorer.get("supply"), dict):
        return Check(
            "consensus.supply",
            "consensus",
            "UNKNOWN",
            True,
            "Live supply data is unavailable.",
            {},
        )
    supply = explorer["supply"]
    circulating = supply.get("circulating")
    maximum = supply.get("maxSupply")
    expected = 22_000_000 * 100_000_000

    if not isinstance(maximum, int) or not isinstance(circulating, int):
        return Check(
            "consensus.supply",
            "consensus",
            "UNKNOWN",
            True,
            "Live supply fields are missing or not base-unit integers.",
            {"circulating": circulating, "max_supply": maximum},
        )
    if maximum != expected:
        return Check(
            "consensus.supply",
            "consensus",
            "FAIL",
            True,
            "Live node reports a maximum supply different from 22,000,000 WAM.",
            {"reported": maximum, "expected": expected},
        )
    if circulating > maximum:
        return Check(
            "consensus.supply",
            "consensus",
            "FAIL",
            True,
            "Live circulating supply exceeds the consensus cap.",
            {"circulating": circulating, "max_supply": maximum},
        )
    return Check(
        "consensus.supply",
        "consensus",
        "PASS",
        True,
        "Live supply is within the 22,000,000 WAM cap.",
        {
            "circulating": circulating,
            "max_supply": maximum,
            "source": supply.get("source"),
        },
    )


def pool_health_check(pool_health: dict[str, Any] | None, *, error: str | None = None) -> Check:
    if pool_health is None:
        return Check(
            "live.pool",
            "live",
            "UNKNOWN",
            False,
            "Official pool health could not be measured.",
            {"error": error},
        )
    if pool_health.get("ok") is False:
        return Check(
            "live.pool",
            "live",
            "FAIL",
            False,
            "Official pool reports unhealthy.",
            {"error": pool_health.get("error")},
        )
    if pool_health.get("ok") is True:
        return Check(
            "live.pool",
            "live",
            "PASS",
            False,
            "Official pool health endpoint reports healthy.",
            {},
        )
    return Check(
        "live.pool",
        "live",
        "UNKNOWN",
        False,
        "Pool health response was not definitive.",
        {},
    )


def payout_visibility_check(pool_stats: dict[str, Any] | None) -> Check:
    if pool_stats is None:
        return Check(
            "payout.visibility",
            "money",
            "UNKNOWN",
            False,
            "Public payout telemetry could not be measured.",
            {},
        )
    pool = pool_stats.get("pool")
    if not isinstance(pool, dict):
        return Check(
            "payout.visibility",
            "money",
            "UNKNOWN",
            False,
            "Pool stats response lacks the pool section.",
            {},
        )
    payments = pool.get("recentPayments")
    if payments is None:
        return Check(
            "payout.visibility",
            "money",
            "WARN",
            False,
            "Pool stats are reachable but public payout history is absent.",
            {},
        )
    if not isinstance(payments, list):
        return Check(
            "payout.visibility",
            "money",
            "WARN",
            False,
            "Public payout telemetry has an unexpected shape.",
            {"type": type(payments).__name__},
        )
    return Check(
        "payout.visibility",
        "money",
        "PASS",
        False,
        "Public payout telemetry is present.",
        {"recent_payments": len(payments)},
    )


def fork_check(
    explorer: dict[str, Any] | None,
    pool_stats: dict[str, Any] | None,
) -> Check:
    eh = _height(explorer)
    ph = _pool_height(pool_stats)
    if eh is None or ph is None:
        return Check(
            "consensus.fork-agreement",
            "consensus",
            "UNKNOWN",
            True,
            "Two independent public height observations are not both available.",
            {"explorer_height": eh, "pool_height": ph},
        )
    delta = abs(eh - ph)
    if delta > 6:
        return Check(
            "consensus.fork-agreement",
            "consensus",
            "FAIL",
            True,
            "Explorer and pool disagree by more than six blocks.",
            {"explorer_height": eh, "pool_height": ph, "delta": delta},
        )
    if delta > 2:
        return Check(
            "consensus.fork-agreement",
            "consensus",
            "WARN",
            False,
            "Explorer and pool heights are temporarily divergent.",
            {"explorer_height": eh, "pool_height": ph, "delta": delta},
        )
    return Check(
        "consensus.fork-agreement",
        "consensus",
        "PASS",
        True,
        "Explorer and pool height observations agree within tolerance.",
        {"explorer_height": eh, "pool_height": ph, "delta": delta},
    )


def release_integrity_check(releases: list[dict[str, Any]] | None) -> Check:
    if not releases:
        return Check(
            "release.integrity",
            "release",
            "UNKNOWN",
            True,
            "No published GitHub release metadata was available.",
            {},
        )
    release = releases[0]
    assets = {
        str(a.get("name"))
        for a in release.get("assets", [])
        if isinstance(a, dict)
    }
    required = {"SHA256SUMS", "SHA256SUMS.asc"}
    missing = sorted(required - assets)
    if missing:
        return Check(
            "release.integrity",
            "release",
            "FAIL",
            True,
            "Latest published release is missing signed checksum material.",
            {
                "tag": release.get("tag_name"),
                "missing": missing,
                "assets": sorted(assets),
            },
        )
    binary_assets = [
        name for name in assets
        if name not in required and (name.endswith(".tar.gz") or name.endswith(".zip"))
    ]
    if not binary_assets:
        return Check(
            "release.integrity",
            "release",
            "WARN",
            False,
            "Latest release has checksum material but no binary archives.",
            {"tag": release.get("tag_name")},
        )
    return Check(
        "release.integrity",
        "release",
        "PASS",
        True,
        "Latest release contains signed checksums and binary artifacts.",
        {
            "tag": release.get("tag_name"),
            "prerelease": release.get("prerelease"),
            "binary_assets": len(binary_assets),
        },
    )


def _height(explorer: dict[str, Any] | None) -> int | None:
    if not explorer:
        return None
    chain = explorer.get("chain")
    if not isinstance(chain, dict):
        return None
    value = chain.get("blocks")
    return value if isinstance(value, int) else None


def _pool_height(pool_stats: dict[str, Any] | None) -> int | None:
    if not pool_stats:
        return None
    network = pool_stats.get("network")
    if not isinstance(network, dict):
        return None
    for key in ("height", "blocks"):
        value = network.get(key)
        if isinstance(value, int):
            return value
    return None
