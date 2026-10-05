#!/usr/bin/env python3
"""Map WAM's owned Electrum boundary and exercise omission semantics with local fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

from wam_security.electrum.trust import (
    compare_servers,
    compare_with_node,
    single_server_completeness_claim,
)

WAM_COMMIT = "bb6d5214f2f5de3b7464587cc1b2949d221dcd18"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wam_root", type=Path)
    ap.add_argument("--expected-commit", default=WAM_COMMIT)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("security-reports/electrum-trust.json"),
    )
    args = ap.parse_args()
    root = args.wam_root.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if head != args.expected_commit:
        raise SystemExit(f"WAM checkout is {head}, expected {args.expected_commit}")

    checker = (root / "scripts/check_electrum.py").read_text(encoding="utf-8")
    endpoints = json.loads(
        (root / "integration/komodo/electrums-WAM.json").read_text(encoding="utf-8")
    )
    source_checks = {
        "server_version_checked": 'rpc(sock, "server.version"' in checker,
        "header_height_checked":
            'rpc(sock, "blockchain.headers.subscribe")' in checker,
        "genesis_identity_checked": 'rpc(sock, "server.features")' in checker,
        "tls_certificate_validation_enabled":
            "ssl.create_default_context()" in checker,
        "wallet_history_completeness_not_checked":
            "blockchain.scripthash.get_history" not in checker,
        "published_ssl_endpoint_present":
            any(e.get("protocol") == "SSL" and e.get("url") for e in endpoints),
    }
    if not all(source_checks.values()):
        raise AssertionError(
            "Electrum source contract changed: "
            + json.dumps(source_checks, sort_keys=True)
        )

    shown = [{"tx_hash": "11" * 32, "height": 10}]
    complete = shown + [{"tx_hash": "22" * 32, "height": 11}]
    peer = compare_servers(shown, complete)
    node = compare_with_node(shown, complete)
    fixture_checks = {
        "single_server_inclusion_cannot_prove_non_omission":
            single_server_completeness_claim(True) == "UNPROVEN_BY_SINGLE_SERVER",
        "two_accepted_servers_reveal_divergence": not peer["agree"],
        "two_servers_do_not_identify_truth": not peer["truth_resolved"],
        "node_derived_expected_history_detects_omission":
            not node["complete"] and len(node["missing_from_server"]) == 1,
    }
    if not all(fixture_checks.values()):
        raise AssertionError("Electrum omission fixture failed")

    evidence = {
        "schema": "wam-security-electrum-trust/v1",
        "target": {
            "repository": "wamcoin-core-dev/wam-coin",
            "commit": head,
        },
        "source_checks": source_checks,
        "fixture_checks": fixture_checks,
        "first_party_wallet_note": (
            "The current WAM Silent Wallet path uses a local validating WAM Core node "
            "through WAM SDK, not Electrum. WAM Core publishes Electrum endpoints for "
            "ecosystem clients; downstream client wallet internals are outside this "
            "WAM-owned source audit."
        ),
        "result": "PASS",
    }
    out = args.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("Electrum trust-boundary regression: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
