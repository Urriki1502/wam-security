"""Source-semantic regression checks for WAM DGW and RandomX consensus code."""

from __future__ import annotations

from pathlib import Path
import re

from wam_security.audit.findings import Finding
from wam_security.consensus.randomx import MAINNET, REGTEST, TESTNET


def _read(root: Path, path: str) -> str:
    p = root / path
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _finding(fid: str, title: str, path: str, evidence: str, recommendation: str) -> Finding:
    return Finding(
        finding_id=fid,
        severity="HIGH",
        confidence="CONFIRMED-CONSENSUS-DRIFT",
        title=title,
        path=path,
        evidence=evidence,
        impact="The independent V3 consensus model may no longer describe the node's consensus behavior.",
        recommendation=recommendation,
    )


def audit_consensus_semantics(root: str | Path) -> list[Finding]:
    root = Path(root)
    pow_cpp = _read(root, "src/wam/pow.cpp")
    rx_cpp = _read(root, "src/wam/crypto/randomx_hash.cpp")
    chain = _read(root, "src/wam/chainparams.cpp")
    findings: list[Finding] = []

    dgw_checks = {
        "24-block parameter use": r"WAM_DGW_PAST_BLOCKS",
        "exact running recurrence": r"bnPastTargetAvg\s*=\s*\(bnPastTargetAvg\s*\*\s*nCountBlocks\s*\+\s*bnTarget\)\s*/\s*\(nCountBlocks\s*\+\s*1\)",
        "minimum timespan clamp": r"nTargetTimespan\s*/\s*WAM_DGW_CLAMP_FACTOR",
        "maximum timespan clamp": r"nTargetTimespan\s*\*\s*WAM_DGW_CLAMP_FACTOR",
        "pow-limit cap": r"bnNew\s*>\s*bnPowLimit",
    }
    missing_dgw = [name for name, pattern in dgw_checks.items() if not re.search(pattern, pow_cpp)]
    if missing_dgw:
        findings.append(_finding(
            "WS-CONS-101",
            "DGW source semantics differ from the V3 model",
            "src/wam/pow.cpp",
            "missing semantic anchors: " + ", ".join(missing_dgw),
            "Review the DGW change as consensus-critical; update independent vectors only after intentional approval.",
        ))

    rx_checks = {
        "network epoch parameter": r"params\.nRandomXEpochBlocks",
        "network lag parameter": r"params\.nRandomXEpochLag",
        "bootstrap lag boundary": r"nHeight\s*<=\s*nLag",
        "lagged height": r"nHeight\s*-\s*nLag",
        "epoch-floor formula": r"\(nLagged\s*/\s*nEpoch\)\s*\*\s*nEpoch",
        "seed ancestor lookup": r"GetAncestor\(nSeedHeight\)",
    }
    missing_rx = [name for name, pattern in rx_checks.items() if not re.search(pattern, rx_cpp)]
    if missing_rx:
        findings.append(_finding(
            "WS-CONS-102",
            "RandomX seed semantics differ from the V3 model",
            "src/wam/crypto/randomx_hash.cpp",
            "missing semantic anchors: " + ", ".join(missing_rx),
            "Treat RandomX seed derivation changes as consensus-critical and regenerate cross-language boundary vectors.",
        ))

    expected_profiles = {
        "mainnet": (MAINNET.epoch_blocks, MAINNET.epoch_lag),
        "testnet": (TESTNET.epoch_blocks, TESTNET.epoch_lag),
        "regtest": (REGTEST.epoch_blocks, REGTEST.epoch_lag),
    }
    # Mainnet uses named constants; testnet/regtest use literals in the pinned source.
    profile_patterns = {
        "mainnet": (
            r"nRandomXEpochBlocks\s*=\s*WAM_RANDOMX_EPOCH_BLOCKS",
            r"nRandomXEpochLag\s*=\s*WAM_RANDOMX_EPOCH_LAG",
        ),
        "testnet": (
            rf"nRandomXEpochBlocks\s*=\s*{TESTNET.epoch_blocks}\s*;",
            rf"nRandomXEpochLag\s*=\s*{TESTNET.epoch_lag}\s*;",
        ),
        "regtest": (
            rf"nRandomXEpochBlocks\s*=\s*{REGTEST.epoch_blocks}\s*;",
            rf"nRandomXEpochLag\s*=\s*{REGTEST.epoch_lag}\s*;",
        ),
    }
    missing_profiles = []
    for name, patterns in profile_patterns.items():
        if not all(re.search(pattern, chain) for pattern in patterns):
            missing_profiles.append(f"{name}={expected_profiles[name][0]}/{expected_profiles[name][1]}")
    if missing_profiles:
        findings.append(_finding(
            "WS-CONS-103",
            "RandomX network profile drift detected",
            "src/wam/chainparams.cpp",
            "expected profiles not found: " + ", ".join(missing_profiles),
            "Review network-specific epoch/lag changes and update V3 profiles deliberately.",
        ))

    return findings
