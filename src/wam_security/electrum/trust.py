"""Pure local models for Electrum identity, inclusion, divergence and omission boundaries."""

from __future__ import annotations

import hashlib
import re


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def verify_merkle_inclusion(
    txid: str,
    branch: list[str],
    position: int,
    merkle_root: str,
) -> bool:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", txid or "") or not re.fullmatch(
        r"[0-9a-fA-F]{64}", merkle_root or ""
    ):
        raise ValueError("HASH_FORMAT")
    if type(position) is not int or position < 0 or not isinstance(branch, list):
        raise ValueError("MERKLE_FORMAT")
    current = bytes.fromhex(txid)[::-1]
    pos = position
    for sibling_hex in branch:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", sibling_hex or ""):
            raise ValueError("MERKLE_FORMAT")
        sibling = bytes.fromhex(sibling_hex)[::-1]
        current = _hash256(sibling + current) if pos & 1 else _hash256(current + sibling)
        pos >>= 1
    return current[::-1].hex() == merkle_root.lower()


def verify_endpoint_claim(
    features: dict,
    header: dict,
    expected_genesis: str,
    node_height: int,
    lag_tolerance: int = 5,
) -> None:
    if not isinstance(features, dict) or features.get("genesis_hash") != expected_genesis:
        raise ValueError("ELECTRUM_CHAIN_IDENTITY")
    height = header.get("height") if isinstance(header, dict) else None
    if (
        type(height) is not int
        or type(node_height) is not int
        or abs(node_height - height) > lag_tolerance
    ):
        raise ValueError("ELECTRUM_HEIGHT_DIVERGENCE")


def normalized_history(entries: list[dict]) -> tuple[tuple[str, int], ...]:
    if not isinstance(entries, list):
        raise ValueError("HISTORY_FORMAT")
    result = []
    seen = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("HISTORY_FORMAT")
        txid, height = item.get("tx_hash"), item.get("height")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", txid or "") or type(height) is not int:
            raise ValueError("HISTORY_FORMAT")
        if txid in seen:
            raise ValueError("HISTORY_DUPLICATE")
        seen.add(txid)
        result.append((txid.lower(), height))
    return tuple(sorted(result))


def compare_servers(a: list[dict], b: list[dict]) -> dict:
    left, right = set(normalized_history(a)), set(normalized_history(b))
    return {
        "agree": left == right,
        "only_a": tuple(sorted(left - right)),
        "only_b": tuple(sorted(right - left)),
        "truth_resolved": False,
    }


def compare_with_node(server_history: list[dict], node_history: list[dict]) -> dict:
    server, node = set(normalized_history(server_history)), set(normalized_history(node_history))
    return {
        "missing_from_server": tuple(sorted(node - server)),
        "unexpected_from_server": tuple(sorted(server - node)),
        "complete": server == node,
    }


def single_server_completeness_claim(valid_inclusions: bool) -> str:
    """Inclusion proofs authenticate shown transactions; they cannot prove no transaction was omitted."""
    if not valid_inclusions:
        raise ValueError("INVALID_INCLUSION")
    return "UNPROVEN_BY_SINGLE_SERVER"
