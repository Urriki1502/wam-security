"""Status primitives and policy evaluation for the V7 security fabric."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Iterable


VALID_STATES = {"PASS", "WARN", "FAIL", "UNKNOWN"}


@dataclass(frozen=True)
class Check:
    check_id: str
    category: str
    state: str
    critical: bool
    summary: str
    details: dict[str, Any]

    def __post_init__(self) -> None:
        if self.state not in VALID_STATES:
            raise ValueError(f"invalid check state: {self.state}")


def evaluate(checks: Iterable[Check]) -> tuple[str, bool]:
    material = list(checks)
    if any(c.state == "FAIL" and c.critical for c in material):
        return "RED", True
    if any(c.state in {"WARN", "UNKNOWN", "FAIL"} for c in material):
        return "YELLOW", False
    return "GREEN", False


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def status_digest(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def build_status(
    *,
    generated_at: str,
    fabric_version: str,
    target_repository: str,
    target_head: str,
    audited_head: str,
    checks: Iterable[Check],
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered = sorted(list(checks), key=lambda c: c.check_id)
    overall, blocked = evaluate(ordered)
    payload = {
        "schema": "wam-security-status/v1",
        "generated_at": generated_at,
        "fabric_version": fabric_version,
        "target": {
            "repository": target_repository,
            "head": target_head,
            "audited_head": audited_head,
        },
        "overall": overall,
        "release_blocked": blocked,
        "checks": [asdict(c) for c in ordered],
        "metrics": metrics or {},
    }
    payload["body_sha256"] = status_digest(payload)
    return payload
