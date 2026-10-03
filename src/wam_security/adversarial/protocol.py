"""Bounded protocol-envelope validators used by V2 adversarial tests.

These are defensive reference guards, not replacements for WAM's production
parsers. Their purpose is to encode properties such as "reject oversized input
before expensive parsing" and "malformed JSON must not escape as a process
crash".
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


@dataclass(frozen=True)
class ProtocolLimits:
    max_line_bytes: int = 16_384
    max_method_bytes: int = 128
    max_params: int = 64
    max_json_depth: int = 16
    max_header_count: int = 2_000
    max_header_batch_bytes: int = 256_000


@dataclass(frozen=True)
class ProtocolDecision:
    accepted: bool
    reason: str
    work_units: int


def _json_depth(value: Any) -> int:
    if not isinstance(value, (dict, list)):
        return 1
    stack: list[tuple[Any, int]] = [(value, 1)]
    deepest = 1
    while stack:
        current, depth = stack.pop()
        deepest = max(deepest, depth)
        if isinstance(current, dict):
            stack.extend((v, depth + 1) for v in current.values())
        elif isinstance(current, list):
            stack.extend((v, depth + 1) for v in current)
    return deepest


def _param_count(params: Any) -> int:
    if params is None:
        return 0
    if isinstance(params, (list, dict)):
        return len(params)
    return 1


def validate_json_rpc_line(
    payload: bytes,
    limits: ProtocolLimits | None = None,
    *,
    require_method: bool = True,
) -> ProtocolDecision:
    """Validate one newline-delimited JSON-RPC/Stratum envelope defensively."""
    limits = limits or ProtocolLimits()
    size = len(payload)
    if size > limits.max_line_bytes:
        return ProtocolDecision(False, "oversized-line", 1)

    try:
        text = payload.decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        return ProtocolDecision(False, "invalid-utf8", max(1, size))

    if not text:
        return ProtocolDecision(False, "empty", max(1, size))

    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return ProtocolDecision(False, "malformed-json", max(1, size))

    if not isinstance(value, dict):
        return ProtocolDecision(False, "non-object", max(1, size))

    if _json_depth(value) > limits.max_json_depth:
        return ProtocolDecision(False, "json-too-deep", max(1, size))

    method = value.get("method")
    if require_method:
        if not isinstance(method, str) or not method:
            return ProtocolDecision(False, "missing-method", max(1, size))
        if len(method.encode("utf-8")) > limits.max_method_bytes:
            return ProtocolDecision(False, "method-too-long", max(1, size))

    if _param_count(value.get("params")) > limits.max_params:
        return ProtocolDecision(False, "too-many-params", max(1, size))

    return ProtocolDecision(True, "accepted", max(1, size))


def validate_header_batch(
    header_count: int,
    serialized_bytes: int,
    limits: ProtocolLimits | None = None,
) -> ProtocolDecision:
    """Apply cheap cardinality/size gates before contextual header processing."""
    limits = limits or ProtocolLimits()
    if header_count < 0 or serialized_bytes < 0:
        return ProtocolDecision(False, "negative-size", 1)
    if header_count > limits.max_header_count:
        return ProtocolDecision(False, "too-many-headers", 1)
    if serialized_bytes > limits.max_header_batch_bytes:
        return ProtocolDecision(False, "header-batch-too-large", 1)
    return ProtocolDecision(True, "accepted", max(1, header_count))
