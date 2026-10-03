"""Deterministic, bounded adversarial corpus generator for V2.

This is intentionally a local parser/resource test harness. It does not open
network sockets or target public infrastructure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import random

from wam_security.adversarial.protocol import (
    ProtocolLimits,
    validate_header_batch,
    validate_json_rpc_line,
)
from wam_security.adversarial.resource import AdmissionController, BudgetExceeded, RuntimeLimits


@dataclass(frozen=True)
class FuzzStats:
    seed: int
    cases: int
    accepted: int
    rejected: int
    max_work_units: int
    resource_rejections: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


_BASES = (
    b'{"id":1,"method":"mining.subscribe","params":[]}',
    b'{"id":2,"method":"mining.authorize","params":["worker","x"]}',
    b'{"id":3,"method":"getblockchaininfo","params":[]}',
)


def _mutate(rng: random.Random, case: int, limits: ProtocolLimits) -> bytes:
    base = bytearray(_BASES[case % len(_BASES)])
    op = rng.randrange(8)
    if op == 0 and base:
        del base[rng.randrange(len(base)):]
    elif op == 1 and base:
        base[rng.randrange(len(base))] ^= rng.randrange(1, 256)
    elif op == 2:
        base.extend(b" " * rng.randrange(0, limits.max_line_bytes + 64))
    elif op == 3:
        left = rng.randrange(1, limits.max_json_depth + 8)
        right = rng.randrange(1, limits.max_json_depth + 8)
        base = bytearray(b"[" * left + b"0" + b"]" * right)
    elif op == 4:
        obj = {
            "id": case,
            "method": "m" * rng.randrange(0, limits.max_method_bytes + 32),
            "params": list(range(rng.randrange(0, limits.max_params + 16))),
        }
        base = bytearray(json.dumps(obj, separators=(",", ":")).encode())
    elif op == 5:
        base = bytearray(rng.randbytes(rng.randrange(0, 512)))
    elif op == 6:
        base.extend(b"\xff\xfe")
    return bytes(base)


def run_adversarial_fuzz(seed: int, cases: int = 1_000) -> FuzzStats:
    if cases <= 0 or cases > 100_000:
        raise ValueError("cases must be between 1 and 100000")

    rng = random.Random(seed)
    limits = ProtocolLimits()
    resources = AdmissionController(RuntimeLimits(
        max_connections=64,
        max_connections_per_ip=8,
        max_message_bytes=limits.max_line_bytes,
        max_messages_per_10s=32,
        max_inflight_per_ip=8,
    ))

    accepted = rejected = resource_rejections = max_work = 0
    ips = [f"192.0.2.{i}" for i in range(1, 9)]
    for ip in ips:
        resources.connect(ip)

    for i in range(cases):
        payload = _mutate(rng, i, limits)
        decision = validate_json_rpc_line(payload, limits)
        max_work = max(max_work, decision.work_units)
        if decision.accepted:
            accepted += 1
        else:
            rejected += 1

        ip = ips[i % len(ips)]
        try:
            resources.record_message(ip, len(payload), i * 250)
            resources.begin_request(ip)
            resources.end_request(ip)
        except BudgetExceeded:
            resource_rejections += 1

        header_count = rng.randrange(-2, limits.max_header_count + 128)
        batch_bytes = rng.randrange(-2, limits.max_header_batch_bytes + 16_384)
        validate_header_batch(header_count, batch_bytes, limits)
        resources.assert_bounded()

        if decision.accepted and len(payload) > limits.max_line_bytes:
            raise AssertionError("oversized input was accepted")
        if decision.work_units > max(1, limits.max_line_bytes):
            raise AssertionError("reference parser exceeded bounded work accounting")

    return FuzzStats(
        seed=seed,
        cases=cases,
        accepted=accepted,
        rejected=rejected,
        max_work_units=max_work,
        resource_rejections=resource_rejections,
    )
