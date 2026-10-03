"""Reference admission and resource-budget model for internet-facing services."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeLimits:
    max_connections: int = 5_000
    max_connections_per_ip: int = 128
    max_message_bytes: int = 16_384
    max_messages_per_10s: int = 240
    max_inflight_per_ip: int = 32


@dataclass
class AdmissionController:
    limits: RuntimeLimits = field(default_factory=RuntimeLimits)
    total_connections: int = 0
    by_ip: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    message_times: dict[str, deque[int]] = field(default_factory=lambda: defaultdict(deque))
    inflight: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def connect(self, ip: str) -> None:
        if self.total_connections >= self.limits.max_connections:
            raise BudgetExceeded("global-connection-limit")
        if self.by_ip[ip] >= self.limits.max_connections_per_ip:
            raise BudgetExceeded("per-ip-connection-limit")
        self.total_connections += 1
        self.by_ip[ip] += 1

    def disconnect(self, ip: str) -> None:
        if self.by_ip[ip] <= 0:
            return
        self.by_ip[ip] -= 1
        self.total_connections -= 1
        if self.by_ip[ip] == 0:
            self.by_ip.pop(ip, None)

    def record_message(self, ip: str, size: int, now_ms: int) -> None:
        if size < 0 or size > self.limits.max_message_bytes:
            raise BudgetExceeded("message-size-limit")
        q = self.message_times[ip]
        cutoff = now_ms - 10_000
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.limits.max_messages_per_10s:
            raise BudgetExceeded("message-rate-limit")
        q.append(now_ms)

    def begin_request(self, ip: str) -> None:
        if self.inflight[ip] >= self.limits.max_inflight_per_ip:
            raise BudgetExceeded("inflight-limit")
        self.inflight[ip] += 1

    def end_request(self, ip: str) -> None:
        if self.inflight[ip] <= 0:
            return
        self.inflight[ip] -= 1
        if self.inflight[ip] == 0:
            self.inflight.pop(ip, None)

    def assert_bounded(self) -> None:
        if self.total_connections < 0 or self.total_connections > self.limits.max_connections:
            raise AssertionError("global connection accounting escaped bounds")
        if any(v < 0 or v > self.limits.max_connections_per_ip for v in self.by_ip.values()):
            raise AssertionError("per-IP connection accounting escaped bounds")
        if any(v < 0 or v > self.limits.max_inflight_per_ip for v in self.inflight.values()):
            raise AssertionError("inflight accounting escaped bounds")
