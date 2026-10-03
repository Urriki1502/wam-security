"""Fail-closed dependency health and restart-budget reference model."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum


class Health(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    FAILED = "failed"


@dataclass(frozen=True)
class RuntimeHealth:
    redis: Health = Health.HEALTHY
    daemon_rpc: Health = Health.HEALTHY
    wallet: Health = Health.HEALTHY
    durable_journal: Health = Health.HEALTHY


@dataclass(frozen=True)
class RuntimeDecision:
    allow_read_only: bool
    allow_mining_ingress: bool
    allow_money_movement: bool
    reason: str


def evaluate_runtime(health: RuntimeHealth) -> RuntimeDecision:
    """Keep observability available while money paths fail closed."""
    money_states = (
        health.redis,
        health.daemon_rpc,
        health.wallet,
        health.durable_journal,
    )
    allow_money = all(state is Health.HEALTHY for state in money_states)

    # Mining ingress depends on durable share/accounting state. A degraded RPC
    # can be survivable for reads, but unknown/failed Redis is not.
    allow_mining = health.redis in {Health.HEALTHY, Health.DEGRADED}

    if allow_money:
        reason = "healthy"
    else:
        bad = [
            name
            for name, state in (
                ("redis", health.redis),
                ("daemon-rpc", health.daemon_rpc),
                ("wallet", health.wallet),
                ("journal", health.durable_journal),
            )
            if state is not Health.HEALTHY
        ]
        reason = "money-paused:" + ",".join(bad)

    return RuntimeDecision(
        allow_read_only=True,
        allow_mining_ingress=allow_mining,
        allow_money_movement=allow_money,
        reason=reason,
    )


@dataclass
class RestartBudget:
    max_restarts: int = 5
    window_ms: int = 60_000
    events: deque[int] = field(default_factory=deque)

    def allow_restart(self, now_ms: int) -> bool:
        cutoff = now_ms - self.window_ms
        while self.events and self.events[0] <= cutoff:
            self.events.popleft()
        if len(self.events) >= self.max_restarts:
            return False
        self.events.append(now_ms)
        return True

    def assert_bounded(self) -> None:
        if len(self.events) > self.max_restarts:
            raise AssertionError("restart loop escaped configured budget")
