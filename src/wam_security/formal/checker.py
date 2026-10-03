"""Small deterministic explicit-state model checker used beside TLA+/TLC.

The Python checker is intentionally independent from TLC. It gives CI a fast,
auditable implementation and mutation sensitivity tests; TLC then checks the
same safety design from the TLA+ specification.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, asdict, is_dataclass
from hashlib import sha256
import json
from typing import Callable, Generic, Iterable, TypeVar

S = TypeVar("S")


@dataclass(frozen=True)
class Violation(Generic[S]):
    invariant: str
    state: S
    path: tuple[str, ...]


@dataclass(frozen=True)
class CheckResult:
    model: str
    states: int
    transitions: int
    max_depth: int
    digest: str


class ModelViolation(AssertionError):
    def __init__(self, violation: Violation):
        super().__init__(
            f"{violation.invariant} violated after {' -> '.join(violation.path) or '<init>'}: "
            f"{violation.state!r}"
        )
        self.violation = violation


def _canonical(state: object) -> bytes:
    value = asdict(state) if is_dataclass(state) else state
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def explore(
    *,
    model: str,
    initial: S,
    successors: Callable[[S], Iterable[tuple[str, S]]],
    invariants: dict[str, Callable[[S], bool]],
    max_states: int = 100_000,
) -> CheckResult:
    queue: deque[tuple[S, tuple[str, ...]]] = deque([(initial, ())])
    seen: dict[S, tuple[str, ...]] = {initial: ()}
    transitions = 0
    max_depth = 0

    while queue:
        state, path = queue.popleft()
        max_depth = max(max_depth, len(path))

        for name, invariant in invariants.items():
            if not invariant(state):
                raise ModelViolation(Violation(name, state, path))

        for action, nxt in successors(state):
            transitions += 1
            new_path = path + (action,)
            if nxt not in seen:
                if len(seen) >= max_states:
                    raise RuntimeError(f"{model}: state limit {max_states} exceeded")
                seen[nxt] = new_path
                queue.append((nxt, new_path))

    digest_input = b"\n".join(sorted(_canonical(s) for s in seen))
    return CheckResult(
        model=model,
        states=len(seen),
        transitions=transitions,
        max_depth=max_depth,
        digest=sha256(digest_input).hexdigest(),
    )


def expect_counterexample(
    *,
    model: str,
    initial: S,
    successors: Callable[[S], Iterable[tuple[str, S]]],
    invariants: dict[str, Callable[[S], bool]],
    expected_invariant: str,
) -> Violation[S]:
    try:
        explore(
            model=model,
            initial=initial,
            successors=successors,
            invariants=invariants,
        )
    except ModelViolation as exc:
        if exc.violation.invariant != expected_invariant:
            raise AssertionError(
                f"{model}: expected {expected_invariant}, got {exc.violation.invariant}"
            ) from exc
        return exc.violation
    raise AssertionError(f"{model}: mutant did not produce a counterexample")
