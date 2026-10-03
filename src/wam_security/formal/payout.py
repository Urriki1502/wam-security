"""Payout state machine used for V6 formal/exhaustive assurance."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable


@dataclass(frozen=True)
class PayoutState:
    phase: str = "idle"
    identity: int = 0
    identities_created: int = 0
    seen: bool = False
    commits: int = 0
    attempted: bool = False


PHASES = {"idle", "reserved", "signed", "unknown", "seen", "committed"}


def initial() -> PayoutState:
    return PayoutState()


def successors(state: PayoutState) -> Iterable[tuple[str, PayoutState]]:
    if state.phase == "idle":
        yield "reserve", replace(state, phase="reserved")
        return

    if state.phase == "reserved":
        yield "sign", replace(
            state,
            phase="signed",
            identity=1,
            identities_created=1,
        )
        yield "crash", state
        return

    if state.phase in {"signed", "unknown"}:
        yield "broadcast-ack", replace(
            state, phase="seen", seen=True, attempted=True
        )
        yield "broadcast-timeout-accepted", replace(
            state, phase="unknown", seen=True, attempted=True
        )
        yield "broadcast-timeout-dropped", replace(
            state, phase="unknown", attempted=True
        )
        yield "crash", state

    if state.phase == "unknown":
        if state.seen:
            yield "reconcile-seen", replace(state, phase="seen")
        else:
            # Retry preserves the exact already-created transaction identity.
            yield "retry-same", state

    if state.phase == "seen":
        yield "commit", replace(state, phase="committed", commits=state.commits + 1)
        yield "crash", state

    if state.phase == "committed":
        yield "stable", state


def invariants() -> dict[str, callable]:
    return {
        "TypeOK": lambda s: (
            s.phase in PHASES
            and s.identity in {0, 1}
            and s.identities_created >= 0
            and s.commits >= 0
        ),
        "AtMostOneIdentity": lambda s: s.identities_created <= 1,
        "AtMostOneCommit": lambda s: s.commits <= 1,
        "MoneyStateHasIdentity": lambda s: (
            s.phase in {"idle", "reserved"}
            or (s.identity == 1 and s.identities_created == 1)
        ),
        "UnknownRetainsIdentity": lambda s: (
            s.phase != "unknown" or (s.identity == 1 and s.identities_created == 1)
        ),
        "CommitOnlyAfterSeen": lambda s: (
            s.commits == 0 or (s.phase == "committed" and s.seen)
        ),
        "AttemptNeverForgetsIdentity": lambda s: (
            not s.attempted or s.identity == 1
        ),
    }


def mutant_commit_unknown(state: PayoutState) -> Iterable[tuple[str, PayoutState]]:
    yield from successors(state)
    if state.phase == "unknown":
        yield "MUTANT-commit-unknown", replace(
            state, phase="committed", commits=state.commits + 1
        )


def mutant_second_identity(state: PayoutState) -> Iterable[tuple[str, PayoutState]]:
    yield from successors(state)
    if state.phase == "unknown":
        yield "MUTANT-new-identity-on-retry", replace(
            state,
            phase="signed",
            identity=1,
            identities_created=state.identities_created + 1,
        )
