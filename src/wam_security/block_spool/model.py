"""Executable reference model for WAM solved-block recovery.

The model is deliberately local and transport-free. It captures the invariants
needed by a future upstream patch without depending on Redis, a node or a pool.

The chosen design is a durable recovery entry plus an idempotent economic
transition. Raw block durability and accounting durability are two phases of
one state machine; a solved block is not considered settled until both the node
outcome and the pool accounting outcome are known.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


REQUIRED_SHARE_FIELDS = frozenset(
    {
        "height",
        "worker",
        "difficulty",
        "jobId",
        "distributableValue",
        "coinbaseValue",
        "devFeeAmount",
        "time",
    }
)

DUPLICATE_LIKE = frozenset(
    {"duplicate", "inconclusive", "duplicate-inconclusive"}
)


class RecoveryError(RuntimeError):
    pass


class DurableWriteError(RecoveryError):
    pass


class AccountingWriteError(RecoveryError):
    pass


class Phase(str, Enum):
    SPOOLED = "spooled"
    ACCEPTED_UNACCOUNTED = "accepted-unaccounted"
    ACCOUNTED = "accounted"
    LOST_RACE = "lost-race"
    REFUSED = "refused"


@dataclass(frozen=True)
class RecoveryContext:
    block_hash: str
    raw_hex: str
    share: dict[str, Any]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.block_hash, str)
            or len(self.block_hash) != 64
            or any(c not in "0123456789abcdef" for c in self.block_hash)
        ):
            raise ValueError("BLOCK_HASH")
        if (
            not isinstance(self.raw_hex, str)
            or not self.raw_hex
            or len(self.raw_hex) % 2
            or any(c not in "0123456789abcdef" for c in self.raw_hex)
        ):
            raise ValueError("BLOCK_HEX")
        if not isinstance(self.share, dict):
            raise ValueError("SHARE_CONTEXT")
        missing = REQUIRED_SHARE_FIELDS - self.share.keys()
        if missing:
            raise ValueError("SHARE_CONTEXT_MISSING:" + ",".join(sorted(missing)))
        if self.share.get("height") is None or self.share.get("worker") in (None, ""):
            raise ValueError("SHARE_CONTEXT")

    def record(self) -> dict[str, Any]:
        return {
            "blockHash": self.block_hash,
            "hex": self.raw_hex,
            "share": dict(self.share),
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "RecoveryContext":
        if not isinstance(record, dict) or set(record) != {"blockHash", "hex", "share"}:
            raise ValueError("RECOVERY_RECORD")
        return cls(record["blockHash"], record["hex"], dict(record["share"]))


@dataclass
class Entry:
    context: RecoveryContext
    phase: Phase = Phase.SPOOLED
    reason: str | None = None


@dataclass
class DurableStore:
    live: dict[str, Entry] = field(default_factory=dict)
    terminal: dict[str, Entry] = field(default_factory=dict)

    def spool(self, context: RecoveryContext, *, fail: bool = False) -> None:
        if fail:
            raise DurableWriteError("SPOOL_WRITE_FAILED")
        existing = self.live.get(context.block_hash) or self.terminal.get(context.block_hash)
        if existing is not None and existing.context != context:
            raise RecoveryError("BLOCK_HASH_CONTEXT_MISMATCH")
        if existing is None:
            self.live[context.block_hash] = Entry(context)

    def submit_ready(self, block_hash: str) -> bool:
        entry = self.live.get(block_hash)
        return entry is not None and entry.phase in {
            Phase.SPOOLED,
            Phase.ACCEPTED_UNACCOUNTED,
        }

    def mark_accepted(self, block_hash: str, *, fail: bool = False) -> None:
        if fail:
            raise DurableWriteError("ACCEPTED_STATE_WRITE_FAILED")
        entry = self._live(block_hash)
        if entry.phase is Phase.SPOOLED:
            entry.phase = Phase.ACCEPTED_UNACCOUNTED
        elif entry.phase is not Phase.ACCEPTED_UNACCOUNTED:
            raise RecoveryError("INVALID_ACCEPTED_TRANSITION")

    def settle(
        self,
        block_hash: str,
        phase: Phase,
        *,
        reason: str | None = None,
        fail: bool = False,
    ) -> None:
        if fail:
            raise DurableWriteError("SETTLE_WRITE_FAILED")
        if phase not in {Phase.ACCOUNTED, Phase.LOST_RACE, Phase.REFUSED}:
            raise RecoveryError("INVALID_TERMINAL_PHASE")
        entry = self._live(block_hash)
        entry.phase = phase
        entry.reason = reason
        self.terminal[block_hash] = entry
        del self.live[block_hash]

    def _live(self, block_hash: str) -> Entry:
        try:
            return self.live[block_hash]
        except KeyError:
            raise RecoveryError("RECOVERY_ENTRY_NOT_LIVE") from None


@dataclass
class AccountingLedger:
    """Models one atomic share+block accounting transition keyed by block hash."""

    accounted: set[str] = field(default_factory=set)
    winner_shares: dict[str, dict[str, Any]] = field(default_factory=dict)
    pending_blocks: dict[str, dict[str, Any]] = field(default_factory=dict)
    accounting_applications: int = 0

    def apply_once(
        self,
        context: RecoveryContext,
        *,
        fail_before_commit: bool = False,
        fail_after_commit: bool = False,
    ) -> bool:
        block_hash = context.block_hash
        if block_hash in self.accounted:
            return False

        share = dict(context.share)
        pending = {
            "height": share["height"],
            "blockHash": block_hash,
            "finder": share["worker"],
            "coinbaseValue": share["coinbaseValue"],
            "devFeeAmount": share["devFeeAmount"],
            "distributableValue": share["distributableValue"],
        }

        if fail_before_commit:
            raise AccountingWriteError("ACCOUNTING_COMMIT_FAILED")

        # This assignment group represents one durable atomic transaction in
        # the target design: the winning-share marker, pending-block record and
        # idempotency marker become visible together.
        self.winner_shares[block_hash] = share
        self.pending_blocks[block_hash] = pending
        self.accounted.add(block_hash)
        self.accounting_applications += 1

        if fail_after_commit:
            # Models a lost acknowledgement after the durable commit.
            raise AccountingWriteError("ACCOUNTING_ACK_LOST")
        return True


@dataclass
class RecoveryEngine:
    store: DurableStore
    ledger: AccountingLedger

    def prepare_candidate(
        self,
        context: RecoveryContext,
        *,
        fail_spool: bool = False,
    ) -> None:
        """Durability barrier: submission is not permitted before this succeeds."""
        self.store.spool(context, fail=fail_spool)

    def recover(
        self,
        block_hash: str,
        outcome: str,
        *,
        active_chain: bool | None = None,
        accounting_fail_before: bool = False,
        accounting_fail_after: bool = False,
        crash_after_accounting: bool = False,
    ) -> str:
        entry = self.store._live(block_hash)

        if outcome in {"rpc-error", "no-answer"}:
            return "RETRY_LATER"

        if outcome == "accepted":
            self.store.mark_accepted(block_hash)
            return self._account(
                entry,
                accounting_fail_before=accounting_fail_before,
                accounting_fail_after=accounting_fail_after,
                crash_after_accounting=crash_after_accounting,
            )

        if outcome in DUPLICATE_LIKE:
            # A duplicate-like submit result is not, by itself, proof that this
            # exact block is on the active chain. Querying the block by the
            # stored block hash is the disambiguation step.
            if active_chain is None:
                return "CHAIN_STATUS_REQUIRED"
            if not active_chain:
                self.store.settle(block_hash, Phase.LOST_RACE, reason=outcome)
                return "LOST_RACE"
            self.store.mark_accepted(block_hash)
            return self._account(
                entry,
                accounting_fail_before=accounting_fail_before,
                accounting_fail_after=accounting_fail_after,
                crash_after_accounting=crash_after_accounting,
            )

        if outcome == "refused":
            self.store.settle(block_hash, Phase.REFUSED, reason=outcome)
            return "REFUSED"

        raise RecoveryError("UNKNOWN_NODE_OUTCOME")

    def resume_accepted(
        self,
        block_hash: str,
        *,
        accounting_fail_before: bool = False,
        accounting_fail_after: bool = False,
        crash_after_accounting: bool = False,
    ) -> str:
        entry = self.store._live(block_hash)
        if entry.phase is not Phase.ACCEPTED_UNACCOUNTED:
            raise RecoveryError("NOT_ACCEPTED_UNACCOUNTED")
        return self._account(
            entry,
            accounting_fail_before=accounting_fail_before,
            accounting_fail_after=accounting_fail_after,
            crash_after_accounting=crash_after_accounting,
        )

    def _account(
        self,
        entry: Entry,
        *,
        accounting_fail_before: bool,
        accounting_fail_after: bool,
        crash_after_accounting: bool,
    ) -> str:
        context = entry.context
        try:
            applied = self.ledger.apply_once(
                context,
                fail_before_commit=accounting_fail_before,
                fail_after_commit=accounting_fail_after,
            )
        except AccountingWriteError:
            # If the durable commit happened but its acknowledgement was lost,
            # a retry is safe because apply_once is keyed by block hash.
            if context.block_hash in self.ledger.accounted:
                if crash_after_accounting:
                    return "CRASHED_AFTER_ACCOUNTING"
                self.store.settle(context.block_hash, Phase.ACCOUNTED)
                return "ACCOUNTED"
            raise

        if crash_after_accounting:
            return "CRASHED_AFTER_ACCOUNTING"

        self.store.settle(context.block_hash, Phase.ACCOUNTED)
        return "ACCOUNTED" if applied else "ALREADY_ACCOUNTED"
