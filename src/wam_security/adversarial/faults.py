"""Crash/restart model for exactly-once payout semantics.

The model deliberately represents an RPC timeout as *unknown*. Recovery asks
about the already-persisted transaction identity and may rebroadcast only the
same raw transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import json


class SimulatedCrash(RuntimeError):
    pass


class CrashPoint(str, Enum):
    AFTER_CONSTRUCT = "after-construct"
    AFTER_PERSIST = "after-persist"
    AFTER_NETWORK_ACCEPT = "after-network-accept"
    AFTER_RPC_RESULT = "after-rpc-result"
    BEFORE_COMMIT = "before-commit"
    AFTER_COMMIT = "after-commit"


class RpcOutcome(str, Enum):
    ACK = "ack"
    TIMEOUT_BEFORE_ACCEPT = "timeout-before-accept"
    TIMEOUT_AFTER_ACCEPT = "timeout-after-accept"


@dataclass
class DurablePayout:
    payouts: dict[str, int]
    raw_tx: str | None = None
    txid: str | None = None
    status: str = "owed"
    committed: bool = False
    committed_count: int = 0
    journal: list[str] = field(default_factory=list)


@dataclass
class NetworkTruth:
    accepted_txids: set[str] = field(default_factory=set)


def _build_tx(payouts: dict[str, int]) -> tuple[str, str]:
    canonical = json.dumps(payouts, sort_keys=True, separators=(",", ":")).encode()
    raw_tx = canonical.hex()
    txid = sha256(canonical).hexdigest()
    return raw_tx, txid


def _crash_if(point: CrashPoint | None, expected: CrashPoint) -> None:
    if point is expected:
        raise SimulatedCrash(expected.value)


class ExactlyOncePayoutRuntime:
    def __init__(self, durable: DurablePayout, network: NetworkTruth):
        self.durable = durable
        self.network = network

    def execute(self, outcome: RpcOutcome, crash_at: CrashPoint | None = None) -> None:
        raw_tx, txid = _build_tx(self.durable.payouts)
        _crash_if(crash_at, CrashPoint.AFTER_CONSTRUCT)

        if self.durable.txid is None:
            self.durable.raw_tx = raw_tx
            self.durable.txid = txid
            self.durable.status = "prepared"
            self.durable.journal.append(f"persist:{txid}")
        elif self.durable.txid != txid or self.durable.raw_tx != raw_tx:
            raise AssertionError("retry changed transaction identity")
        _crash_if(crash_at, CrashPoint.AFTER_PERSIST)

        if self.durable.status in {"prepared", "unknown"}:
            if outcome in {RpcOutcome.ACK, RpcOutcome.TIMEOUT_AFTER_ACCEPT}:
                self.network.accepted_txids.add(txid)
                _crash_if(crash_at, CrashPoint.AFTER_NETWORK_ACCEPT)

            if outcome is RpcOutcome.ACK:
                self.durable.status = "seen"
            else:
                self.durable.status = "unknown"
            self.durable.journal.append(f"rpc:{outcome.value}")
        _crash_if(crash_at, CrashPoint.AFTER_RPC_RESULT)

        if self.durable.status == "unknown":
            self.reconcile()
        if self.durable.status != "seen":
            raise AssertionError(f"unexpected payout status {self.durable.status}")

        _crash_if(crash_at, CrashPoint.BEFORE_COMMIT)
        self._commit()
        _crash_if(crash_at, CrashPoint.AFTER_COMMIT)

    def reconcile(self) -> None:
        if not self.durable.txid or not self.durable.raw_tx:
            raise AssertionError("cannot reconcile without persisted transaction identity")
        if self.durable.txid in self.network.accepted_txids:
            self.durable.status = "seen"
            self.durable.journal.append("reconcile:seen")
            return

        self.network.accepted_txids.add(self.durable.txid)
        self.durable.status = "seen"
        self.durable.journal.append("reconcile:rebroadcast-same-tx")

    def recover_and_complete(self) -> None:
        if self.durable.committed:
            self.assert_safe()
            return
        if self.durable.txid is None:
            self.execute(RpcOutcome.ACK)
            return
        if self.durable.status == "unknown":
            self.reconcile()
        elif self.durable.status == "prepared":
            self.network.accepted_txids.add(self.durable.txid)
            self.durable.status = "seen"
            self.durable.journal.append("recovery:broadcast-same-tx")
        if self.durable.status == "seen":
            self._commit()
        self.assert_safe()

    def _commit(self) -> None:
        if self.durable.committed:
            return
        if self.durable.status != "seen":
            raise AssertionError("balances cannot commit before transaction is known")
        self.durable.committed = True
        self.durable.committed_count += 1
        self.durable.status = "committed"
        self.durable.journal.append("commit")

    def assert_safe(self) -> None:
        if self.durable.committed_count > 1:
            raise AssertionError("payout balance committed more than once")
        if self.durable.txid and len(self.network.accepted_txids) > 1:
            raise AssertionError("one logical payout created multiple transaction identities")
        if self.durable.committed and self.durable.txid not in self.network.accepted_txids:
            raise AssertionError("committed payout is not known to network truth")


def exercise_crash_matrix() -> int:
    scenarios = 0
    for outcome in RpcOutcome:
        for point in list(CrashPoint) + [None]:
            durable = DurablePayout({"wam-test-a": 100, "wam-test-b": 200})
            network = NetworkTruth()
            runtime = ExactlyOncePayoutRuntime(durable, network)
            try:
                runtime.execute(outcome, point)
            except SimulatedCrash:
                runtime = ExactlyOncePayoutRuntime(durable, network)
                runtime.recover_and_complete()
            runtime.assert_safe()
            if not durable.committed:
                raise AssertionError(f"scenario did not settle: {outcome}/{point}")
            scenarios += 1
    return scenarios
