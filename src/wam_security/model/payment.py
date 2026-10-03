"""Reference model for an exactly-once payout state machine.

This is not a wallet implementation. It defines the safety properties a pool
payout implementation must preserve across crashes and ambiguous RPC outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Mapping


class PaymentState(str, Enum):
    OWED = "owed"
    PREPARED = "prepared"
    BROADCAST_UNKNOWN = "broadcast-unknown"
    BROADCAST_SEEN = "broadcast-seen"
    COMMITTED = "committed"


@dataclass
class PaymentIntent:
    payouts: dict[str, int]
    state: PaymentState = PaymentState.OWED
    raw_tx: str | None = None
    txid: str | None = None
    economic_payments: int = 0
    journal: list[str] = field(default_factory=list)

    def prepare(self) -> str:
        """Create one deterministic transaction identity for this intent."""
        if self.state is not PaymentState.OWED:
            if self.txid is None:
                raise AssertionError("prepared intent lost transaction identity")
            return self.txid
        canonical = json.dumps(self.payouts, sort_keys=True, separators=(",", ":"))
        self.raw_tx = canonical.encode().hex()
        self.txid = sha256(bytes.fromhex(self.raw_tx)).hexdigest()
        self.state = PaymentState.PREPARED
        self.journal.append(f"prepared:{self.txid}")
        return self.txid

    def broadcast_result(self, acknowledged: bool | None) -> None:
        """Record an RPC outcome without guessing what happened on timeout."""
        if self.state not in {PaymentState.PREPARED, PaymentState.BROADCAST_UNKNOWN}:
            raise ValueError(f"cannot broadcast in state {self.state}")
        if acknowledged is True:
            self.state = PaymentState.BROADCAST_SEEN
            self.economic_payments = max(self.economic_payments, 1)
            self.journal.append("broadcast:seen")
        elif acknowledged is None:
            self.state = PaymentState.BROADCAST_UNKNOWN
            self.journal.append("broadcast:unknown")
        else:
            self.journal.append("broadcast:not-seen")

    def reconcile(self, tx_seen: bool | None) -> None:
        """Resolve an ambiguous broadcast by transaction identity."""
        if self.state is not PaymentState.BROADCAST_UNKNOWN:
            raise ValueError("reconcile is only valid for ambiguous broadcasts")
        if tx_seen is True:
            self.state = PaymentState.BROADCAST_SEEN
            self.economic_payments = max(self.economic_payments, 1)
            self.journal.append("reconcile:seen")
        elif tx_seen is False:
            self.state = PaymentState.PREPARED
            self.journal.append("reconcile:not-seen")
        else:
            self.journal.append("reconcile:still-unknown")

    def commit(self) -> None:
        if self.state is not PaymentState.BROADCAST_SEEN:
            raise ValueError("cannot clear balances until transaction is known")
        self.state = PaymentState.COMMITTED
        self.journal.append("balances:committed")

    def assert_safe(self) -> None:
        if self.economic_payments > 1:
            raise AssertionError("same payout intent was economically paid more than once")
        if self.state is PaymentState.COMMITTED and self.economic_payments != 1:
            raise AssertionError("committed payout must correspond to exactly one payment")
        if self.state is not PaymentState.OWED and (self.raw_tx is None or self.txid is None):
            raise AssertionError("non-owed state must retain deterministic transaction identity")


def new_intent(payouts: Mapping[str, int]) -> PaymentIntent:
    if not payouts or any(v <= 0 for v in payouts.values()):
        raise ValueError("payouts must contain positive amounts")
    return PaymentIntent(dict(payouts))
