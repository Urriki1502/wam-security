"""Durable exactly-once payout reference model for WAM Security V4.

The model is intentionally stricter than the current WAM pool implementation:
a payout becomes one durable intent, receives one signed transaction identity
before any broadcast attempt, and that exact raw transaction is the only object
that may ever be retried for the intent.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import json
from typing import Mapping

COIN = 100_000_000


class IntentState(str, Enum):
    RESERVED = "reserved"
    SIGNED = "signed"
    BROADCAST_UNKNOWN = "broadcast-unknown"
    BROADCAST_SEEN = "broadcast-seen"


@dataclass(frozen=True)
class PaymentPolicy:
    payout_wallet: str
    max_recipients: int = 200
    max_batch: int = 100_000 * COIN
    max_recipient: int = 100_000 * COIN
    max_fee: int = COIN // 10
    max_daily_spend: int = 250_000 * COIN

    def __post_init__(self) -> None:
        if not self.payout_wallet:
            raise ValueError("a dedicated named payout wallet is required")
        for name in ("max_recipients", "max_batch", "max_recipient", "max_fee", "max_daily_spend"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass
class PaymentIntent:
    intent_id: str
    sequence: int
    wallet: str
    payouts: dict[str, int]
    total: int
    state: IntentState = IntentState.RESERVED
    raw_tx: str | None = None
    txid: str | None = None
    fee: int = 0
    broadcast_attempted: bool = False

    def assert_identity(self) -> None:
        if self.state is not IntentState.RESERVED and (not self.raw_tx or not self.txid):
            raise AssertionError("money-moving state lost raw transaction identity")


class ChainSimulator:
    """Minimal chain/mempool observer used by deterministic fault testing."""

    def __init__(self) -> None:
        self.seen_txids: set[str] = set()
        self.intent_txids: dict[str, set[str]] = {}

    def broadcast(self, intent: PaymentIntent, outcome: str) -> bool | None:
        if not intent.raw_tx or not intent.txid:
            raise ValueError("transaction must be signed before broadcast")
        if outcome not in {"accept-ack", "accept-timeout", "drop-timeout", "reject"}:
            raise ValueError(f"unknown broadcast outcome {outcome}")

        if outcome in {"accept-ack", "accept-timeout"}:
            self.seen_txids.add(intent.txid)
            self.intent_txids.setdefault(intent.intent_id, set()).add(intent.txid)

        if outcome == "accept-ack":
            return True
        if outcome in {"accept-timeout", "drop-timeout"}:
            return None
        return False

    def seen(self, txid: str) -> bool:
        return txid in self.seen_txids

    def assert_at_most_once(self, intent_id: str) -> None:
        identities = self.intent_txids.get(intent_id, set())
        if len(identities) > 1:
            raise AssertionError(f"intent {intent_id} produced multiple economic transaction identities")


class MoneyLedger:
    """Durable accounting model with one active payout intent."""

    def __init__(
        self,
        balances: Mapping[str, int],
        *,
        policy: PaymentPolicy,
        paid: Mapping[str, int] | None = None,
        sequence: int = 0,
        daily_spent: int = 0,
    ) -> None:
        self.policy = policy
        self.balances = {str(k): int(v) for k, v in balances.items()}
        self.paid = {str(k): int(v) for k, v in (paid or {}).items()}
        self.sequence = int(sequence)
        self.daily_spent = int(daily_spent)
        self.active: PaymentIntent | None = None
        self.completed_txids: set[str] = set()
        self.total_credited = sum(self.balances.values()) + sum(self.paid.values())
        self._assert_nonnegative()

    def _assert_nonnegative(self) -> None:
        if any(v < 0 for v in self.balances.values()):
            raise AssertionError("negative owed balance")
        if any(v < 0 for v in self.paid.values()):
            raise AssertionError("negative paid balance")

    @staticmethod
    def _canonical_payouts(payouts: Mapping[str, int]) -> dict[str, int]:
        normal = {str(k): int(v) for k, v in payouts.items()}
        if not normal or any(not k or v <= 0 for k, v in normal.items()):
            raise ValueError("payouts require non-empty addresses and positive base-unit amounts")
        return dict(sorted(normal.items()))

    def credit(self, address: str, amount: int) -> None:
        if amount <= 0:
            raise ValueError("credit must be positive")
        self.balances[address] = self.balances.get(address, 0) + amount
        self.total_credited += amount

    def reserve(self, payouts: Mapping[str, int], *, wallet: str) -> PaymentIntent:
        if self.active is not None:
            raise RuntimeError("an unresolved payout intent already exists")
        if wallet != self.policy.payout_wallet:
            raise PermissionError("money path attempted through a non-payout wallet")

        normal = self._canonical_payouts(payouts)
        total = sum(normal.values())
        if len(normal) > self.policy.max_recipients:
            raise ValueError("recipient limit exceeded")
        if total > self.policy.max_batch:
            raise ValueError("batch value limit exceeded")
        if total + self.daily_spent > self.policy.max_daily_spend:
            raise ValueError("daily spend limit exceeded")
        if any(v > self.policy.max_recipient for v in normal.values()):
            raise ValueError("per-recipient value limit exceeded")
        for address, amount in normal.items():
            if amount > self.balances.get(address, 0):
                raise ValueError(f"payout exceeds owed balance for {address}")

        material = json.dumps(
            {"sequence": self.sequence, "wallet": wallet, "payouts": normal},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        intent_id = sha256(material).hexdigest()
        intent = PaymentIntent(
            intent_id=intent_id,
            sequence=self.sequence,
            wallet=wallet,
            payouts=normal,
            total=total,
        )
        self.sequence += 1
        self.active = intent
        return intent

    def sign(self, *, fee: int = 0) -> str:
        intent = self._need_active()
        if fee < 0 or fee > self.policy.max_fee:
            raise ValueError("transaction fee exceeds policy")
        if intent.raw_tx is not None:
            intent.assert_identity()
            return intent.txid or ""

        envelope = json.dumps(
            {
                "intent_id": intent.intent_id,
                "wallet": intent.wallet,
                "payouts": intent.payouts,
                "fee": fee,
                "replaceable": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        intent.raw_tx = envelope.hex()
        intent.txid = sha256(envelope).hexdigest()
        intent.fee = fee
        intent.state = IntentState.SIGNED
        return intent.txid

    def broadcast(self, chain: ChainSimulator, outcome: str) -> bool | None:
        intent = self._need_active()
        if intent.state not in {IntentState.SIGNED, IntentState.BROADCAST_UNKNOWN}:
            raise RuntimeError(f"cannot broadcast in state {intent.state}")
        intent.assert_identity()
        original = (intent.raw_tx, intent.txid)
        intent.broadcast_attempted = True
        ack = chain.broadcast(intent, outcome)
        if (intent.raw_tx, intent.txid) != original:
            raise AssertionError("retry changed transaction identity")

        if ack is True:
            intent.state = IntentState.BROADCAST_SEEN
        elif ack is None:
            intent.state = IntentState.BROADCAST_UNKNOWN
        # A rejection leaves the same signed identity available for diagnosis/retry.
        else:
            intent.state = IntentState.SIGNED
        return ack

    def reconcile(self, chain: ChainSimulator) -> bool:
        intent = self._need_active()
        intent.assert_identity()
        if intent.txid and chain.seen(intent.txid):
            intent.state = IntentState.BROADCAST_SEEN
            return True
        return False

    def commit_atomic(self) -> str:
        """Apply accounting as one indivisible logical transaction."""
        intent = self._need_active()
        if intent.state is not IntentState.BROADCAST_SEEN:
            raise RuntimeError("cannot clear balances before transaction identity is observed")
        intent.assert_identity()

        balances = dict(self.balances)
        paid = dict(self.paid)
        for address, amount in intent.payouts.items():
            if balances.get(address, 0) < amount:
                raise AssertionError(f"owed balance changed below reserved amount for {address}")
            balances[address] -= amount
            paid[address] = paid.get(address, 0) + amount

        # Publish the copied state only after all preconditions succeed.
        self.balances = balances
        self.paid = paid
        self.daily_spent += intent.total
        txid = intent.txid or ""
        self.completed_txids.add(txid)
        self.active = None
        self.assert_conservation()
        return txid

    def cancel_before_broadcast(self) -> None:
        intent = self._need_active()
        if intent.broadcast_attempted:
            raise RuntimeError("an attempted transaction must be reconciled, never silently cancelled")
        self.active = None

    def snapshot(self) -> str:
        payload = {
            "policy": asdict(self.policy),
            "balances": self.balances,
            "paid": self.paid,
            "sequence": self.sequence,
            "daily_spent": self.daily_spent,
            "active": None if self.active is None else {
                **asdict(self.active),
                "state": self.active.state.value,
            },
            "completed_txids": sorted(self.completed_txids),
            "total_credited": self.total_credited,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def restore(cls, raw: str) -> "MoneyLedger":
        p = json.loads(raw)
        ledger = cls(
            p["balances"],
            policy=PaymentPolicy(**p["policy"]),
            paid=p["paid"],
            sequence=p["sequence"],
            daily_spent=p["daily_spent"],
        )
        ledger.total_credited = p["total_credited"]
        ledger.completed_txids = set(p["completed_txids"])
        if p["active"] is not None:
            a = dict(p["active"])
            a["state"] = IntentState(a["state"])
            ledger.active = PaymentIntent(**a)
        ledger.assert_conservation()
        return ledger

    def assert_conservation(self) -> None:
        self._assert_nonnegative()
        accounted = sum(self.balances.values()) + sum(self.paid.values())
        if accounted != self.total_credited:
            raise AssertionError(
                f"accounting conservation failed: owed+paid={accounted}, credited={self.total_credited}"
            )

    def _need_active(self) -> PaymentIntent:
        if self.active is None:
            raise RuntimeError("no active payout intent")
        return self.active
