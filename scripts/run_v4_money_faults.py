#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random

from wam_security.money.model import ChainSimulator, MoneyLedger, PaymentPolicy

def restart(ledger: MoneyLedger) -> MoneyLedger:
    return MoneyLedger.restore(ledger.snapshot())

def run_case(rng: random.Random, case_id: int) -> int:
    names = [f"miner-{case_id}-{i}" for i in range(rng.randint(1, 5))]
    initial = {name: rng.randint(2_000, 50_000) for name in names}
    payouts = {name: rng.randint(1, initial[name]) for name in names}

    policy = PaymentPolicy(
        payout_wallet="pool-v4",
        max_recipients=10,
        max_batch=1_000_000,
        max_recipient=1_000_000,
        max_fee=10_000,
        max_daily_spend=2_000_000,
    )
    ledger = MoneyLedger(initial, policy=policy)
    chain = ChainSimulator()

    intent = ledger.reserve(payouts, wallet="pool-v4")
    if rng.choice([True, False]):
        ledger = restart(ledger)

    txid = ledger.sign(fee=rng.randint(0, 100))
    raw = ledger.active.raw_tx
    if rng.choice([True, False]):
        ledger = restart(ledger)
    assert ledger.active.txid == txid and ledger.active.raw_tx == raw

    credits = {name: 0 for name in names}
    if rng.random() < 0.35:
        who = rng.choice(names)
        amount = rng.randint(1, 2_000)
        ledger.credit(who, amount)
        credits[who] += amount

    first = rng.choice(["accept-ack", "accept-timeout", "drop-timeout", "reject"])
    ledger.broadcast(chain, first)
    if rng.choice([True, False]):
        ledger = restart(ledger)

    for attempt in range(6):
        if ledger.reconcile(chain):
            break
        if ledger.active.txid != txid or ledger.active.raw_tx != raw:
            raise AssertionError("recovery changed transaction identity")
        outcome = "accept-ack" if attempt == 5 else rng.choice(
            ["accept-ack", "accept-timeout", "drop-timeout", "reject"]
        )
        ledger.broadcast(chain, outcome)
        if rng.random() < 0.5:
            ledger = restart(ledger)
    else:
        raise AssertionError("fault case did not converge")

    if not ledger.reconcile(chain):
        raise AssertionError("accepted transaction could not be reconciled")

    if rng.choice([True, False]):
        ledger = restart(ledger)

    committed = ledger.commit_atomic()
    if committed != txid:
        raise AssertionError("commit changed txid")

    if rng.choice([True, False]):
        ledger = restart(ledger)

    chain.assert_at_most_once(intent.intent_id)
    if ledger.active is not None:
        raise AssertionError("committed intent remained active")

    for name in names:
        expected_balance = initial[name] + credits[name] - payouts[name]
        if ledger.balances[name] != expected_balance:
            raise AssertionError(
                f"balance mismatch {name}: {ledger.balances[name]} != {expected_balance}"
            )
        if ledger.paid.get(name, 0) != payouts[name]:
            raise AssertionError(f"paid mismatch for {name}")

    ledger.assert_conservation()
    return 1

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=lambda x: int(x, 0), default=0x57414D)
    p.add_argument("--cases", type=int, default=5000)
    args = p.parse_args()
    rng = random.Random(args.seed)
    completed = sum(run_case(rng, i) for i in range(args.cases))
    print(f"V4 exactly-once crash/restart matrix: PASS ({completed} cases, seed={hex(args.seed)})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
