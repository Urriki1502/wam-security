"""Pure validation primitives for the WAM treasury split-role reference path."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib

COIN = 100_000_000
WAM_WIF_VERSION = 190
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DEFAULT_FEERATE_ATOMS_PER_KVB = 20_000
DUST_ATOMS = 546
COINBASE_MATURITY = 100


def coins_to_atoms(value) -> int:
    try:
        amount = Decimal(str(value)) * COIN
    except (InvalidOperation, ValueError):
        raise ValueError("AMOUNT_FORMAT") from None
    if not amount.is_finite() or amount != amount.to_integral_value() or amount < 0:
        raise ValueError("AMOUNT_FORMAT")
    return int(amount)


def atoms_to_coins(atoms: int) -> str:
    if type(atoms) is not int or atoms < 0:
        raise ValueError("AMOUNT_ATOMS")
    return f"{Decimal(atoms) / COIN:.8f}"


def decode_base58check(text: str) -> bytes:
    if not isinstance(text, str) or not text or any(c not in B58 for c in text):
        raise ValueError("WIF_BASE58")
    n = 0
    for c in text:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5:
        raise ValueError("WIF_LENGTH")
    body, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("WIF_CHECKSUM")
    return body


def validate_wif(text: str) -> dict:
    body = decode_base58check(text)
    if body[0] != WAM_WIF_VERSION:
        raise ValueError("WIF_NETWORK")
    payload = body[1:]
    compressed = False
    if len(payload) == 33 and payload[-1] == 1:
        compressed = True
        payload = payload[:-1]
    if len(payload) != 32:
        raise ValueError("WIF_LENGTH")
    scalar = int.from_bytes(payload, "big")
    if not 1 <= scalar < SECP256K1_N:
        raise ValueError("WIF_SCALAR")
    return {"compressed": compressed, "version": WAM_WIF_VERSION}


def estimate_fee_atoms(
    input_count: int,
    output_count: int = 2,
    feerate_atoms_per_kvb: int = DEFAULT_FEERATE_ATOMS_PER_KVB,
) -> int:
    if type(input_count) is not int or input_count < 1 or output_count not in (1, 2):
        raise ValueError("FEE_SHAPE")
    if type(feerate_atoms_per_kvb) is not int or feerate_atoms_per_kvb < 1:
        raise ValueError("FEE_RATE")
    vbytes = input_count * 148 + output_count * 34 + 10
    return int(
        (Decimal(feerate_atoms_per_kvb) * vbytes / 1000).to_integral_value(
            rounding=ROUND_CEILING
        )
    )


def calculate_change(
    input_atoms: int,
    amount_atoms: int,
    input_count: int,
    feerate_atoms_per_kvb: int = DEFAULT_FEERATE_ATOMS_PER_KVB,
) -> tuple[int, int]:
    if any(type(x) is not int for x in (input_atoms, amount_atoms, input_count)):
        raise ValueError("AMOUNT_ATOMS")
    if input_atoms <= 0 or amount_atoms <= 0 or amount_atoms > input_atoms:
        raise ValueError("INSUFFICIENT_INPUTS")
    fee = estimate_fee_atoms(input_count, 2, feerate_atoms_per_kvb)
    change = input_atoms - amount_atoms - fee
    if change < 0:
        raise ValueError("INSUFFICIENT_INPUTS")
    if 0 < change < DUST_ATOMS:
        fee += change
        change = 0
    return fee, change


def outpoint(item: dict) -> tuple[str, int]:
    if not isinstance(item, dict):
        raise ValueError("INPUT_FORMAT")
    txid, vout = item.get("txid"), item.get("vout")
    if not isinstance(txid, str) or len(txid) != 64:
        raise ValueError("INPUT_FORMAT")
    try:
        bytes.fromhex(txid)
    except ValueError:
        raise ValueError("INPUT_FORMAT") from None
    if type(vout) is not int or not 0 <= vout < 2**32:
        raise ValueError("INPUT_FORMAT")
    return txid, vout


def mempool_spent_outpoints(transactions: list[dict]) -> set[tuple[str, int]]:
    if not isinstance(transactions, list):
        raise ValueError("MEMPOOL_STATE_UNKNOWN")
    spent: set[tuple[str, int]] = set()
    for tx in transactions:
        if not isinstance(tx, dict) or not isinstance(tx.get("vin"), list):
            raise ValueError("MEMPOOL_STATE_UNKNOWN")
        for vin in tx["vin"]:
            if "coinbase" in vin:
                continue
            point = outpoint(vin)
            if point in spent:
                raise ValueError("MEMPOOL_DUPLICATE_SPEND_VIEW")
            spent.add(point)
    return spent


def filter_spendable(
    utxos: list[dict],
    tip: int,
    mempool_transactions: list[dict],
) -> list[dict]:
    if type(tip) is not int or tip < 0 or not isinstance(utxos, list):
        raise ValueError("UTXO_STATE")
    spent = mempool_spent_outpoints(mempool_transactions)
    result = []
    seen = set()
    for item in utxos:
        point = outpoint(item)
        if point in seen:
            raise ValueError("DUPLICATE_UTXO")
        seen.add(point)
        height = item.get("height")
        if type(height) is not int or height < 1 or height > tip:
            raise ValueError("UTXO_STATE")
        coins_to_atoms(item.get("amount"))
        if not isinstance(item.get("scriptPubKey"), str):
            raise ValueError("UTXO_STATE")
        if tip - height + 1 > COINBASE_MATURITY and point not in spent:
            result.append(item)
    return sorted(result, key=lambda u: (u["height"], u["txid"], u["vout"]))


def validate_plan(plan: dict) -> tuple[tuple[str, int], ...]:
    required = {
        "network",
        "from",
        "to",
        "amount",
        "change",
        "fee",
        "inputs",
        "inputTotal",
        "unsignedHex",
        "prevtxs",
        "reason",
    }
    if not isinstance(plan, dict) or not required <= plan.keys():
        raise ValueError("PLAN_FORMAT")
    if (
        plan["network"] != "mainnet"
        or not isinstance(plan["unsignedHex"], str)
        or not plan["unsignedHex"]
    ):
        raise ValueError("PLAN_FORMAT")
    prevtxs = plan["prevtxs"]
    if (
        not isinstance(prevtxs, list)
        or type(plan["inputs"]) is not int
        or plan["inputs"] != len(prevtxs)
    ):
        raise ValueError("PLAN_INPUT_COUNT")
    points = tuple(outpoint(p) for p in prevtxs)
    if len(set(points)) != len(points):
        raise ValueError("PLAN_DUPLICATE_INPUT")
    total = 0
    for p in prevtxs:
        if not isinstance(p.get("scriptPubKey"), str) or not p["scriptPubKey"]:
            raise ValueError("PLAN_PREVOUT")
        total += coins_to_atoms(p.get("amount"))
    if coins_to_atoms(plan["inputTotal"]) != total:
        raise ValueError("PLAN_INPUT_TOTAL")
    amount = coins_to_atoms(plan["amount"])
    change = coins_to_atoms(plan["change"])
    fee = coins_to_atoms(plan["fee"])
    if amount <= 0 or fee <= 0 or total != amount + change + fee:
        raise ValueError("PLAN_VALUE_CONSERVATION")
    if (
        not isinstance(plan["to"], str)
        or not plan["to"]
        or not isinstance(plan["from"], str)
        or not plan["from"]
    ):
        raise ValueError("PLAN_ADDRESS")
    return points


def decoded_input_outpoints(decoded: dict) -> tuple[tuple[str, int], ...]:
    if not isinstance(decoded, dict) or not isinstance(decoded.get("vin"), list):
        raise ValueError("TRANSACTION_FORMAT")
    points = tuple(outpoint(v) for v in decoded["vin"])
    if len(set(points)) != len(points):
        raise ValueError("DUPLICATE_INPUT")
    return points
