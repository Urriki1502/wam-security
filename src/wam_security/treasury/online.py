"""Online WAM treasury builder/broadcaster reference role. Contains no signing capability."""

from __future__ import annotations

from .common import coins_to_atoms, decoded_input_outpoints, outpoint, validate_plan


def collect_mempool_transactions(rpc) -> list[dict]:
    txids = rpc.call("getrawmempool")
    if not isinstance(txids, list) or len(set(txids)) != len(txids):
        raise ValueError("MEMPOOL_STATE_UNKNOWN")
    transactions = []
    for txid in txids:
        try:
            tx = rpc.call("getrawtransaction", [txid, True])
        except Exception as exc:
            raise ValueError("MEMPOOL_STATE_UNKNOWN") from exc
        if (
            not isinstance(tx, dict)
            or tx.get("txid") not in (None, txid)
            or not isinstance(tx.get("vin"), list)
        ):
            raise ValueError("MEMPOOL_STATE_UNKNOWN")
        transactions.append(tx)
    return transactions


def verify_broadcast_state(signed: dict, decoded: dict, rpc) -> dict:
    expected = (
        validate_plan(signed | {"prevtxs": signed.get("prevtxs", [])})
        if "prevtxs" in signed
        else None
    )
    if expected is None:
        # Signed transport may omit prevtxs for compactness, but must preserve an exact inputSet.
        raw_points = signed.get("inputSet")
        if not isinstance(raw_points, list):
            raise ValueError("SIGNED_INPUT_SET_MISSING")
        expected = tuple(outpoint(p) for p in raw_points)
        if len(set(expected)) != len(expected) or len(expected) != signed.get("inputs"):
            raise ValueError("SIGNED_INPUT_SET")

    actual = decoded_input_outpoints(decoded)
    if actual != expected:
        raise ValueError("SIGNED_INPUT_SET_MISMATCH")

    paid = {}
    vouts = decoded.get("vout")
    if not isinstance(vouts, list):
        raise ValueError("TRANSACTION_FORMAT")
    for output in vouts:
        if not isinstance(output, dict) or not isinstance(output.get("scriptPubKey"), dict):
            raise ValueError("TRANSACTION_FORMAT")
        address = output["scriptPubKey"].get("address")
        if address:
            paid[address] = paid.get(address, 0) + coins_to_atoms(output.get("value"))

    amount = coins_to_atoms(signed["amount"])
    change = coins_to_atoms(signed["change"])
    fee = coins_to_atoms(signed["fee"])
    if paid.get(signed["to"]) != amount:
        raise ValueError("DESTINATION_MISMATCH")
    if change and paid.get(signed["from"]) != change:
        raise ValueError("CHANGE_MISMATCH")
    if any(addr not in (signed["to"], signed["from"]) for addr in paid):
        raise ValueError("UNEXPECTED_OUTPUT")

    total_out = sum(paid.values())
    input_total = coins_to_atoms(signed["inputTotal"])
    if input_total - total_out != fee:
        raise ValueError("FEE_MISMATCH")

    observed_total = 0
    for txid, vout in actual:
        state = rpc.call("gettxout", [txid, vout, True])
        if not isinstance(state, dict):
            raise ValueError("STALE_OR_SPENT_UTXO")
        observed_total += coins_to_atoms(state.get("value"))
    if observed_total != input_total:
        raise ValueError("UTXO_VALUE_CHANGED")
    return {"inputs": len(actual), "fee_atoms": fee, "input_atoms": input_total}
