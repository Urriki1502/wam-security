"""Offline WAM treasury signer reference role. It has no network/RPC client."""

from __future__ import annotations

from .common import decoded_input_outpoints, validate_plan, validate_wif


def preflight_plan(plan: dict, decoded_unsigned: dict) -> tuple[tuple[str, int], ...]:
    expected = validate_plan(plan)
    actual = decoded_input_outpoints(decoded_unsigned)
    if actual != expected:
        raise ValueError("UNSIGNED_INPUT_SET_MISMATCH")
    return expected


def sign_plan(plan: dict, decoded_unsigned: dict, key_supplier, signer) -> dict:
    """Validate all non-secret material, then obtain one WIF and invoke signer once."""
    input_set = preflight_plan(plan, decoded_unsigned)
    wif = key_supplier()
    validate_wif(wif)
    result = signer(plan["unsignedHex"], wif, plan["prevtxs"])
    if (
        not isinstance(result, dict)
        or not result.get("complete")
        or not isinstance(result.get("hex"), str)
    ):
        raise ValueError("SIGNING_INCOMPLETE")
    signed = {k: v for k, v in plan.items() if k != "prevtxs"}
    signed["inputSet"] = [{"txid": txid, "vout": vout} for txid, vout in input_set]
    signed["signedHex"] = result["hex"]
    return signed
