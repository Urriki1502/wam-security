# WAM treasury spend hardening candidate

## Scope and provenance

This directory carries a review-ready upstream-shaped candidate for:

- upstream repository: `wamcoin-core-dev/wam-coin`
- locked baseline commit: `bd71b0bd645286a3867dad6b2bfefd911ec8a5b6`
- baseline file: `scripts/treasury_spend.py`
- candidate: `reference/upstream_patch/scripts/treasury_spend_hardened.py`

Upstream production is not modified by this repository. Maintainer review is required
before any part of the candidate is adopted in WAM Core.

The candidate intentionally preserves the upstream operator workflow and naming:
`plan` runs online, `sign` runs on the air-gapped signer, and `broadcast` returns
online. It keeps the treasury address, RPC transport, plan JSON shape, fee policy,
file hand-off and confirmation prompts wherever they remain safe.

## Original -> gap -> hardened behavior -> regression proof

| Upstream baseline behavior | Identified boundary | Hardened candidate behavior | Direct regression |
| --- | --- | --- | --- |
| `scantxoutset` results are filtered for maturity and mempool spends | a failed `getrawtransaction` is caught and silently `continue`s, making spend-state incomplete | any unknown/malformed mempool state aborts planning; duplicate mempool spend views also abort | `test_unknown_mempool_transaction_state_fails_closed`, `test_mempool_spent_utxo_is_excluded` |
| scanned UTXOs are consumed in height order | duplicate/inconsistent scan entries are not explicitly rejected | exact outpoints are validated and duplicates fail closed before selection | `test_duplicate_scanned_input_rejected` |
| amount/fee/change use binary floating point and `round(..., 8)` | security invariants should not depend on binary floating-point equality | values are converted to integer atomic units through `Decimal`; fee is 20,000 atoms/kvB with ceiling arithmetic | `test_fee_calculation_matches_upstream_policy_exactly`, `test_change_calculation_is_exact`, `test_normal_plan_creation_uses_exact_fee_and_change` |
| WIF helper proves Base58Check checksum only | a checksummed key can still be wrong network, wrong payload shape or invalid scalar | require Base58Check, WAM mainnet version `190`, valid 32-byte secret / `0x01` compressed marker, and `1 <= scalar < n` | `test_bad_base58check_checksum_rejected`, `test_wrong_wif_version_rejected`, `test_invalid_compressed_marker_rejected`, `test_zero_private_scalar_rejected`, `test_out_of_range_private_scalar_rejected` |
| operator confirms destination, then key is requested and signing is attempted | unsigned transaction itself is not decoded and matched against the plan before key use | decode unsigned transaction first; require exact ordered/unique input set, exact destination/change outputs and exact fee conservation before destination confirmation or WIF prompt | `test_inconsistent_unsigned_input_set_rejected`, `test_unsigned_mismatch_fails_before_key_prompt`, `test_signing_primitive_not_called_on_preflight_failure` |
| signed transport drops bulky `prevtxs` | broadcaster only has an input count, not the approved exact outpoints | signed transport adds compact `inputSet=[{txid,vout},...]` before dropping `prevtxs` | `test_valid_mocked_sign_flow_adds_exact_input_set`, `test_signed_transport_duplicate_input_rejected` |
| broadcast decodes the transaction and checks destination/change/count/fee | count equality does not prove the same inputs were signed | broadcaster requires exact ordered/unique input set and exact output set; unexpected scripts/addresses fail closed | `test_changed_destination_rejected`, `test_changed_amount_rejected`, `test_unexpected_output_rejected` |
| broadcast does not refresh every selected input immediately before send | an input can become spent/stale after planning/signing | call `gettxout(txid, vout, true)` for every approved input immediately before confirmation/broadcast and verify aggregate value | `test_stale_input_rejected_before_broadcast`, `test_valid_mocked_broadcast_flow_succeeds` |
| `--amount` is parsed as Python `float` | exact decimal text is rounded before invariant logic sees it | CLI spelling is unchanged, but conversion is delayed and performed through `Decimal`/atomic units | covered by exact fee/change/value-conservation tests |
| online and offline commands coexist in one script | key access must stay restricted to `sign` despite single-file upstream compatibility | only `cmd_sign` calls `getpass` or `signrawtransactionwithkey`; plan/broadcast never request/load a WIF | `test_online_plan_and_broadcast_paths_do_not_prompt_or_sign` |

## Compatibility notes

Intentional compatibility choices:

- command names remain `plan`, `sign`, `broadcast`;
- default filenames remain `treasury-plan.json` and `treasury-signed.json`;
- treasury address remains `WdMMqW1DcgWZ6HtyJuEMdce6QkKg4raGmE`;
- RPC defaults and `wam-cli -stdin` signing path remain;
- fee policy remains `0.0002 WAM/kvB`;
- the plan retains the existing fields and numeric JSON representation;
- `prevtxs` is still removed from the signed hand-off after signing.

Intentional format extension:

- signed hand-off adds `inputSet`, containing only `{txid, vout}` pairs. This is
  necessary for the broadcaster to prove that the signed transaction spends the
  exact inputs approved before key use without carrying the full `prevtxs` payload.

Intentional CLI implementation change:

- `--amount` is no longer converted by `argparse` with `type=float`; the same textual
  CLI values are accepted, but exact conversion occurs inside the script so binary
  float rounding cannot precede security checks.

## Review/adoption guidance

This file is a candidate, not a production declaration. A safe maintainer review is:

1. diff `scripts/treasury_spend.py` at the locked commit against the candidate;
2. review each row above with its direct regression;
3. preserve the fail-closed behavior if adapting the patch to a newer WAM Core head;
4. run the candidate tests plus the existing treasury/reference and full security suites;
5. only then port/cherry-pick the reviewed changes into WAM Core.

The intended handoff is:

`DEV original -> security finding -> hardened candidate -> regression proof`
