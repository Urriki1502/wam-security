# WAM treasury split-role regression model

## Locked target

The harness is bound to `wamcoin-core-dev/wam-coin@bd71b0bd645286a3867dad6b2bfefd911ec8a5b6`.
Because this account has read-only access to upstream WAM Core, this repository carries
a review-ready reference refactor and regression model; it does not silently replace
production `scripts/treasury_spend.py`.

## Roles

The intended operating model is enforced structurally:

```text
online builder -> unsigned plan -> offline signer -> signed transaction -> online broadcaster
```

`src/wam_security/treasury/online.py` contains chain-state collection and broadcast
validation only. It has no WIF parser, terminal key prompt or signing call.
`src/wam_security/treasury/offline.py` accepts the plan, validates the decoded unsigned
transaction, then obtains and validates one WIF and invokes a supplied local signer.
`common.py` contains pure amount, input-set, fee/change and Base58Check validation.

## Locked-source gaps captured by the harness

The current upstream script already removes mempool-spent UTXOs, keeps the WIF off
argv, and checks signed outputs before broadcast. The regression adds coverage for
four boundaries that are not yet fully enforced upstream:

1. a failed `getrawtransaction` while enumerating mempool spends currently continues;
   the reference path treats that as unknown state and aborts;
2. current `_wif_looks_whole` verifies Base58Check only; the reference validator also
   requires WAM mainnet version 190, the valid compressed/uncompressed payload shape,
   and a secp256k1 scalar in range;
3. plan/sign/broadcast still coexist in one production file; the reference path makes
   the offline signer a separate module;
4. broadcast checks transaction contents but does not re-query every input with
   `gettxout(..., true)` immediately before send; the reference broadcaster does.

## Invariants

Regression tests require mempool-spent outputs to be excluded; unknown mempool state
to fail closed; no duplicate or inconsistent input set; exact base-unit fee/change
arithmetic; unsigned inputs to match the plan before any key prompt; malformed WIF to
fail before the signing primitive runs; signed inputs to match the approved set; every
input to remain unspent and unchanged immediately before broadcast; and the online
role to contain no private-key/signing loader.

The candidate deliberately uses integer atomic units/`Decimal` conversion for money
invariants rather than binary floating point. Compatibility with the current JSON
plan fields is preserved where practical.

## Upstream adoption

Maintainer review is required before moving the reference split into WAM Core. A safe
upstream migration is to keep the existing plan JSON fields, add the exact input set
to the signed transport, introduce separate online/offline entry points, and retain a
short compatibility wrapper only if it cannot reintroduce online access to signing.
