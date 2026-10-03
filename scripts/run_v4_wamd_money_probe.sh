#!/usr/bin/env bash
set -euo pipefail

CORE_DIR="${1:?usage: run_v4_wamd_money_probe.sh <patched-wam-core-dir>}"
cd "$CORE_DIR"

DATADIR="${RUNNER_TEMP:-/tmp}/wam-v4-money-regtest"
rm -rf "$DATADIR"
mkdir -p "$DATADIR"
RPC_USER=v4ci
RPC_PASS=v4ci-only

NODE=(./src/wam-cli -regtest -datadir="$DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS")
POOL=(./src/wam-cli -regtest -datadir="$DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcwallet=pool-v4)
RECV=(./src/wam-cli -regtest -datadir="$DATADIR" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" -rpcwallet=recv-v4)

cleanup() {
  "${NODE[@]}" stop >/dev/null 2>&1 || true
}
trap cleanup EXIT

./src/wamd -regtest -datadir="$DATADIR"   -server=1 -listen=0 -dnsseed=0 -discover=0 -txindex=1   -fallbackfee=0.0001   -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS"   -daemonwait

"${NODE[@]}" -rpcwait getblockchaininfo >/dev/null
"${NODE[@]}" createwallet pool-v4 >/dev/null
"${NODE[@]}" createwallet recv-v4 >/dev/null

POOL_ADDR=$("${POOL[@]}" getnewaddress)
RECV_ADDR=$("${RECV[@]}" getnewaddress)

POOL_OWNS=$("${POOL[@]}" getaddressinfo "$POOL_ADDR" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ismine"]).lower())')
RECV_OWNS_POOL=$("${RECV[@]}" getaddressinfo "$POOL_ADDR" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ismine"]).lower())')
test "$POOL_OWNS" = "true"
test "$RECV_OWNS_POOL" = "false"

"${NODE[@]}" generatetoaddress 110 "$POOL_ADDR" >/dev/null

RAW=$("${POOL[@]}" createrawtransaction '[]' "{\"$RECV_ADDR\":1.00000000}")
FUNDED=$("${POOL[@]}" fundrawtransaction "$RAW" '{"replaceable":false,"lockUnspents":true}')
FUNDED_HEX=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])' <<<"$FUNDED")
SIGNED=$("${POOL[@]}" signrawtransactionwithwallet "$FUNDED_HEX")
COMPLETE=$(python3 -c 'import json,sys; print(str(json.load(sys.stdin)["complete"]).lower())' <<<"$SIGNED")
test "$COMPLETE" = "true"
SIGNED_HEX=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])' <<<"$SIGNED")
TXID=$("${NODE[@]}" decoderawtransaction "$SIGNED_HEX" | python3 -c 'import json,sys; print(json.load(sys.stdin)["txid"])')

INTENT_DIR="${RUNNER_TEMP:-/tmp}/wam-v4-intent"
rm -rf "$INTENT_DIR"
mkdir -p "$INTENT_DIR"
printf '%s\n' "$SIGNED_HEX" > "$INTENT_DIR/rawtx"
printf '%s\n' "$TXID" > "$INTENT_DIR/txid"
BEFORE_HASH=$(sha256sum "$INTENT_DIR/rawtx" | awk '{print $1}')

# First broadcast succeeds, but the application deliberately ignores the RPC
# response to model a timeout/lost-response boundary.
"${NODE[@]}" sendrawtransaction "$SIGNED_HEX" >/dev/null
"${NODE[@]}" getmempoolentry "$TXID" >/dev/null

# Recovery reads the persisted identity and rebroadcasts exactly the same bytes.
RECOVERED_RAW=$(cat "$INTENT_DIR/rawtx")
RECOVERED_TXID=$(cat "$INTENT_DIR/txid")
test "$RECOVERED_RAW" = "$SIGNED_HEX"
test "$RECOVERED_TXID" = "$TXID"

set +e
SECOND_OUT=$("${NODE[@]}" sendrawtransaction "$RECOVERED_RAW" 2>&1)
SECOND_RC=$?
set -e
echo "second broadcast rc=$SECOND_RC: $SECOND_OUT"

AFTER_HASH=$(sha256sum "$INTENT_DIR/rawtx" | awk '{print $1}')
test "$BEFORE_HASH" = "$AFTER_HASH"

MEMPOOL=$("${NODE[@]}" getrawmempool)
MEMPOOL="$MEMPOOL" TXID="$TXID" python3 - <<'PY'
import json, os
txs = json.loads(os.environ["MEMPOOL"])
assert txs == [os.environ["TXID"]], txs
PY

"${NODE[@]}" generatetoaddress 1 "$POOL_ADDR" >/dev/null
CHAIN_TXID=$("${NODE[@]}" getrawtransaction "$TXID" true | python3 -c 'import json,sys; print(json.load(sys.stdin)["txid"])')
test "$CHAIN_TXID" = "$TXID"

RECV_BAL=$("${RECV[@]}" getbalance)
python3 - "$RECV_BAL" <<'PY'
import sys
bal = float(sys.argv[1])
assert abs(bal - 1.0) < 0.00000001, bal
PY

echo "V4 patched wamd raw-transaction identity probe: PASS"
echo "  payout wallet isolation: PASS"
echo "  persisted rawtx + txid before broadcast: PASS"
echo "  lost-response recovery rebroadcasted identical bytes: PASS"
echo "  mempool economic tx count: 1"
echo "  confirmed recipient amount: 1.00000000 WAM"
