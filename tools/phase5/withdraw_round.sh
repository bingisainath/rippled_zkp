#!/usr/bin/env bash
#  withdraw_round.sh — submit ONE ZK withdrawal batch to a running node.
#  Companion to accumulate_xrp_demo.sh. Each call credits +20 XRP to DEST
#  and prints the destination balance before/after, so successive calls show
#  the balance accumulating (30 -> 50 -> 70 -> ...).
#
#  Usage:   bash tools/phase5/withdraw_round.sh <batchId>
#  Example: bash tools/phase5/withdraw_round.sh 2   # then 3, then 4, ...
#
#  Reuses the node booted by accumulate_xrp_demo.sh (port 5098 by default).
#  Honours the same env overrides (ZKACC_PORT, DEST, GEN_TOOL, RIPPLED_ROOT).
set -uo pipefail

BATCH_ID="${1:-}"
[[ -n "$BATCH_ID" ]] || { echo "usage: $0 <batchId>   (e.g. 2, then 3, then 4)"; exit 1; }
[[ "$BATCH_ID" =~ ^[0-9]+$ && "$BATCH_ID" -ge 2 ]] || { echo "batchId must be an integer >= 2"; exit 1; }

RIPPLED_ROOT="${RIPPLED_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RIPPLED="${RIPPLED:-$RIPPLED_ROOT/build/build/Release/rippled}"
GEN_TOOL="${GEN_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob}"
PORT="${ZKACC_PORT:-5098}"
RPC_URL="http://127.0.0.1:${PORT}"
WORK_DIR="${WORK_DIR:-/tmp/zkacc_node}"
GENESIS_ACCT="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_SECRET="snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
DEST="${DEST:-rQsWK5BwuZY2kcCiyjx3z24LxKfbcDYBLg}"

C_OK=$'\033[0;32m'; C_INFO=$'\033[0;34m'; C_ERR=$'\033[0;31m'; C_OFF=$'\033[0m'
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK"  "$C_OFF" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_OFF" "$*"; exit 1; }

rpc() { curl -sf -X POST -H "Content-Type: application/json" --data "$1" "$RPC_URL"; }
close_ledger() { rpc '{"method":"ledger_accept","params":[{}]}' >/dev/null 2>&1 || true; }
drops_to_xrp() { python3 -c "print(f'{int(\"$1\")/1_000_000:.6f}')" 2>/dev/null || echo "?"; }

get_balance() {
    rpc "{\"method\":\"account_info\",\"params\":[{\"account\":\"$1\",\"ledger_index\":\"current\"}]}" 2>/dev/null \
    | python3 -c "import sys,json;r=json.load(sys.stdin).get('result',{});print(r.get('account_data',{}).get('Balance','DOES_NOT_EXIST') if 'account_data' in r else 'DOES_NOT_EXIST')" 2>/dev/null \
    || echo "DOES_NOT_EXIST"
}

submit_rollup() {  # blob pub batchId prevRoot newRoot
    python3 - "$@" <<PYEOF
import urllib.request, json, sys
blob, pub, bid, prev, new = sys.argv[1:6]
tx = {"TransactionType":"BatchRollup","Account":"${GENESIS_ACCT}",
      "BatchId":int(bid),"PrevRoot":prev,"RollupRoot":new,"TxCount":8,
      "SequencerPubKey":pub,"BatchProof":blob}
body = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=body.encode(), headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        print(json.load(resp)["result"]["engine_result"])
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
}

# ── sanity: node reachable? ─────────────────────────────────
rpc '{"method":"server_info","params":[{}]}' >/dev/null 2>&1 \
    || fail "node not reachable on :${PORT} — run accumulate_xrp_demo.sh first"

BAL_BEFORE="$(get_balance "$DEST")"
[[ "$BAL_BEFORE" != "DOES_NOT_EXIST" ]] \
    || fail "destination ${DEST} does not exist — run accumulate_xrp_demo.sh first (it pre-funds it)"
info "Destination ${DEST}"
info "BEFORE: ${BAL_BEFORE} drops ($(drops_to_xrp "$BAL_BEFORE") XRP)"

# ── generate + submit this withdrawal batch ─────────────────
info "gen_batch_blob ${BATCH_ID} --chain --withdrawals 1 --dest ${DEST}  (8 Groth16 proofs, ~25-30s)…"
GEN="$("$GEN_TOOL" "$BATCH_ID" --chain --withdrawals 1 --dest "$DEST" 2>"${WORK_DIR}/gen_b${BATCH_ID}.log")" \
    || fail "gen_batch_blob failed (see ${WORK_DIR}/gen_b${BATCH_ID}.log)"
eval "$(echo "$GEN" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID)=')"
info "batchId=${BATCH_ID}, prevRoot=${PREV_ROOT:0:16}… newRoot=${NEW_ROOT:0:16}…"

RES="$(submit_rollup "$BLOB" "$PUB" "$BATCH_ID" "$PREV_ROOT" "$NEW_ROOT")"
[[ "$RES" == "tesSUCCESS" ]] || fail "batch ${BATCH_ID} -> $RES (expected tesSUCCESS)"
close_ledger
ok "Withdrawal batch ${BATCH_ID} accepted -> ${RES}"

BAL_AFTER="$(get_balance "$DEST")"
DELTA=$(( BAL_AFTER - BAL_BEFORE ))
ok "AFTER : ${BAL_AFTER} drops ($(drops_to_xrp "$BAL_AFTER") XRP)   [+$(drops_to_xrp "$DELTA") XRP via ZK proof]"
echo
info "Next round:  bash tools/phase5/withdraw_round.sh $((BATCH_ID + 1))"
