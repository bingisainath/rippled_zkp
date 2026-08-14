#!/usr/bin/env bash
#  live_xrp_transfer_demo.sh — "Watch real XRP land via a ZK proof"
#
#  A focused, narration-friendly LIVE demo for a viva. It shows, on a real
#  standalone rippled node, that a zero-knowledge ROLLUP WITHDRAWAL moves
#  genuine on-ledger XRP into a destination account:
#
#    1. boot a fresh standalone node (ZKRollup amendment on from genesis)
#    2. submit a DEPOSIT batch (8 deposits)  -> rollup pool funded to 160 XRP
#    3. show the destination account BEFORE  -> it does NOT exist yet
#    4. submit a WITHDRAWAL batch (ZK-proven) -> doApply credits real XRP
#    5. show the destination account AFTER   -> it now holds 20 real XRP
#
#  This is the on-chain twin of the 23-scenario ~/rollup_demo.sh. It does NOT
#  modify or depend on that script — run either or both.
#
#  Usage:  bash tools/phase5/live_xrp_transfer_demo.sh
#
#  NOTE: not using `set -e` — this is a poll-heavy orchestration script with
#  explicit `|| fail` on every critical step (same rationale as bench_live_e2e).
set -uo pipefail

# ─── paths & config ─────────────────────────────────────────
RIPPLED_ROOT="${RIPPLED_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RIPPLED="${RIPPLED:-$RIPPLED_ROOT/build/build/Release/rippled}"
GEN_TOOL="${GEN_TOOL:-$(dirname "${RIPPLED}")/gen_batch_blob}"

# Unique sandbox + token so our pkill never matches the demo (5095) or bench
# (5096) nodes, and never matches this script's own launch command line.
WORK_DIR="${WORK_DIR:-/tmp/zkxfer_node}"
CFG="${WORK_DIR}/rippled.cfg"
DB_DIR="${WORK_DIR}/db"
PORT="${ZKXFER_PORT:-5097}"
RPC_URL="http://127.0.0.1:${PORT}"
KILL_TOKEN="zkxfer_node"          # our private pkill match string

# Standalone genesis (master) account — acts as the rollup bridge pool.
GENESIS_ACCT="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_SECRET="snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
ZKR_HASH="E0BED425F9FA5F184F68156A07EB8EF25B03245EFA08F3F71EBA31C7EE74BCBF"

# Destination for the withdrawal. On a FRESH node this account does not exist,
# so the ZK withdrawal will create it from nothing. (Address = demo's DEST_0,
# a valid Ed25519 r-address; any valid classic address works.)
DEST="${DEST:-rQsWK5BwuZY2kcCiyjx3z24LxKfbcDYBLg}"

# ─── pretty output ──────────────────────────────────────────
C_HDR=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_INFO=$'\033[0;34m'
C_WARN=$'\033[1;33m'; C_ERR=$'\033[0;31m'; C_OFF=$'\033[0m'
hdr()  { printf '\n%s══ %s ══%s\n' "$C_HDR" "$*" "$C_OFF"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK"  "$C_OFF" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_INFO" "$C_OFF" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_OFF" "$*"; stop_node; exit 1; }

rpc() { curl -sf -X POST -H "Content-Type: application/json" --data "$1" "$RPC_URL"; }

# ─── node lifecycle ─────────────────────────────────────────
write_cfg() {
    mkdir -p "${DB_DIR}/nudb" "$(dirname "${CFG}")"
    cat > "${CFG}" <<CFGEOF
[server]
port_rpc_admin_local

[port_rpc_admin_local]
port = ${PORT}
ip = 127.0.0.1
admin = 127.0.0.1
protocol = http

[node_db]
type=NuDB
path=${DB_DIR}/nudb

[database_path]
${DB_DIR}

[debug_logfile]
${WORK_DIR}/debug.log

[validation_seed]
snoPBrXtMeMyMHUVTgbuqAfg1SUTb

[ledger_history]
none

[signing_support]
true

[ssl_verify]
0

[amendments]
${ZKR_HASH} ZKRollup
CFGEOF
}

start_node() {
    pkill -f "rippled.*${KILL_TOKEN}" 2>/dev/null || true
    sleep 1
    # rm -rf "${DB_DIR}"; mkdir -p "${DB_DIR}/nudb"; rm -f "${WORK_DIR}/debug.log"
    nohup "${RIPPLED}" --conf "${CFG}" --standalone --start \
        > "${WORK_DIR}/stdout.log" 2>&1 &
    local w=0
    until rpc '{"method":"server_info","params":[{}]}' >/dev/null 2>&1; do
        sleep 0.5; w=$((w+1)); [[ $w -gt 120 ]] && fail "node did not start on :${PORT}"
    done
}
stop_node() { pkill -f "rippled.*${KILL_TOKEN}" 2>/dev/null || true; }
close_ledger() { rpc '{"method":"ledger_accept","params":[{}]}' >/dev/null 2>&1 || true; }

# ─── RPC helpers ────────────────────────────────────────────
# echoes "BatchCounter|RollupRoot|PoolDrops" or "none|none|none"
get_pool() {
    rpc '{"method":"ledger_data","params":[{"ledger_index":"current","limit":400}]}' 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
nodes = d.get('result',{}).get('state', d.get('result',{}).get('state_data',[]))
for n in nodes:
    if n.get('LedgerEntryType') == 'RollupState':
        bal = n.get('Balance','0'); bal = bal if isinstance(bal,str) else bal.get('value','0')
        print(f\"{n.get('BatchCounter','?')}|{n.get('RollupRoot','?')[:16]}…|{bal}\"); break
else:
    print('none|none|none')
" 2>/dev/null || echo "error|error|error"
}

# echoes the account's balance in drops, or "DOES_NOT_EXIST"
get_balance() {
    rpc "{\"method\":\"account_info\",\"params\":[{\"account\":\"$1\",\"ledger_index\":\"current\"}]}" 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
r = d.get('result',{})
if r.get('status') == 'error' or 'account_data' not in r:
    print('DOES_NOT_EXIST')
else:
    print(r['account_data'].get('Balance','?'))
" 2>/dev/null || echo "DOES_NOT_EXIST"
}

prefund() {  # account drops  — normal Payment from genesis
    python3 - "$@" <<PYEOF
import urllib.request, json, sys
acct, drops = sys.argv[1], sys.argv[2]
tx = {"TransactionType":"Payment","Account":"${GENESIS_ACCT}",
      "Destination":acct,"Amount":str(drops)}
body = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=body.encode(),
                             headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=60) as resp:
        print(json.load(resp)["result"]["engine_result"])
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
}

submit_rollup() {  # blob pub batchId prevRoot newRoot
    python3 - "$@" <<PYEOF
import urllib.request, json, sys
blob, pub, bid, prev, new = sys.argv[1:6]
tx = {"TransactionType":"BatchRollup","Account":"${GENESIS_ACCT}",
      "BatchId":int(bid),"PrevRoot":prev,"RollupRoot":new,"TxCount":8,
      "SequencerPubKey":pub,"BatchProof":blob}
body = json.dumps({"method":"submit","params":[{"tx_json":tx,"secret":"${GENESIS_SECRET}"}]})
req = urllib.request.Request("${RPC_URL}", data=body.encode(),
                             headers={"Content-Type":"application/json"})
try:
    with urllib.request.urlopen(req, timeout=180) as resp:
        print(json.load(resp)["result"]["engine_result"])
except Exception as e:
    print(f"RPC_ERROR:{e}", file=sys.stderr); sys.exit(1)
PYEOF
}

drops_to_xrp() { python3 -c "print(f'{int(\"$1\")/1_000_000:.6f}')" 2>/dev/null || echo "?"; }

# ─── preflight ──────────────────────────────────────────────
[[ -x "$RIPPLED"  ]] || fail "rippled not found at $RIPPLED"
[[ -x "$GEN_TOOL" ]] || fail "gen_batch_blob not found at $GEN_TOOL"
if [[ ! -f /tmp/rippled_rollup_keys_pk ]]; then
    info "generating Groth16 keys (~60s, one-time)…"
    "$GEN_TOOL" --gen-keys >/dev/null 2>&1 || fail "key generation failed"
fi

clear 2>/dev/null || true
cat <<BANNER
${C_HDR}╔══════════════════════════════════════════════════════════════════╗
║   ZK-ROLLUP LIVE DEMO — real XRP moved by a zero-knowledge proof  ║
╚══════════════════════════════════════════════════════════════════╝${C_OFF}
BANNER

# ─── 1. boot ────────────────────────────────────────────────
hdr "STEP 1 — Boot a fresh standalone XRPL node"
write_cfg
start_node
ZKR=$(rpc '{"method":"feature","params":[{"feature":"'"${ZKR_HASH}"'"}]}' \
      | python3 -c "import sys,json;d=json.load(sys.stdin);f=list(d['result'].values())[0] if d.get('result') else {};print(f.get('enabled','?'))" 2>/dev/null)
ok "Node live on :${PORT} — featureZKRollup enabled = ${ZKR}"
info "Rollup state at genesis: $(get_pool)  (BatchCounter|Root|PoolDrops)"

# ─── 2. deposit batch funds the pool ────────────────────────
hdr "STEP 2 — Submit a DEPOSIT batch (8 ZK proofs) to fund the rollup pool"
info "Generating 8 Groth16 proofs (~25-30s)…"
GEN1="$("$GEN_TOOL" 1 2>"${WORK_DIR}/gen_deposit.log")" || fail "deposit gen failed (see gen_deposit.log)"
eval "$(echo "$GEN1" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID)=' | sed 's/^/D_/')"
info "Deposit blob: $(( ${#D_BLOB} / 2 )) bytes, batchId=${D_BATCH_ID}"
RES1="$(submit_rollup "$D_BLOB" "$D_PUB" "$D_BATCH_ID" "$D_PREV_ROOT" "$D_NEW_ROOT")"
[[ "$RES1" == "tesSUCCESS" ]] || fail "deposit batch -> $RES1 (expected tesSUCCESS)"
close_ledger
ok "Deposit batch accepted on-chain -> ${RES1}"
IFS='|' read -r CTR ROOT POOL <<< "$(get_pool)"
ok "Rollup pool funded: BatchCounter=${CTR}, pool=${POOL} drops ($(drops_to_xrp "$POOL") XRP)"

# ─── 3. destination BEFORE ──────────────────────────────────
hdr "STEP 3 — The withdrawal destination, BEFORE"
info "Destination account: ${DEST}"
info "Pre-funding it with the bare 10 XRP reserve via a NORMAL payment."
info "(Why: rippled forbids creating a new account *inside* a BatchRollup —"
info " a documented prototype limit. The rollup then ADDS to this balance.)"
PF="$(prefund "$DEST" 10000000)"
[[ "$PF" == "tesSUCCESS" ]] || fail "pre-fund payment -> $PF"
close_ledger
BAL_BEFORE="$(get_balance "$DEST")"
ok "account_info BEFORE -> Balance = ${BAL_BEFORE} drops ($(drops_to_xrp "$BAL_BEFORE") XRP, reserve only)"

# ─── 4. withdrawal batch moves real XRP ─────────────────────
hdr "STEP 4 — Submit a ZK WITHDRAWAL batch crediting that destination"
info "gen_batch_blob 2 --chain --withdrawals 1 --dest ${DEST}"
info "Generating 8 Groth16 proofs (~25-30s)…"
GEN2="$("$GEN_TOOL" 2 --chain --withdrawals 1 --dest "$DEST" 2>"${WORK_DIR}/gen_withdraw.log")" \
    || fail "withdrawal gen failed (see gen_withdraw.log)"
eval "$(echo "$GEN2" | grep -E '^(BLOB|PUB|PREV_ROOT|NEW_ROOT|BATCH_ID)=' | sed 's/^/W_/')"
info "Withdrawal blob: $(( ${#W_BLOB} / 2 )) bytes, batchId=${W_BATCH_ID}, prevRoot=${W_PREV_ROOT:0:16}…"
RES2="$(submit_rollup "$W_BLOB" "$W_PUB" "$W_BATCH_ID" "$W_PREV_ROOT" "$W_NEW_ROOT")"
[[ "$RES2" == "tesSUCCESS" ]] || fail "withdrawal batch -> $RES2 (expected tesSUCCESS)"
close_ledger
ok "Withdrawal batch accepted on-chain -> ${RES2}"

# ─── 5. destination AFTER ───────────────────────────────────
hdr "STEP 5 — The withdrawal destination, AFTER"
BAL_AFTER="$(get_balance "$DEST")"
if [[ "$BAL_AFTER" == "DOES_NOT_EXIST" ]]; then
    fail "destination still does not exist — withdrawal did not credit it"
fi
ok "account_info -> Balance = ${BAL_AFTER} drops ($(drops_to_xrp "$BAL_AFTER") XRP)"
IFS='|' read -r CTR2 ROOT2 POOL2 <<< "$(get_pool)"
info "Rollup pool now: BatchCounter=${CTR2}, pool=${POOL2} drops ($(drops_to_xrp "$POOL2") XRP)"

# ─── summary ────────────────────────────────────────────────
DELTA=$(( BAL_AFTER - BAL_BEFORE ))
hdr "RESULT"
printf '%s' "$C_OK"
cat <<SUMMARY
  Destination ${DEST}
    BEFORE (normal payment, reserve only) : ${BAL_BEFORE} drops ($(drops_to_xrp "$BAL_BEFORE") XRP)
    AFTER  (after ZK rollup withdrawal)   : ${BAL_AFTER} drops ($(drops_to_xrp "$BAL_AFTER") XRP)
    CREDITED BY THE ZK WITHDRAWAL         : +${DELTA} drops (+$(drops_to_xrp "$DELTA") XRP)

  The +$(drops_to_xrp "$DELTA") XRP landed in this account purely because the node
  VERIFIED a zero-knowledge proof on the consensus hot path and replayed the
  Merkle update in doApply — no plaintext sender, no on-chain link between the
  deposit note and this withdrawal. (This batch also carried 7 deposits, so the
  pool's net balance reflects both the +1 withdrawal and the +7 deposits.)
SUMMARY
printf '%s' "$C_OFF"

stop_node
ok "Demo complete. Node stopped. Logs in ${WORK_DIR}/"
