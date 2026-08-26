#!/usr/bin/env bash
# Mutation pass for decode_policy_datum: each mutation must be CAUGHT (aiken
# check goes red). A surviving mutation means the suite does not pin that
# property. Scratch script — not a production caller.
set -u
SRC=lib/aegis/policy_datum.ak
cp "$SRC" /tmp/pd.orig
# Restore on ANY exit: run() restores at its START, so without this the
# LAST mutation is left applied to the working tree.
trap 'cp /tmp/pd.orig "$SRC"; echo "--- source restored ---"' EXIT

run() {
  local name="$1"; shift
  cp /tmp/pd.orig "$SRC"
  "$@"
  local failed
  aiken check -m "aegis/policy_datum" > ../.mut.txt 2>&1
  failed=$(python -c "
import json
raw=open('../.mut.txt',encoding='utf-8',errors='replace').read()
i=raw.find('{')
print(json.loads(raw[i:])['summary']['failed'] if i>=0 else 'COMPILE_ERROR')
")
  if [ "$failed" = "0" ]; then
    echo "SURVIVED  $name"
  else
    echo "caught($failed)  $name"
  fi
}

m_tail_off_by_one() { sed -i 's/when list.at(tail, 0) is/when list.at(tail, 1) is/' "$SRC"; }
m_commitment_off()  { sed -i 's/when list.at(tail, 1) is/when list.at(tail, 2) is/' "$SRC"; }
m_datum_off()       { sed -i 's/when list.at(tail, 2) is/when list.at(tail, 1) is/' "$SRC"; }
m_no_tag_check()    { sed -i 's/^  expect tag == 0$/  expect tag >= 0/' "$SRC"; }
m_swap_head()       { sed -i 's/expect strike_price: Int = f_strike_price/expect strike_price: Int = f_coverage_amount/' "$SRC"; }
m_head_too_short()  { sed -i 's/^    f_oracle_provider, f_partner_address, f_partner_share_bps, f_risk_class,$/    f_oracle_provider, f_partner_address, f_partner_share_bps,/;s/^  expect risk_class: RiskClass = f_risk_class$/  expect risk_class: RiskClass = f_policy_id/' "$SRC"; }

run "tail[0] payout_address -> index 1" m_tail_off_by_one
run "tail[1] receipt_commitment -> index 2" m_commitment_off
run "tail[2] payout_datum -> index 1" m_datum_off
run "constructor tag check weakened" m_no_tag_check
run "head field 2 reads field 3" m_swap_head
run "risk_class demoted out of required head" m_head_too_short

cp /tmp/pd.orig "$SRC"
rm -f ../.mut.txt
echo "--- source restored ---"
