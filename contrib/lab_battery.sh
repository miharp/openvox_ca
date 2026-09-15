#!/usr/bin/env bash
# Exercise openvox_ca end to end against a disposable lab.
#
# Run on the CA host, inside an OpenBolt project whose modulepath holds this
# module and whose inventory defines the agent group. Every case prints PASS
# or FAIL with a one-line reason; the exit code is the number of failures.
#
#   CA_TARGET=localhost AGENTS=agents AGENT1=agent01.example.com AGENT2=agent02.example.com \
#     bash modules/openvox_ca/contrib/lab_battery.sh [case ...]
#
# Cases are named CHK-*, EXT-*, DIST-*, E2E-*, RB-*. With no arguments all run,
# in an order that leaves the lab healthy at the end. The battery changes the
# CA certificate, revokes and cleans a throwaway certificate, and restarts
# puppetserver, puppetdb, and the agents. Never point it at a real deployment.
set -u

CA_TARGET=${CA_TARGET:-localhost}
AGENTS=${AGENTS:-agents}
AGENT1=${AGENT1:-agent01.example.com}
AGENT2=${AGENT2:-agent02.example.com}
RUN_AS=${RUN_AS:---run-as root}
CADIR=$(puppet config print --section server cadir)
CERTNAME=$(puppet config print --section server certname)
HOSTCERT=$(puppet config print --section server hostcert)
LOCALCACERT=$(puppet config print --section server localcacert)
WORK=$(mktemp -d /tmp/openvox_ca_battery.XXXX)
PASS=0; FAILS=0; FAILED=()

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
fail() { printf '\033[31mFAIL\033[0m %s: %s\n' "$1" "$2"; FAILS=$((FAILS+1)); FAILED+=("$1"); }
need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 2; }; }
need bolt; need jq; need openssl

# bolt wrappers: stdout is the JSON result, exit code is bolt's.
plan()   { bolt plan run "$@" --format json 2>/dev/null; }
task()   { bolt task run "$@" --format json 2>/dev/null; }
cmd()    { bolt command run "$1" --targets "$2" $RUN_AS --format json 2>/dev/null; }
# first item value of a task/command result set
first()  { jq -r '.items[0].value'; }
ca_not_after() { openssl x509 -in "$CADIR/ca_crt.pem" -noout -enddate | cut -d= -f2; }
ca_epoch()     { date -d "$(ca_not_after)" +%s; }
crl_number()   { openssl crl -in "$CADIR/ca_crl.pem" -noout -text | awk '/X509v3 CRL Number/{getline; gsub(/ /,""); print; exit}'; }
sums()         { sha256sum "$CADIR/ca_crt.pem" "$CADIR/ca_crl.pem" "$CADIR/infra_crl.pem" "$LOCALCACERT" | awk '{print $1}' | tr '\n' ' '; }
agent_runs()   { cmd "/opt/puppetlabs/bin/puppet agent -t --detailed-exitcodes >/dev/null 2>&1; echo \$?" "$AGENTS" | jq -r '.items[] | "\(.target) \(.value.stdout|tonumber)"'; }
agents_ok()    { local bad; bad=$(agent_runs | awk '$2!=0 && $2!=2'); [ -z "$bad" ] || { echo "$bad"; return 1; }; }
unit_started() { cmd "systemctl show -p ActiveEnterTimestamp $1 | cut -d= -f2" "$2" | jq -r '.items[0].value.stdout'; }
wait_server()  { for _ in $(seq 1 36); do curl -sSf --insecure https://127.0.0.1:8140/status/v1/simple >/dev/null 2>&1 && return 0; sleep 5; done; return 1; }
near()         { local a=$1 b=$2 tol=$3; [ $(( a > b ? a - b : b - a )) -le "$tol" ]; }

# ---------------------------------------------------------------- CHK
t_CHK_01() { local r; r=$(plan openvox_ca::check ca="$CA_TARGET" targets="$AGENTS" $RUN_AS)
  [ "$(jq -r .ca.status <<<"$r")" = ok ] && [ "$(jq -r .ca.layout <<<"$r")" = single ] \
  && [ "$(jq '.hosts | length' <<<"$r")" = 2 ] && pass CHK-01 || fail CHK-01 "fresh lab not all ok: $(jq -c '{ca: .ca.status, hosts: (.hosts|map_values(.status))}' <<<"$r")"; }
t_CHK_02() { local r; r=$(plan openvox_ca::check ca="$CA_TARGET" warn_days=99999)
  [ "$(jq -r .ca.status <<<"$r")" = warn ] && pass CHK-02 || fail CHK-02 "huge warn window did not produce warn"; }
t_CHK_03() { local r; r=$(plan openvox_ca::check ca="$AGENTS" $RUN_AS); local rc=$?
  [ $rc -ne 0 ] && [ "$(jq -r .kind <<<"$r")" = openvox_ca/bad-ca-target ] && pass CHK-03 || fail CHK-03 "two CA targets accepted"; }
t_CHK_04() { local r; r=$(plan openvox_ca::check ca="$CA_TARGET" targets="$AGENT1,nope.example.com" $RUN_AS); local rc=$?
  [ $rc -eq 0 ] && [ "$(jq -r '.hosts["nope.example.com"]._error.kind' <<<"$r")" != null ] && [ "$(jq -r ".hosts[\"$AGENT1\"].status" <<<"$r")" = ok ] \
  && pass CHK-04 || fail CHK-04 "unreachable target should be reported, not fatal"; }
t_CHK_05() { local r; r=$(bolt task run openvox_ca::check_host_cert --targets "$AGENT1" --format json 2>/dev/null)
  [ "$(jq -r '.items[0].status' <<<"$r")" = failure ] || [ "$(jq '.items[0].value.items | length' <<<"$r")" != 0 ] \
  && pass CHK-05 || fail CHK-05 "non-root check reported ok with no items (should error or find files)"; }

# ---------------------------------------------------------------- EXT
t_EXT_01() { local before after r; before=$(sums); r=$(plan openvox_ca::extend ca="$CA_TARGET" dry_run=true); after=$(sums)
  [ "$before" = "$after" ] && [ "$(jq -r .extend.status <<<"$r")" = dry_run ] && [ "$(jq '.extend.planned_writes|length' <<<"$r")" = 5 ] \
  && pass EXT-01 || fail EXT-01 "dry run changed files or did not plan 5 writes"; }
t_EXT_02() { local before r rc; before=$(sums); r=$(plan openvox_ca::extend ca="$CA_TARGET"); rc=$?
  [ $rc -ne 0 ] && [ "$(jq -r .kind <<<"$r")" = openvox_ca/nothing-due ] && [ "$(sums)" = "$before" ] \
  && pass EXT-02 || fail EXT-02 "extend without force on a healthy CA should refuse"; }
t_EXT_03() { local r now; now=$(date +%s); r=$(plan openvox_ca::extend ca="$CA_TARGET" force=true ttl=15y)
  near "$(ca_epoch)" $((now + 15*365*86400)) 120 && [ "$(jq '.extend.backups|length' <<<"$r")" = 5 ] \
  && [ "$(systemctl is-active puppetserver)" = active ] && [ "$(systemctl is-active puppetdb)" = active ] && agents_ok \
  && pass EXT-03 || fail EXT-03 "15y extend: expiry $(ca_not_after), services $(systemctl is-active puppetserver puppetdb | tr '\n' ' ')"; }
t_EXT_04() { local n1 n2; n1=$(ls "$CADIR"/ca_crt.pem.*.bak | wc -l); sleep 1; plan openvox_ca::extend ca="$CA_TARGET" force=true >/dev/null; n2=$(ls "$CADIR"/ca_crt.pem.*.bak | wc -l)
  [ $((n2 - n1)) -eq 1 ] && agents_ok && pass EXT-04 || fail EXT-04 "second extend did not add exactly one backup or broke agents"; }
t_EXT_05() { local now; now=$(date +%s); plan openvox_ca::extend ca="$CA_TARGET" force=true ttl=400d >/dev/null
  near "$(ca_epoch)" $((now + 400*86400)) 120 && pass EXT-05 || fail EXT-05 "ttl=400d gave $(ca_not_after)"; }
t_EXT_06() { local rc; plan openvox_ca::extend ca="$CA_TARGET" force=true ttl=soon >/dev/null; rc=$?
  [ $rc -ne 0 ] && pass EXT-06 || fail EXT-06 "ttl=soon was accepted"; }
t_EXT_07() { local n1 n2 nu; n1=$(crl_number); plan openvox_ca::extend ca="$CA_TARGET" force=true crls=all >/dev/null; n2=$(crl_number)
  nu=$(date -d "$(openssl crl -in "$CADIR/ca_crl.pem" -noout -nextupdate | cut -d= -f2)" +%s)
  [ $((n2 - n1)) -eq 1 ] && near "$nu" "$(ca_epoch)" 5 && pass EXT-07 || fail EXT-07 "crls=all: number $n1->$n2, next_update not aligned with CA expiry"; }
t_EXT_08() { local serial; puppetserver ca generate --certname throwaway.example.com >/dev/null 2>&1
  serial=$(openssl x509 -in "$CADIR/signed/throwaway.example.com.pem" -noout -serial | cut -d= -f2)
  puppetserver ca revoke --certname throwaway.example.com >/dev/null 2>&1
  plan openvox_ca::extend ca="$CA_TARGET" force=true crls=all >/dev/null
  if openssl crl -in "$CADIR/ca_crl.pem" -noout -text | /usr/bin/grep -qi "Serial Number: $serial"; then pass EXT-08; else fail EXT-08 "revoked serial $serial missing from re-signed CRL"; fi
  puppetserver ca clean --certname throwaway.example.com >/dev/null 2>&1; }
t_EXT_09() { local t1 t2; t1=$(systemctl show -p ActiveEnterTimestamp puppetdb | cut -d= -f2); plan openvox_ca::extend ca="$CA_TARGET" force=true restart_puppetdb=false >/dev/null; t2=$(systemctl show -p ActiveEnterTimestamp puppetdb | cut -d= -f2)
  [ "$t1" = "$t2" ] && pass EXT-09 || fail EXT-09 "puppetdb was restarted despite restart_puppetdb=false"; systemctl restart puppetdb; }
t_EXT_10() { local r; r=$(task openvox_ca::extend_ca --targets "$CA_TARGET")
  if [ "$(jq -r '.items[0].status' <<<"$r")" = failure ] && jq -r '.items[0].value._error.msg' <<<"$r" | /usr/bin/grep -q running; then
    r=$(task openvox_ca::extend_ca --targets "$CA_TARGET" force=true); [ "$(jq -r '.items[0].value.status' <<<"$r")" = changed ] && pass EXT-10 || fail EXT-10 "force=true did not proceed"
  else fail EXT-10 "task ran against a live puppetserver without force"; fi; systemctl restart puppetserver; wait_server; }
t_EXT_11() { local before r rc; mv "$CADIR/ca_key.pem" "$WORK/ca_key.pem"; before=$(sums); r=$(plan openvox_ca::extend ca="$CA_TARGET" force=true); rc=$?; mv "$WORK/ca_key.pem" "$CADIR/ca_key.pem"
  [ $rc -ne 0 ] && [ "$(jq -r .kind <<<"$r")" = openvox_ca/external-ca ] && [ "$(sums)" = "$before" ] && [ "$(systemctl is-active puppetserver)" = active ] \
  && pass EXT-11 || fail EXT-11 "missing CA key: kind=$(jq -r .kind <<<"$r"), server $(systemctl is-active puppetserver)"; }
t_EXT_12() { local r; cp -p "$CADIR/ca_crt.pem" "$WORK/ca_crt.pem"; cat "$HOSTCERT" >> "$CADIR/ca_crt.pem"
  r=$(task openvox_ca::extend_ca --targets "$CA_TARGET" force=true dry_run=true); cp -p "$WORK/ca_crt.pem" "$CADIR/ca_crt.pem"
  jq -r '.items[0].value._error.msg' <<<"$r" | /usr/bin/grep -q "holds 3 certificates" && pass EXT-12 || fail EXT-12 "three-certificate bundle not refused"; }
t_EXT_13() { local r sans; r=$(plan openvox_ca::extend ca="$CA_TARGET" force=true regen_primary_cert=true)
  sans=$(openssl x509 -in "$HOSTCERT" -noout -ext subjectAltName | tail -1)
  echo "$sans" | /usr/bin/grep -q "DNS:$CERTNAME" && ! echo "$sans" | /usr/bin/grep -q "DNS:puppet," \
  && [ "$(jq -r '.extend.status' <<<"$r")" = changed ] && pass EXT-13 || fail EXT-13 "regen without alt names: SANs are '$sans'"; }
t_EXT_14() { local sans ext; plan openvox_ca::extend ca="$CA_TARGET" force=true regen_primary_cert=true "dns_alt_names=[\"puppet\",\"$CERTNAME\"]" >/dev/null
  sans=$(openssl x509 -in "$HOSTCERT" -noout -ext subjectAltName | tail -1); ext=$(openssl x509 -in "$HOSTCERT" -noout -text | /usr/bin/grep -c 1.3.6.1.4.1.34380.1.3.39)
  echo "$sans" | /usr/bin/grep -q "DNS:puppet," && [ "$ext" = 1 ] && puppetserver ca list --all >/dev/null 2>&1 && agents_ok \
  && pass EXT-14 || fail EXT-14 "regen with alt names: SANs '$sans', pp_cli_auth=$ext"; }
t_EXT_15() { local r; r=$(task openvox_ca::regen_primary_cert --targets "$CA_TARGET")
  [ "$(jq -r '.items[0].status' <<<"$r")" = failure ] && pass EXT-15 || fail EXT-15 "regen ran against a live puppetserver"; }

# ---------------------------------------------------------------- DIST
t_DIST_01() { local r; r=$(plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENTS" $RUN_AS)
  [ "$(jq "[.[] | select(.status==\"changed\")] | length" <<<"$r")" = 2 ] && agents_ok && pass DIST-01 || fail DIST-01 "refetch on healthy agents"; }
t_DIST_02() { local t1 t2 r; t1=$(unit_started puppet "$AGENT1"); r=$(plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENTS" strategy=upload $RUN_AS); t2=$(unit_started puppet "$AGENT1")
  [ "$(jq "[.[] | select(.written|length==2)] | length" <<<"$r")" = 2 ] && [ "$t1" != "$t2" ] && agents_ok && pass DIST-02 || fail DIST-02 "upload: written or agent restart missing"; }
t_DIST_03() { local expired; expired=$WORK/expired_ca.pem
  /opt/puppetlabs/puppet/bin/ruby -ropenssl -e 'k=OpenSSL::PKey::RSA.new(2048); c=OpenSSL::X509::Certificate.new; c.version=2; c.serial=1; c.subject=c.issuer=OpenSSL::X509::Name.new([["CN","Puppet CA: expired"]]); c.public_key=k.public_key; c.not_before=Time.now-864000; c.not_after=Time.now-86400; ef=OpenSSL::X509::ExtensionFactory.new; ef.subject_certificate=ef.issuer_certificate=c; c.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true)); c.sign(k,OpenSSL::Digest.new("SHA256")); File.write(ARGV[0], c.to_pem)' "$expired"
  bolt file upload "$expired" "$LOCALCACERT" --targets "$AGENTS" $RUN_AS >/dev/null 2>&1
  if agents_ok >/dev/null 2>&1; then fail DIST-03 "agents still ran with an expired CA copy"; return; fi
  plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENT1" $RUN_AS >/dev/null
  plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENT2" strategy=upload $RUN_AS >/dev/null
  agents_ok && pass DIST-03 || fail DIST-03 "agents not repaired after refetch/upload"; }
t_DIST_04() { local r; r=$(task openvox_ca::remove_localcacert --targets "$AGENT1" trigger_run=false $RUN_AS)
  [ "$(jq -r '.items[0].value.status' <<<"$r")" = removed ] && [ "$(jq -r '.items[0].value.fetched' <<<"$r")" = false ] && agents_ok \
  && pass DIST-04 || fail DIST-04 "trigger_run=false: $(jq -c '.items[0].value|{status,fetched}' <<<"$r")"; }
t_DIST_05() { local r before after; before=$(cmd "sha256sum $LOCALCACERT" "$AGENT2" | jq -r '.items[0].value.stdout')
  r=$(task openvox_ca::upload_ca --targets "$AGENT2" bundle="$(echo -n 'not a certificate' | base64)" $RUN_AS); after=$(cmd "sha256sum $LOCALCACERT" "$AGENT2" | jq -r '.items[0].value.stdout')
  [ "$(jq -r '.items[0].status' <<<"$r")" = failure ] && [ "$before" = "$after" ] && pass DIST-05 || fail DIST-05 "garbage bundle accepted or file changed"; }
t_DIST_06() { local r rc; r=$(plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENT1,nope.example.com" $RUN_AS); rc=$?
  [ $rc -ne 0 ] && [ "$(jq -r .kind <<<"$r")" = openvox_ca/distribute-failed ] && pass DIST-06 || fail DIST-06 "partial failure not reported as distribute-failed"; }
t_DIST_07() { local rc; plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENTS" strategy=teleport >/dev/null; rc=$?; [ $rc -ne 0 ] && pass DIST-07 || fail DIST-07 "invalid strategy accepted"; }

# ---------------------------------------------------------------- E2E
t_E2E_01() { local r
  plan openvox_ca::extend ca="$CA_TARGET" force=true ttl=1 crls=all >/dev/null; sleep 3
  r=$(plan openvox_ca::check ca="$CA_TARGET")
  [ "$(jq -r .ca.status <<<"$r")" = expired ] || { fail E2E-01 "CA not expired after ttl=1"; return; }
  if agents_ok >/dev/null 2>&1; then fail E2E-01 "agents still ran against an expired CA"; return; fi
  r=$(plan openvox_ca::extend ca="$CA_TARGET" ttl=15y)
  [ "$(jq '[.extend.crls[] | select(.resigned)] | length' <<<"$r")" -ge 2 ] || { fail E2E-01 "expired CRLs were not re-signed on recovery"; return; }
  plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENTS" $RUN_AS >/dev/null
  agents_ok && [ "$(plan openvox_ca::check ca="$CA_TARGET" targets="$AGENTS" $RUN_AS | jq -r .ca.status)" = ok ] \
  && curl -sSf --cert "$HOSTCERT" --key "$(puppet config print --section server hostprivkey)" --cacert "$LOCALCACERT" "https://$CERTNAME:8081/pdb/meta/v1/version" >/dev/null \
  && pass E2E-01 || fail E2E-01 "recovery from an expired CA incomplete"; }

# ---------------------------------------------------------------- RB
t_RB_01() { local b
  b=$(ls -t "$CADIR"/ca_crt.pem.*.bak | tail -1)
  systemctl stop puppetserver; cp -p "$b" "$CADIR/ca_crt.pem"; cp -p "$CADIR/ca_crt.pem" "$LOCALCACERT"; systemctl start puppetserver; wait_server
  agents_ok && pass RB-01 || fail RB-01 "restoring the oldest backup broke the deployment"
  plan openvox_ca::extend ca="$CA_TARGET" force=true ttl=15y >/dev/null; plan openvox_ca::distribute ca="$CA_TARGET" targets="$AGENTS" $RUN_AS >/dev/null; }

ALL=(CHK_01 CHK_02 CHK_03 CHK_04 CHK_05 EXT_01 EXT_02 EXT_03 EXT_04 EXT_05 EXT_06 EXT_07 EXT_08 EXT_09 EXT_10 EXT_11 EXT_12 EXT_13 EXT_14 EXT_15 DIST_01 DIST_02 DIST_03 DIST_04 DIST_05 DIST_06 DIST_07 E2E_01 RB_01)
if [ $# -gt 0 ]; then CASES=("${@//-/_}"); else CASES=("${ALL[@]}"); fi
log "openvox_ca lab battery on $CERTNAME ($(date -u +%FT%TZ)); CA expires $(ca_not_after)"
for c in "${CASES[@]}"; do log "$c"; "t_$c"; done
log "results: $PASS passed, $FAILS failed${FAILED:+ (${FAILED[*]})}"
rm -rf "$WORK"
exit "$FAILS"
