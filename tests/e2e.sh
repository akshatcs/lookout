#!/usr/bin/env bash
# End-to-end check of the whole system on the veth testbed. Takes ~2 minutes.
#
#   sudo ./tests/e2e.sh        (or: sudo make e2e)
#
# Creates the testbed and loads the firewall if needed, then checks real
# packets against every feature. Leaves the firewall loaded with default
# settings and empty lists.
set -u
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "needs root: sudo $0" >&2; exit 1; }
for t in hping3 tcpdump ping ip; do
    command -v $t >/dev/null || { echo "missing $t (./scripts/install_deps.sh)" >&2; exit 1; }
done

[[ -e /sys/class/net/veth-fw ]] || ./bench/setup_netns.sh >/dev/null || exit 1
[[ -e /sys/fs/bpf/adaptfw/config ]] || ./bin/fwload -i veth-fw >/dev/null || exit 1

FW="python3 -m control.fwctl"
NS="ip netns exec fwtest"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; pkill -f "control.controller" 2>/dev/null' EXIT
pass=0 fail=0

check() {   # check "description" <test command...>
    local what=$1; shift
    if "$@"; then echo "  ok    $what"; pass=$((pass+1))
    else          echo "  FAIL  $what"; fail=$((fail+1)); fi
}
stat()     { $FW stats | tr -d , | awk -v k="$1" '$1==k {print $2}'; }
replies()  { $NS ping -c "$2" -W 1 -i 0.2 -I "$1" 10.10.1.1 2>/dev/null | grep -oE '[0-9]+ received' | cut -d' ' -f1; }
hits()     { $FW block list | tr -d , | awk -v p="$1/32" '$1==p {print $3}'; }
send()     { $NS hping3 -q "$@" 10.10.1.1 >/dev/null 2>&1; }
clean()    { $FW reset --all >/dev/null; }
level()    { $FW config | awk '/aggressiveness/ {print $2}'; }
# tcpdump sees what the stack sees, i.e. only what XDP passed
capture()  { tcpdump -ni veth-fw -c 1000 "$2" >"$TMP/$1" 2>/dev/null & cap=$!; sleep 1; }
captured() { sleep 1; kill $cap; wait $cap 2>/dev/null; grep -c . "$TMP/$1"; }
eq()       { [[ "$1" == "$2" ]]; }
ge()       { [[ "${1:-0}" -ge "$2" ]]; }
between()  { [[ "${1:-0}" -ge "$2" && "${1:-0}" -le "$3" ]]; }

clean

echo "plumbing"
check "selftest passes" bash -c "$FW selftest | grep -q 'self-test passed'"
check "attached in native mode" bash -c "ip link show veth-fw | grep -q 'xdp '"

echo "manual block and expiry"
check "traffic passes with no rules" eq "$(replies 10.10.1.2 3)" 3
$FW block add 10.10.1.2 --duration 2 >/dev/null
check "blocked source gets no replies" eq "$(replies 10.10.1.2 3)" 0
check "block hit counter counts drops" ge "$(hits 10.10.1.2)" 3
sleep 2
check "block lifts on its own at the deadline" eq "$(replies 10.10.1.2 3)" 3
$FW block add 10.10.1.2 >/dev/null; $FW block del 10.10.1.2 >/dev/null
check "manual unblock restores traffic" eq "$(replies 10.10.1.2 3)" 3

echo "allowlist"
$FW allow add 10.10.1.2 >/dev/null
check "CLI refuses to block an allowlisted host" bash -c "$FW block add 10.10.1.2 | grep -q refused"
python3 -c "from control.firewall import Firewall; Firewall().block('10.10.1.2', 60)"
check "kernel ignores a block on an allowlisted host" eq "$(replies 10.10.1.2 3)" 3
$FW allow del 10.10.1.2 >/dev/null; clean

echo "TCP flag checks"
send -c 20 -i u10000 -F -P -U -p 80
check "20 xmas packets dropped" eq "$(stat drop_proto)" 20
$FW reset >/dev/null; send -c 10 -i u10000 -S -F -p 80
check "10 SYN+FIN packets dropped" eq "$(stat drop_proto)" 10
$FW reset >/dev/null; send -c 10 -i u10000 -S -p 80
check "plain SYNs pass" eq "$(stat drop_proto)" 0

echo "port rules and default policy"
capture p23 'tcp dst port 23'
send -c 5 -i u100000 -S -p 23
send -c 5 -i u100000 -S -p 80
n23=$(captured p23)
check "no rules: SYNs to port 23 reach the stack ($n23 seen)" eq "$n23" 5
clean; $FW port deny tcp 23 >/dev/null
capture p23 'tcp dst port 23'
send -c 5 -i u100000 -S -p 23
send -c 5 -i u100000 -S -p 80
n23=$(captured p23)
check "deny tcp/23: the stack sees none of them" eq "$n23" 0
check "deny tcp/23: 5 counted as drop_port_rule" eq "$(stat drop_port_rule)" 5
check "deny tcp/23: port 80 still passes" eq "$(stat pass_default)" 5
check "rule hit counter is 5" bash -c "$FW port | tr -d , | grep -q 'tcp/23.*deny.* 5$'"
$FW allow add 10.10.1.4 >/dev/null; $FW reset >/dev/null
send -c 3 -i u100000 -S -p 23 -a 10.10.1.4
check "allowlisted source bypasses port rules" eq "$(stat pass_allowlist)" 3
clean

$FW port allow tcp 22 >/dev/null; $FW port allow icmp 8 >/dev/null
$FW policy deny >/dev/null
check "default deny: ping allowed by the icmp/8 rule" eq "$(replies 10.10.1.2 3)" 3
$FW reset >/dev/null
# From an address that doesn't exist: if the VM runs sshd, it answers SYNs
# from a real client, whose resets to port 22 would be counted here too.
send -c 4 -i u100000 -S -p 22 -a 10.10.1.9
send -c 4 -i u100000 -S -p 8080
send -c 4 -i u100000 --udp -p 53
check "default deny: tcp/22 passes by rule" eq "$(stat pass_rule)" 4
check "default deny: tcp/8080 and udp/53 dropped by the policy" eq "$(stat drop_default)" 8
$FW reset >/dev/null
send -c 3 -i u100000 -S -F -p 22
check "flag checks still run before the port rules" eq "$(stat drop_proto)" 3
$FW policy allow >/dev/null; $FW reset >/dev/null
send -c 3 -i u100000 --udp -p 53
check "policy back to allow: udp/53 passes" eq "$(stat pass_default)" 3
clean

echo "fragments"
send -c 2 -i u100000 --udp -p 53 -d 1400 -f
check "fragments pass by default" bash -c "[[ $(stat pass_default) -ge 4 && $(stat drop_fragment) == 0 ]]"
$FW reset >/dev/null; $FW config set --enable frags >/dev/null
send -c 2 -i u100000 --udp -p 53 -d 1400 -f
check "with frags enabled, non-first fragments are dropped" ge "$(stat drop_fragment)" 2
clean

echo "per-source rate limit"
$FW reset >/dev/null; $FW config set --rate 1000 --burst 2000 >/dev/null
$NS timeout 6 hping3 --flood -S -p 80 -a 10.10.1.3 10.10.1.1 >/dev/null 2>&1 &
sleep 2; got=$(replies 10.10.1.4 5); wait
check "another source is unaffected during the flood" eq "$got" 5
admitted=$(python3 -c "
from control.firewall import Firewall
s = Firewall().read_states()['10.10.1.3']; print(s['packets'] - s['dropped'])")
check "flood held to the limit ($admitted admitted, ~8000 expected)" between "$admitted" 6000 10000
# Two senders with the same source address land on different CPUs and
# queues, so the bucket is updated from both at once.
$FW reset >/dev/null
for i in 1 2; do $NS timeout 6 hping3 --flood -S -p 80 -a 10.10.1.3 10.10.1.1 >/dev/null 2>&1 & done
wait
admitted=$(python3 -c "
from control.firewall import Firewall
s = Firewall().read_states()['10.10.1.3']; print(s['packets'] - s['dropped'])")
check "limit holds with one source on two CPUs ($admitted admitted)" between "$admitted" 6000 10000
s=$($FW stats | tr -d ,)
rx=$(echo "$s" | awk '$1=="rx_packets" {print $2}')
sum=$(echo "$s" | awk '$1 ~ /^(pass|drop)_/ {t += $2} END {print t}')
check "passed + dropped == received ($rx)" eq "$rx" "$sum"
clean

echo "spoofed source and subnets"
tcpdump -ni veth-fw -c 100 'src host 8.8.8.8' >"$TMP/before" 2>/dev/null & tp=$!
sleep 1; send -c 5 -i u100000 -S -p 80 -a 8.8.8.8; sleep 1; kill $tp; wait $tp 2>/dev/null
$FW block add 8.8.8.8 >/dev/null
tcpdump -ni veth-fw -c 100 'src host 8.8.8.8' >"$TMP/after" 2>/dev/null & tp=$!
sleep 1; send -c 5 -i u100000 -S -p 80 -a 8.8.8.8; sleep 1; kill $tp; wait $tp 2>/dev/null
check "tcpdump sees 5 SYNs before the block" eq "$(grep -c 'Flags \[S\]' "$TMP/before")" 5
check "tcpdump sees nothing after it (dropped before the stack)" eq "$(grep -c 'Flags \[S\]' "$TMP/after")" 0
check "block hit counter is 5" eq "$(hits 8.8.8.8)" 5
clean; $FW block add 8.8.8.0/24 >/dev/null
send -c 3 -i u100000 -S -a 8.8.8.44; send -c 3 -i u100000 -S -a 8.8.9.44
check "one /24 entry drops 8.8.8.44 but not 8.8.9.44" \
    bash -c "[[ $(stat drop_blocklist) == 3 && $(stat pass_default) == 3 ]]"
clean

echo "controller"
CTL="python3 -m control.controller"
# If a controller check fails, its screen output is kept here for diagnosis
LOG=results/e2e-controller.log
keep_log() { mkdir -p results; sed 's/\x1b\[[0-9;]*[A-Za-z]//g' "$1" >"$LOG"
             echo "  (controller output saved to $LOG)"; }
timeout 9 $CTL --dry-run >"$TMP/dry" 2>&1 &
sleep 2; $NS timeout 6 hping3 --flood -S -p 80 -a 10.10.1.3 10.10.1.1 >/dev/null 2>&1; wait
check "dry run reports WOULD BLOCK" grep -q 'WOULD BLOCK 10.10.1.3' "$TMP/dry"
check "dry run leaves the blocklist empty" bash -c "$FW block list | grep -q empty"
clean

failed_before=$fail
$FW allow add 10.10.1.9 >/dev/null
$CTL >"$TMP/live" 2>&1 & ctl=$!
sleep 2
# Pace the floods (RATE us/packet, ~25k pps) rather than --flood, so seven
# generators plus the controller all fit on a modest VM and the measured
# rates stay well above the detection thresholds instead of flickering.
gen() { RATE=40 ./bench/gen_traffic.sh "$1" 20 "$2" >/dev/null & }
gen syn_flood 10.10.1.3; gen low_slow_syn 10.10.1.4; gen udp_flood 10.10.1.5
gen icmp_flood 10.10.1.6; gen port_scan 10.10.1.7
# 10.10.1.9 is allowlisted and matches the SYN rule. It sends slowly on
# purpose: the allowlist passes everything up the stack, and a full flood
# there would only test how fast this machine's kernel is.
gen game 10.10.1.2; gen low_slow_syn 10.10.1.9
# Wait until all five are blocked, for at most 18 s (a fast machine needs 3)
t0=$SECONDS; declare -A took=(); lvl=L0
for _ in $(seq 36); do
    sleep 0.5
    bl=$($FW block list)
    l=$(level); [[ ${l#L} -gt ${lvl#L} ]] && lvl=$l      # highest tier seen
    for ip in 3 4 5 6 7; do
        [[ -z ${took[$ip]:-} ]] && grep -q "10.10.1.$ip/32" <<<"$bl" && took[$ip]=$((SECONDS - t0))
    done
    [[ ${#took[@]} == 5 ]] && break
done
blocked=$($FW block list)
kill -INT $ctl; wait $ctl 2>/dev/null
pkill -f "hping3" 2>/dev/null; wait
for ip in 3 4 5 6 7; do
    check "attack from 10.10.1.$ip auto-blocked (within ${took[$ip]:-18+} s)" \
        grep -q "10.10.1.$ip/32" <<<"$blocked"
done
check "normal game traffic from 10.10.1.2 not blocked" bash -c "! grep -q 10.10.1.2/32 <<<'$blocked'"
check "allowlisted 10.10.1.9 not blocked though it matches a rule" bash -c "! grep -q 10.10.1.9/32 <<<'$blocked'"
check "rate tier escalated under load (reached $lvl)" bash -c "[[ $lvl != L0 ]]"
# Put the loose rate limit back and let the bucket refill, so that only the
# blocklist entry can be what drops these pings.
$FW config set --rate 20000 --burst 40000 >/dev/null; sleep 1.5
check "blocks still enforced after the controller exits" eq "$(replies 10.10.1.3 3)" 0
[[ $fail -gt $failed_before ]] && keep_log "$TMP/live"
$FW allow del 10.10.1.9 >/dev/null
clean

echo "adaptation both ways"
failed_before=$fail
$CTL >"$TMP/live2" 2>&1 & ctl=$!
sleep 2
./bench/gen_traffic.sh syn_flood 40 10.10.1.3 >/dev/null &
for _ in $(seq 10); do sleep 1; $FW block list | grep -q 10.10.1.3/32 && break; done
peak=$(level)
# relaxing takes 5 calm seconds per tier; give it up to 20 s
for _ in $(seq 20); do sleep 1; later=$(level); [[ ${later#L} -lt ${peak#L} ]] && break; done
kill -INT $ctl; wait $ctl 2>/dev/null
pkill -f "hping3" 2>/dev/null; wait
check "flood blocked and tier raised ($peak)" bash -c "[[ $peak != L0 ]] && $FW block list | grep -q 10.10.1.3/32"
check "tier relaxed while the blocked flood went on ($peak -> $later)" bash -c "[[ ${later#L} -lt ${peak#L} ]]"
[[ $fail -gt $failed_before ]] && keep_log "$TMP/live2"
clean

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
