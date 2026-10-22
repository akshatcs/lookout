#!/usr/bin/env bash
# Guided demo. Every step runs real commands against the loaded firewall,
# shows them, checks the outcome and pauses. docs/DEMO.md explains each step.
#
#   sudo ./scripts/demo.sh             press Enter to advance
#   sudo ./scripts/demo.sh 4           start at step 4
#   sudo DEMO_AUTO=1 ./scripts/demo.sh no pauses (rehearsal; also how it is tested)
#
# For step 8 open a second terminal and run the controller there when asked,
# so the audience can watch it decide. In DEMO_AUTO mode the script starts it.
set -u
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo $0" >&2; exit 1; }
for t in hping3 tcpdump curl ip python3; do
    command -v $t >/dev/null || { echo "missing $t (./scripts/install_deps.sh)" >&2; exit 1; }
done
[[ -e bin/fwload && -e bpf/firewall.bpf.o ]] || { echo "run make first" >&2; exit 1; }

START=${1:-1}
AUTO=${DEMO_AUTO:-}
FW="python3 -m control.fwctl"
NS="ip netns exec fwtest"
B=$'\e[1m' D=$'\e[2m' G=$'\e[32m' R=$'\e[31m' C=$'\e[36m' N=$'\e[0m'
passed=0 failed=0 web=

cleanup() {
    [[ -n $web ]] && kill $web 2>/dev/null
    [[ -n ${ctl:-} ]] && kill -INT $ctl 2>/dev/null
    rm -f /tmp/demo-controller.$$
    [[ $passed -gt 0 || $failed -gt 0 ]] &&
        echo -e "\n${B}demo checks: $passed passed, $failed failed${N}"
}
trap cleanup EXIT

say()   { echo -e "  ${D}$*${N}"; }
run()   { echo -e "${C}\$ $*${N}"; eval "$@"; }
pause() { [[ -n $AUTO ]] || read -rsp $'  \e[2m[Enter]\e[0m\n' _; }
check() {   # check "what should be true" <command...>
    local what=$1; shift
    if "$@"; then echo -e "  ${G}✓ $what${N}"; passed=$((passed + 1))
    else          echo -e "  ${R}✗ $what${N}"; failed=$((failed + 1)); fi
}
step() {    # step N "title": returns 1 if this step is skipped
    [[ $1 -lt $START ]] && return 1
    echo -e "\n${B}━━ $1. $2 ━━${N}"
}

# Connect to 10.10.1.1:<port> from <source> and say what happened. "refused"
# means the host's TCP stack answered with a reset, so the packet got there.
# "no answer" means it was dropped on the way in.
tcp() {
    local code
    code=$($NS curl -s -m 2 -o /dev/null -w '%{http_code}' --interface "$1" \
           "http://10.10.1.1:$2/" 2>/dev/null)
    case $? in
        0)  echo "HTTP $code" ;;
        7)  echo "refused" ;;
        28) echo "no answer" ;;
        *)  echo "error" ;;
    esac
}
show_tcp() { local r; r=$(tcp "$1" "$2"); echo "  from $1 to port $2: $r"; last=$r; }
pings()    { $NS ping -c "${2:-3}" -W 1 -i 0.3 -I "$1" 10.10.1.1 2>/dev/null |
             grep -oE '[0-9]+ received' | cut -d' ' -f1; }
stat()     { $FW stats | tr -d , | awk -v k="$1" '$1==k {print $2}'; }
no_controller() { ! pgrep -f "python3 -m control[.]controller" >/dev/null; }

# ---------------------------------------------------------------- setup
echo -e "${B}Adaptive XDP firewall: guided demo${N}"
say "testbed: namespace fwtest (clients 10.10.1.2-.7) -> veth-fw 10.10.1.1, where XDP runs"
[[ -e /sys/class/net/veth-fw ]] || ./bench/setup_netns.sh >/dev/null || exit 1
for ip in 10.10.1.5 10.10.1.6 10.10.1.7; do
    $NS ip addr add $ip/24 dev veth-cl noprefixroute 2>/dev/null
done
if [[ $START -le 1 ]]; then
    ./bin/fwload -i veth-fw -u >/dev/null 2>&1
fi
[[ -e /sys/fs/bpf/adaptfw/config ]] || ./bin/fwload -i veth-fw >/dev/null
$FW reset --all >/dev/null
pkill -f "python3 -m control[.]controller" 2>/dev/null
# a small web server on the firewall host, so there is a real service to protect
python3 -m http.server 8080 --bind 10.10.1.1 --directory docs >/dev/null 2>&1 &
web=$!
sleep 1
pause

# ---------------------------------------------------------------- 1
if step 1 "The firewall is an eBPF program in the driver's receive path"; then
    say "Load it. The loader verifies, JIT-compiles and attaches it, then exits."
    run "./bin/fwload -i veth-fw -u >/dev/null; ./bin/fwload -i veth-fw"
    pause
    run "ip link show veth-fw | grep -oE ' xdp(generic)? |prog/xdp.*'"
    check "attached in native (driver) mode, not generic" \
        bash -c "ip link show veth-fw | grep -q 'xdp ' && ! ip link show veth-fw | grep -q xdpgeneric"
    run "$FW status | sed -n 2,4p"
    if command -v bpftool >/dev/null; then
        run "bpftool prog show name xdp_firewall"
    fi
    run "ls /sys/fs/bpf/adaptfw/"
    say "The program is still running although the loader has exited: the interface"
    say "holds the program, and the pinned maps are how the Python tools reach it."
    pause
fi

# ---------------------------------------------------------------- 2
if step 2 "Port rules: deny a service"; then
    say "Port 8080 has a web server. Port 23 (telnet) has nothing listening."
    show_tcp 10.10.1.2 8080
    show_tcp 10.10.1.2 23
    check "port 23 is refused: the host's TCP stack saw the SYN and reset it" [ "$last" = refused ]
    pause
    run "$FW port deny tcp 23"
    show_tcp 10.10.1.2 23
    check "now there is no answer at all: the SYN never reached the stack" [ "$last" = "no answer" ]
    show_tcp 10.10.1.2 8080
    check "the web server is unaffected" [ "$last" = "HTTP 200" ]
    pause
    say "Proof that the drop happens before the stack: tcpdump on veth-fw sees what the"
    say "stack sees. Five SYNs to port 23, five to port 8080:"
    tcpdump -ni veth-fw -c 100 'tcp[tcpflags] == tcp-syn' >/tmp/demo-tcpdump.$$ 2>/dev/null & tp=$!
    sleep 1
    run "$NS hping3 -q -c 5 -i u100000 -S -p 23 10.10.1.1 >/dev/null 2>&1"
    run "$NS hping3 -q -c 5 -i u100000 -S -p 8080 10.10.1.1 >/dev/null 2>&1"
    sleep 1; kill $tp; wait $tp 2>/dev/null
    seen23=$(grep -c '\.23: ' /tmp/demo-tcpdump.$$); seen80=$(grep -c '\.8080: ' /tmp/demo-tcpdump.$$)
    rm -f /tmp/demo-tcpdump.$$
    echo "  tcpdump saw $seen23 SYNs to port 23 and $seen80 to port 8080"
    check "tcpdump saw none of the denied SYNs and all five allowed ones" \
        bash -c "[[ $seen23 == 0 && $seen80 == 5 ]]"
    run "$FW port"
    pause
fi

# ---------------------------------------------------------------- 3
if step 3 "Default deny: only what you allow gets in"; then
    $FW port flush >/dev/null
    run "$FW port allow tcp 8080"
    run "$FW port allow icmp 8"
    run "$FW policy deny"
    show_tcp 10.10.1.2 8080
    check "the web server is reachable" [ "$last" = "HTTP 200" ]
    show_tcp 10.10.1.2 22
    check "ssh (22) gets no answer: no rule allows it" [ "$last" = "no answer" ]
    show_tcp 10.10.1.2 5432
    check "postgres (5432) gets no answer" [ "$last" = "no answer" ]
    n=$(pings 10.10.1.2); echo "  ping: $n of 3 replies"
    check "ping works because icmp type 8 is allowed" [ "$n" = 3 ]
    run "$FW port"
    run "$FW stats | grep -E 'pass_rule|drop_default'"
    say "Stateless, like iptables without conntrack: replies to connections this host"
    say "opens itself would need rules too (Section 8.2 of the report)."
    run "$FW port flush; $FW policy allow"
    pause
fi

# ---------------------------------------------------------------- 4
if step 4 "Blocking a source, with an expiry the kernel enforces"; then
    run "$FW block add 10.10.1.3 --duration 15"
    show_tcp 10.10.1.3 8080
    check "10.10.1.3 is cut off" [ "$last" = "no answer" ]
    show_tcp 10.10.1.2 8080
    check "10.10.1.2 on the same link is not" [ "$last" = "HTTP 200" ]
    run "$FW block list"
    say "Waiting for the block to run out. No userspace process removes it: the XDP"
    say "program compares the deadline on every packet."
    for i in $(seq 15 -1 1); do printf "\r  %2ds " $i; sleep 1; done; echo
    show_tcp 10.10.1.3 8080
    check "the block lifted on time by itself" [ "$last" = "HTTP 200" ]
    pause
fi

# ---------------------------------------------------------------- 5
if step 5 "Subnets, and the allowlist always wins"; then
    run "$FW block add 10.10.1.0/24 --duration 120"
    show_tcp 10.10.1.2 8080; a=$last
    show_tcp 10.10.1.4 8080; b=$last
    check "one /24 entry blocks every client" bash -c "[[ '$a' == 'no answer' && '$b' == 'no answer' ]]"
    run "$FW allow add 10.10.1.2"
    show_tcp 10.10.1.2 8080
    check "the allowlisted host gets through despite the /24 block" [ "$last" = "HTTP 200" ]
    show_tcp 10.10.1.4 8080
    check "everyone else in the /24 is still blocked" [ "$last" = "no answer" ]
    run "$FW block add 10.10.1.2"
    say "The allowlist is checked first, in the kernel, so no block (and no bad automatic"
    say "decision by the controller) can cut off a trusted host."
    run "$FW reset --all >/dev/null"
    pause
fi

# ---------------------------------------------------------------- 6
if step 6 "Packets no real TCP stack sends"; then
    run "$FW reset >/dev/null"
    run "$NS hping3 -q -c 20 -i u10000 -F -P -U -p 8080 10.10.1.1 >/dev/null 2>&1"
    run "$FW stats | grep -E 'rx_packets|drop_proto'"
    check "20 FIN+PSH+URG ('xmas') packets, 20 dropped" [ "$(stat drop_proto)" = 20 ]
    show_tcp 10.10.1.2 8080
    check "normal connections are unaffected" [ "$last" = "HTTP 200" ]
    pause
fi

# ---------------------------------------------------------------- 7
if step 7 "Per-source rate limiting"; then
    run "$FW reset >/dev/null; $FW config set --rate 1000 --burst 2000"
    say "10.10.1.3 floods the web port for 8 s; meanwhile 10.10.1.4 uses the site."
    $NS timeout 8 hping3 --flood -S -p 8080 -a 10.10.1.3 10.10.1.1 >/dev/null 2>&1 &
    fl=$!
    sleep 3
    show_tcp 10.10.1.4 8080
    check "10.10.1.4 is served during the flood" [ "$last" = "HTTP 200" ]
    wait $fl
    run "$FW top -n 3"
    read -r pk dr <<<"$(python3 -c "
from control.firewall import Firewall
s = Firewall().read_states()['10.10.1.3']; print(s['packets'], s['dropped'])")"
    adm=$((pk - dr))
    echo "  10.10.1.3 sent $pk packets; $adm were admitted (2000 burst + 8 s x 1000/s = 10000 expected)"
    check "the flooder was held to its limit (within 15%)" \
        bash -c "[[ $adm -ge 8500 && $adm -le 11500 ]]"
    run "$FW config set --rate 20000 --burst 40000"
    pause
fi

# ---------------------------------------------------------------- 8
if step 8 "The adaptive control plane"; then
    $FW reset --all >/dev/null
    $FW allow add 10.10.1.2 >/dev/null
    if [[ -n $AUTO ]]; then
        python3 -m control.controller >/tmp/demo-controller.$$ 2>&1 & ctl=$!
    else
        echo -e "  In a second terminal run: ${C}sudo python3 -m control.controller${N}"
        pause
        pgrep -f "python3 -m control[.]controller" >/dev/null || {
            say "(not running, starting it here in the background)"
            python3 -m control.controller >/dev/null 2>&1 & ctl=$!
        }
    fi
    sleep 2
    say "Three clients: 10.10.1.2 normal game-like traffic, 10.10.1.7 scans ports"
    say "1-1024, 10.10.1.3 floods. Nobody tells the firewall which is which."
    gens=()
    for g in "game 10.10.1.2" "port_scan 10.10.1.7" "syn_flood 10.10.1.3"; do
        set -- $g
        ./bench/gen_traffic.sh "$1" 60 "$2" >/dev/null & gens+=($!)
    done
    # usually 2-3 s; a slow VM can take longer, so wait up to 15 s
    for _ in $(seq 15); do
        sleep 1
        [[ $($FW block list | grep -cE '10\.10\.1\.(3|7)/32') == 2 ]] && break
    done
    run "$FW block list"
    peak=$($FW config | awk '/aggressiveness/ {print $2}')
    check "the scanner was blocked automatically" bash -c "$FW block list | grep -q 10.10.1.7/32"
    check "the flooder was blocked automatically" bash -c "$FW block list | grep -q 10.10.1.3/32"
    check "the normal client was not" bash -c "! $FW block list | grep -q 10.10.1.2/32"
    echo "  rate-limit tier right after the flood started: $peak"
    say "The tier went up within a second because load jumped. Now that the flooder is"
    say "blocked its packets no longer count as load, so the tier steps back down,"
    say "one level per 5 calm seconds, while the flood is still running."
    for i in $(seq 20); do
        sleep 1
        later=$($FW config | awk '/aggressiveness/ {print $2}')
        [[ ${later#L} -lt ${peak#L} ]] && break
    done
    echo "  tier $i s later: $later"
    check "the tier relaxed again ($peak -> $later)" bash -c "[[ ${later#L} -lt ${peak#L} ]]"
    pkill -f "hping3" 2>/dev/null       # stop the traffic early
    wait "${gens[@]}" 2>/dev/null       # not a bare wait: the web server is a job too
    pause
fi

# ---------------------------------------------------------------- 9
if step 9 "Stop the controller: the firewall keeps enforcing"; then
    if [[ -n ${ctl:-} ]]; then
        kill -INT $ctl; wait $ctl 2>/dev/null; ctl=
    else
        say "Ctrl-C the controller in the other terminal now."
        pause
        pkill -INT -f "python3 -m control[.]controller" 2>/dev/null
    fi
    sleep 1
    check "no controller process is running" no_controller
    show_tcp 10.10.1.3 8080
    check "the automatically blocked source is still cut off" [ "$last" = "no answer" ]
    run "$FW block list"
    run "ip link show veth-fw | grep -oE ' xdp(generic)? |prog/xdp.*'"
    say "The controller only decides. The kernel holds the rules, the deadlines and"
    say "the program, so they outlive it."
    pause
fi

echo -e "\n${B}done.${N} The firewall is still loaded. To clean up:"
echo "  sudo python3 -m control.fwctl reset --all"
echo "  sudo ./bin/fwload -i veth-fw -u && sudo ./bench/teardown_netns.sh"
[[ $failed -eq 0 ]]
