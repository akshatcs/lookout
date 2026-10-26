#!/usr/bin/env bash
# Experiment 2: how well the controller tells attackers from normal clients.
#
#   sudo ./bench/setup_netns.sh
#   sudo ./bench/detection.sh [--repeat 3] [--seconds 30] [--only attacks|normal]
#        [--out results/detection-X]
#   python3 bench/eval_report.py results/detection-X
#
# Every run starts the controller on a freshly reset firewall, sends one kind
# of traffic from one address for --seconds, and records the rate the
# firewall received and, from the watcher and the controller's log, whether
# and when that address was blocked and by which rule.
#
# Attacks, from 198.18.0.1 through the NIC-like path, at rates from below
# their rule's threshold to well above it:
#   syn_flood   SYNs to tcp/80           udp_flood   100-byte UDP to udp/53
#   icmp_flood  echo requests            port_scan   SYNs to ports 1, 2, 3...
# Normal clients (bench/clients.py, from 10.10.1.2), each chosen because it
# resembles an attack in some way:
#   browse      page loads of 20 requests every 2 s
#   download    a large file over and over (a stream of small ACKs back)
#   upload      a large upload (full-size packets)
#   nat-100, nat-1000   that many people behind one address
#   udp-1000, udp-10000 small UDP datagrams, like a DNS client or resolver
#   services    one connection a second, each to a different port
set -uo pipefail
cd "$(dirname "$0")/.."

REPEAT=3 SECS=30 ONLY= OUT=
while [[ $# -gt 0 ]]; do
    case $1 in
        --repeat)  REPEAT=$2; shift 2 ;;
        --seconds) SECS=$2; shift 2 ;;
        --only)    ONLY=$2; shift 2 ;;
        --out)     OUT=$2; shift 2 ;;
        *) sed -n '2,7p' "$0"; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }
[[ -e /sys/class/net/veth-fw ]] || { echo "run sudo ./bench/setup_netns.sh first" >&2; exit 1; }
command -v hping3 >/dev/null || { echo "hping3 missing (./scripts/install_deps.sh)" >&2; exit 1; }

NS="ip netns exec fwtest" IFACE=veth-fw
FW="python3 -m control.fwctl"
WEB=$(mktemp -d)
server= ctl=

cleanup() {
    pkill -x hping3 2>/dev/null
    [[ -n $ctl ]] && kill -INT "$ctl" 2>/dev/null
    [[ -n $server ]] && kill "$server" 2>/dev/null
    ./bin/fwload -i $IFACE -u >/dev/null 2>&1
    ./bench/nic_path.sh down
    rm -rf "$WEB"
}
trap cleanup EXIT

head -c 2048 /dev/urandom | base64 >"$WEB/index.html"
head -c 50M /dev/zero >"$WEB/big.bin"
python3 bench/clients.py serve "$WEB" 9000 $(seq 9001 9030) & server=$!
./bin/fwload -i $IFACE >/dev/null || { echo "could not load the XDP firewall" >&2; exit 1; }
./bench/nic_path.sh up 1 || exit 1          # attacks come from 198.18.0.1

OUT=${OUT:-results/detection-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
[[ -s $OUT/environment.txt ]] || {
    echo "kernel      $(uname -r)"
    echo "cpus        $(nproc) x $(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
    echo "hypervisor  $(systemd-detect-virt 2>/dev/null || echo unknown)"
    echo "settings    ${SECS} s runs, $REPEAT repeats"
} >"$OUT/environment.txt"
[[ -s $OUT/runs.csv ]] ||
    echo "kind,traffic,setting,run,source,start,rx_pps,mean_bytes" >"$OUT/runs.csv"

rx()  { cat /sys/class/net/$IFACE/statistics/rx_packets; }
rxb() { cat /sys/class/net/$IFACE/statistics/rx_bytes; }

run_one() {     # run_one <kind> <traffic> <setting> <run> <source> <command...>
    local kind=$1 traffic=$2 setting=$3 run=$4 src=$5 tag watcher r0 b0 start r
    shift 5
    tag=$traffic-$setting-$run
    echo "$tag"
    $FW reset --all >/dev/null
    python3 -m control.controller >"$OUT/controller-$tag.log" 2>&1 & ctl=$!
    sleep 3                         # let it take a baseline
    python3 bench/clients.py watch $((SECS + 2)) "$OUT/watch-$tag.csv" & watcher=$!
    r0=$(rx); b0=$(rxb); start=$(date +%s.%N)
    $NS timeout "$SECS" "$@" >/dev/null 2>&1
    r=$(( $(rx) - r0 ))
    echo "$kind,$traffic,$setting,$run,$src,$start,$((r / SECS)),$(( r ? ($(rxb) - b0) / r : 0 ))" \
        >>"$OUT/runs.csv"
    wait "$watcher"
    kill -INT "$ctl"; wait "$ctl" 2>/dev/null; ctl=
}

attack() {      # attack <traffic> <setting> <run> <hping3 args...>
    local traffic=$1 setting=$2 run=$3
    shift 3
    run_one attack "$traffic" "$setting" "$run" 198.18.0.1 hping3 "$@" -I gen0 10.10.1.1
}

# hping3 interval for a rate, or --flood
iv() { [[ $1 == max ]] && echo --flood || echo "-i u$((1000000 / $1))"; }

for run in $(seq "$REPEAT"); do
    if [[ $ONLY != normal ]]; then
        for r in 20 50 100 1000 10000 max;  do attack syn_flood  "$r" "$run" $(iv $r) -S -p 80; done
        for r in 2000 4000 7000 10000 20000 max; do attack udp_flood "$r" "$run" $(iv $r) --udp -p 53 -d 100; done
        for r in 500 1500 2500 5000 max;    do attack icmp_flood "$r" "$run" $(iv $r) --icmp; done
        for r in 5 20 100 500;              do attack port_scan  "$r" "$run" $(iv $r) -S -p ++1; done
    fi
    if [[ $ONLY != attacks ]]; then
        C="python3 bench/clients.py"
        run_one normal browse   -     "$run" 10.10.1.2 $C browse "$SECS"
        run_one normal download -     "$run" 10.10.1.2 $C download "$SECS"
        run_one normal upload   -     "$run" 10.10.1.2 $C upload "$SECS"
        run_one normal nat      100   "$run" 10.10.1.2 $C nat "$SECS" 100
        run_one normal nat      1000  "$run" 10.10.1.2 $C nat "$SECS" 1000
        run_one normal udp      1000  "$run" 10.10.1.2 $C udp "$SECS" 1000
        run_one normal udp      10000 "$run" 10.10.1.2 $C udp "$SECS" 10000
        run_one normal services -     "$run" 10.10.1.2 $C services "$SECS"
    fi
done
echo "done. summary: python3 bench/eval_report.py $OUT"
