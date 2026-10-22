#!/usr/bin/env bash
# Benchmark: what the same firewall policy costs per packet with no firewall,
# with nftables and with the XDP firewall.
#
#   sudo ./bench/run_experiment.sh [--duration 15] [--repeat 3] [--senders "1 2"]
#        [--systems none,nftables,nft-ingress,xdp,xdp-empty] [--out results/run-X]
#   python3 bench/plot.py results/run-<stamp>
#
# Every system gets the same policy: allowlist, blocklist (10.10.1.3 and
# 10.10.1.5), TCP flag checks, deny tcp/23, per-source limit of 20000 pps
# with a burst of 40000. Two workloads, SYNs sent as fast as hping3 can by
# 1 or 2 senders for --duration seconds:
#
#   block   from the blocked addresses: every packet is dropped by the
#           first rule that applies to it
#   limit   from 10.10.1.6 and .7, which are not blocked, to tcp/80: the
#           packets go through every check and the rate limiter drops
#           what is over the limit
#
# Systems:
#   none         no firewall: every packet goes up the stack
#   nftables     nftables at prerouting, where firewalls normally filter
#   nft-ingress  nftables at the netdev ingress hook, its earliest point
#   xdp          this project
#   xdp-empty    an XDP program that only drops: the cost of delivering a
#                frame and running any XDP program at all (a baseline, not
#                a firewall)
#
# NIC-like delivery: the senders transmit on a separate veth pair (gen0/gen1)
# in the client namespace, and a one-line XDP program on gen1 redirects each
# frame into veth-cl. veth-fw then receives raw frames with no sk_buff, the
# way a network card's driver does (see bench/nic_path.bpf.c for why).
#
# Per run, as differences across the traffic window:
#   offered     packets sent on gen0
#   received    the veth-fw rx counter (counts before any filtering)
#   fw_dropped  the firewall's own drop counters
#   ip_in       IpInReceives from /proc/net/snmp: what reached the IP layer.
#               An independent check on the firewall's counters.
#   cpu         busy and softirq shares of all CPUs, from /proc/stat
#   ns_per_pkt  softirq CPU time / packets received. The receive path (XDP,
#               netfilter, IP, TCP) runs in softirq, so this is the CPU each
#               system spends per packet. Busy CPU is no use for comparing:
#               each hping3 sender spins on its own CPU whatever happens to
#               the packets.
#
# Use fewer senders than vCPUs, or the senders and the receive path compete.
set -uo pipefail
cd "$(dirname "$0")/.."

DURATION=15 REPEAT=3 SENDERS="1 2" SYSTEMS=none,nftables,nft-ingress,xdp,xdp-empty OUT=
WORKLOADS="block limit"
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)  DURATION=$2; shift 2 ;;
        --repeat)    REPEAT=$2; shift 2 ;;
        --senders)   SENDERS=$2; shift 2 ;;
        --systems)   SYSTEMS=$2; shift 2 ;;
        --workloads) WORKLOADS=$2; shift 2 ;;
        --out)       OUT=$2; shift 2 ;;     # add to an earlier run
        *) sed -n '2,7p' "$0"; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }
[[ -e /sys/class/net/veth-fw ]] || { echo "run sudo ./bench/setup_netns.sh first" >&2; exit 1; }
command -v hping3 >/dev/null || { echo "hping3 missing (./scripts/install_deps.sh)" >&2; exit 1; }

NS="ip netns exec fwtest" IFACE=veth-fw TARGET=10.10.1.1
BLOCKED=(10.10.1.3 10.10.1.5) UNBLOCKED=(10.10.1.6 10.10.1.7)
FW="python3 -m control.fwctl"
NFT=./bench/nftables_baseline.sh
HZ=$(getconf CLK_TCK)
BUILD=$(mktemp -d)

cleanup() {
    ./bin/fwload -i $IFACE -u >/dev/null 2>&1
    ip link set dev $IFACE xdpdrv off 2>/dev/null
    $NFT remove >/dev/null 2>&1
    $NS ip link del gen0 2>/dev/null
    ethtool -K $IFACE gro off 2>/dev/null
    rm -rf "$BUILD"
}
trap cleanup EXIT

# The NIC-like path. veth-fw needs GRO on to receive XDP frames when no XDP
# program is attached; with one attached the kernel turns it on anyway.
CFLAGS="-O2 -g -Wall -target bpf -I/usr/include/$(uname -m)-linux-gnu"
clang $CFLAGS -DTARGET_IFINDEX=$($NS cat /sys/class/net/veth-cl/ifindex) \
    -c bench/nic_path.bpf.c -o "$BUILD/redirect.o" &&
clang $CFLAGS -c bench/nic_path.bpf.c -o "$BUILD/empty.o" || exit 1
$NS ip link del gen0 2>/dev/null
Q=$(nproc)
$NS ip link add gen0 numtxqueues $Q numrxqueues $Q type veth peer name gen1 numtxqueues $Q numrxqueues $Q
for f in gro gso tso sg; do $NS ethtool -K gen0 $f off; $NS ethtool -K gen1 $f off; done >/dev/null 2>&1
$NS ip link set gen0 up && $NS ip link set gen1 up
$NS ip addr add 10.10.2.1/24 dev gen0
$NS ip route add $TARGET/32 dev gen0 src 10.10.2.1
$NS ip neigh replace $TARGET lladdr "$(cat /sys/class/net/$IFACE/address)" dev gen0 nud permanent
$NS ip link set dev gen1 xdpdrv obj "$BUILD/redirect.o" sec xdp || exit 1
ethtool -K $IFACE gro on >/dev/null

OUT=${OUT:-results/run-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
CSV=$OUT/results.csv
[[ -s $CSV ]] || echo "system,workload,senders,run,duration_s,offered,received,fw_dropped,ip_in,cpu_busy_pct,cpu_softirq_pct,ns_per_pkt" >"$CSV"
[[ -s $OUT/environment.txt ]] || {
    echo "kernel      $(uname -r)"
    echo "os          $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "cpus        $(nproc) x $(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
    echo "hypervisor  $(systemd-detect-virt 2>/dev/null || echo unknown)"
    echo "nftables    $(nft --version)"
    echo "settings    ${DURATION}s runs, $REPEAT repeats, senders: $SENDERS, workloads: $WORKLOADS"
} >"$OUT/environment.txt"

sent()    { $NS cat /sys/class/net/gen0/statistics/tx_packets; }
rx()      { cat /sys/class/net/$IFACE/statistics/rx_packets; }
ip_in()   { awk '$1 == "Ip:" { if (!c) { for (i = 2; i <= NF; i++) if ($i == "InReceives") c = i }
                                else print $c }' /proc/net/snmp; }
cpu_now() { awk '/^cpu / { t = 0; for (i = 2; i <= 9; i++) t += $i; print t, t - $5 - $6, $8 }' /proc/stat; }

drops() {
    case $1 in
        xdp)         $FW stats | tr -d , | awk '/^drop_/ { s += $2 } END { print s + 0 }' ;;
        nftables)    $NFT drops ;;
        nft-ingress) HOOK=ingress $NFT drops ;;
        *)           echo 0 ;;
    esac
}

use_system() {     # load one system with the policy and the blocklist
    local ip hook
    ./bin/fwload -i $IFACE -u >/dev/null 2>&1
    ip link set dev $IFACE xdpdrv off 2>/dev/null
    $NFT remove >/dev/null 2>&1
    case $1 in
        nftables|nft-ingress)
            [[ $1 == nft-ingress ]] && hook=ingress || hook=prerouting
            HOOK=$hook $NFT apply $IFACE >/dev/null || return 1
            for ip in "${BLOCKED[@]}"; do HOOK=$hook $NFT block $ip; done ;;
        xdp)
            ./bin/fwload -i $IFACE >/dev/null || return 1
            $FW port deny tcp 23 >/dev/null
            for ip in "${BLOCKED[@]}"; do $FW block add $ip --duration 0 >/dev/null; done ;;
        xdp-empty)
            ip link set dev $IFACE xdpdrv obj "$BUILD/empty.o" sec xdp || return 1 ;;
    esac
    sleep 1
}

run_one() {     # run_one <system> <workload> <senders> <run>
    local sys=$1 wl=$2 n=$3 run=$4 i pids=() src
    local tx0 rx0 d0 ip0 cpu0
    tx0=$(sent); rx0=$(rx); d0=$(drops $sys); ip0=$(ip_in); cpu0=$(cpu_now)

    for ((i = 0; i < n; i++)); do
        [[ $wl == block ]] && src=${BLOCKED[i % 2]} || src=${UNBLOCKED[i % 2]}
        $NS timeout "$DURATION" hping3 --flood -S -p 80 -I gen0 -a $src $TARGET \
            >/dev/null 2>&1 &
        pids+=($!)
    done
    wait "${pids[@]}"

    local cpu1 tx rxd dropped ipin cpu
    cpu1=$(cpu_now)
    tx=$(( $(sent) - tx0 )); rxd=$(( $(rx) - rx0 )); ipin=$(( $(ip_in) - ip0 ))
    # the empty program has no counters: whatever didn't reach IP was dropped
    if [[ $sys == xdp-empty ]]; then dropped=$(( rxd - ipin ))
    else dropped=$(( $(drops $sys) - d0 )); fi
    cpu=$(echo "$cpu0 $cpu1 $rxd $HZ" | awk '{
        d = $4 - $1; busy = $5 - $2; soft = $6 - $3
        if (d <= 0 || $7 <= 0) { print "0,0,0"; exit }
        printf "%.2f,%.2f,%.1f", 100 * busy / d, 100 * soft / d, soft / $8 * 1e9 / $7 }')

    echo "$sys,$wl,$n,$run,$DURATION,$tx,$rxd,$dropped,$ipin,$cpu" >>"$CSV"
    printf "    run %d: offered %d pps, dropped %d of %d, IP layer saw %d, %s ns per packet\n" \
        "$run" $((tx / DURATION)) "$dropped" "$rxd" "$ipin" "${cpu##*,}"
}

echo "benchmark: ${DURATION}s x $REPEAT runs -> $OUT/"
for sys in ${SYSTEMS//,/ }; do
    echo "== $sys"
    use_system "$sys" || { echo "   could not set up $sys" >&2; continue; }
    for wl in $WORKLOADS; do
        [[ $sys == xdp-empty && $wl != block ]] && continue    # one baseline is enough
        for n in $SENDERS; do
            echo "  $wl, $n sender(s)"
            for run in $(seq "$REPEAT"); do
                # fresh rate-limit buckets every run
                if [[ $sys == xdp ]]; then $FW reset >/dev/null
                elif [[ $sys == nft* ]]; then use_system "$sys"; fi
                run_one "$sys" "$wl" "$n" "$run"
                sleep 2
            done
        done
    done
done

echo
echo "done. summary and chart: python3 bench/plot.py $OUT"
