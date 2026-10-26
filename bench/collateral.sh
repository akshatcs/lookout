#!/usr/bin/env bash
# Experiment 1: what a normal user experiences during an attack.
#
#   sudo ./bench/setup_netns.sh
#   sudo ./bench/collateral.sh [--repeat 3] [--attacks "single spread random"]
#        [--systems "none nft-ingress xdp xdp-adaptive"] [--out results/collateral-X]
#   python3 bench/eval_report.py results/collateral-X
#
# A web server runs on the firewall host, and a client (10.10.1.2) requests
# a page ten times a second for 60 s, logging every request. From second 10
# to second 50 one hping3 sender attacks at full speed through the NIC-like
# path (bench/nic_path.sh), from addresses in 198.18.0.0/15:
#
#   single  SYN flood on the web port from one address
#   spread  UDP flood spread over 100 addresses; each sends a few thousand
#           packets a second, under every per-source threshold
#   random  SYN flood on the web port from 65,000 random addresses, a few
#           packets each: what per-source defences can't handle
#
# Systems: no firewall; nftables at ingress with the same policy and a fixed
# per-source limit (bench/nftables_baseline.sh); the XDP firewall with its
# fixed default limit and no controller; and the XDP firewall with the
# adaptive controller running.
set -uo pipefail
cd "$(dirname "$0")/.."

REPEAT=3 ATTACKS="single spread random" SYSTEMS="none nft-ingress xdp xdp-adaptive" OUT=
while [[ $# -gt 0 ]]; do
    case $1 in
        --repeat)  REPEAT=$2; shift 2 ;;
        --attacks) ATTACKS=$2; shift 2 ;;
        --systems) SYSTEMS=$2; shift 2 ;;
        --out)     OUT=$2; shift 2 ;;
        *) sed -n '2,8p' "$0"; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }
[[ -e /sys/class/net/veth-fw ]] || { echo "run sudo ./bench/setup_netns.sh first" >&2; exit 1; }
command -v hping3 >/dev/null || { echo "hping3 missing (./scripts/install_deps.sh)" >&2; exit 1; }

NS="ip netns exec fwtest" IFACE=veth-fw
FW="python3 -m control.fwctl"
NFT=./bench/nftables_baseline.sh
WEB=$(mktemp -d)
server= ctl=

stop_firewalls() {
    [[ -n $ctl ]] && { kill -INT "$ctl" 2>/dev/null; wait "$ctl" 2>/dev/null; ctl=; }
    ./bin/fwload -i $IFACE -u >/dev/null 2>&1
    $NFT remove >/dev/null 2>&1
}
cleanup() {
    pkill -x hping3 2>/dev/null
    stop_firewalls
    [[ -n $server ]] && kill "$server" 2>/dev/null
    ./bench/nic_path.sh down
    rm -rf "$WEB"
}
trap cleanup EXIT

# a page about the size of a small HTML document
head -c 2048 /dev/urandom | base64 >"$WEB/index.html"
python3 bench/clients.py serve "$WEB" & server=$!
sleep 1

OUT=${OUT:-results/collateral-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
[[ -s $OUT/environment.txt ]] || {
    echo "kernel      $(uname -r)"
    echo "cpus        $(nproc) x $(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
    echo "hypervisor  $(systemd-detect-virt 2>/dev/null || echo unknown)"
    echo "settings    60 s runs, attack from 10 s to 50 s, $REPEAT repeats"
} >"$OUT/environment.txt"
[[ -s $OUT/runs.csv ]] ||
    echo "system,attack,run,attack_start,attack_pps,ip_pps,softirq_pct" >"$OUT/runs.csv"

# what reached the IP layer, and the share of all CPU time spent in softirq
# (the receive path), over the attack
ip_in()   { awk '$1 == "Ip:" { if (!c) { for (i = 2; i <= NF; i++) if ($i == "InReceives") c = i }
                                else print $c }' /proc/net/snmp; }
cpu_now() { awk '/^cpu / { t = 0; for (i = 2; i <= 9; i++) t += $i; print t, $8 }' /proc/stat; }

use_system() {
    stop_firewalls
    case $1 in
        nft-ingress)
            HOOK=ingress $NFT apply $IFACE >/dev/null ;;
        xdp|xdp-adaptive)
            ./bin/fwload -i $IFACE >/dev/null && $FW reset --all >/dev/null ||
                { echo "could not load the XDP firewall" >&2; exit 1; } ;;
    esac
    if [[ $1 == xdp-adaptive ]]; then
        python3 -m control.controller >"$OUT/controller-$2.log" 2>&1 & ctl=$!
        sleep 3                     # let it take a baseline
    fi
}

for attack in $ATTACKS; do
    case $attack in
        single) spread=1;     flood=(-S -p 8080) ;;
        spread) spread=100;   flood=(--udp -p 9 -d 100) ;;
        random) spread=65000; flood=(-S -p 8080) ;;
        *) echo "unknown attack $attack" >&2; exit 1 ;;
    esac
    ./bench/nic_path.sh up $spread || exit 1
    for sys in $SYSTEMS; do
        for run in $(seq "$REPEAT"); do
            tag=$sys-$attack-$run
            echo "$tag"
            use_system "$sys" "$tag"
            watcher=
            if [[ $sys == xdp* ]]; then
                python3 bench/clients.py watch 61 "$OUT/watch-$tag.csv" & watcher=$!
            fi
            $NS python3 bench/clients.py probe 60 "$OUT/probe-$tag.csv" & probe=$!
            sleep 10
            tx0=$($NS cat /sys/class/net/gen0/statistics/tx_packets)
            ip0=$(ip_in); cpu0=$(cpu_now)
            start=$(date +%s.%N)
            $NS timeout 40 hping3 --flood "${flood[@]}" -I gen0 10.10.1.1 >/dev/null 2>&1
            tx=$(( $($NS cat /sys/class/net/gen0/statistics/tx_packets) - tx0 ))
            ipps=$(( ($(ip_in) - ip0) / 40 ))
            soft=$(echo "$cpu0 $(cpu_now)" | awk '{ printf "%.1f", 100 * ($4 - $2) / ($3 - $1) }')
            wait "$probe" $watcher
            echo "$sys,$attack,$run,$start,$((tx / 40)),$ipps,$soft" >>"$OUT/runs.csv"
            stop_firewalls
            sleep 3
        done
    done
done
echo "done. summary and chart: python3 bench/eval_report.py $OUT"
