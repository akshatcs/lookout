#!/usr/bin/env bash
# Send one kind of traffic from the client namespace at the firewall.
#
#   sudo ./bench/gen_traffic.sh <class> [seconds] [source-ip]
#
# Normal:      game (steady 60 pps UDP to one port)
# Misbehaving: syn_flood, low_slow_syn (~200 pps, under any pps threshold),
#              udp_flood, icmp_flood, port_scan
#
# source-ip forges the source address (hping3 -a), e.g. 10.10.1.3.
set -uo pipefail

NS=${NS:-fwtest}
TARGET=${TARGET:-10.10.1.1}
CLASS=${1:-}
SECS=${2:-60}
SRC=${3:-}

[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }
[[ -n $CLASS ]] || { sed -n '2,10p' "$0"; exit 1; }

spoof=()
[[ -n $SRC ]] && spoof=(-a "$SRC")

run() { ip netns exec "$NS" timeout "$SECS" "$@" >/dev/null 2>&1; }

echo "sending $CLASS to $TARGET for ${SECS}s ${SRC:+from $SRC}"
case $CLASS in
    game)         run hping3 --udp -p 27015 -d 80 -i u16666 "${spoof[@]}" "$TARGET" ;;
    syn_flood)    run hping3 --flood -S -p 80 "${spoof[@]}" "$TARGET" ;;
    low_slow_syn) run hping3 -S -p 80 -i u5000 "${spoof[@]}" "$TARGET" ;;
    udp_flood)    run hping3 --flood --udp -p 53 -d 100 "${spoof[@]}" "$TARGET" ;;
    icmp_flood)   run hping3 --flood --icmp "${spoof[@]}" "$TARGET" ;;
    port_scan)    run hping3 -S --scan 1-1024 -i u2000 "${spoof[@]}" "$TARGET" ;;
    *) echo "unknown class: $CLASS" >&2; sed -n '2,10p' "$0"; exit 1 ;;
esac
echo "done"