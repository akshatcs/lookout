#!/usr/bin/env bash
# Block any IPv4 address or prefix someone names, and prove it on the testbed.
#
#   sudo ./scripts/block_ip.sh 8.8.8.8            block for 120 s
#   sudo ./scripts/block_ip.sh 203.0.113.0/24 0   block a prefix permanently
#
# The testbed is a closed network, so nothing from that address would ever
# arrive. The script therefore sends packets with that source address from
# the client namespace (hping3 -a), five before the block and five after,
# and lets tcpdump on veth-fw count them. tcpdump sees what the network
# stack sees, so it should count 5 and then 0.
set -u
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "run with sudo: sudo $0 $*" >&2; exit 1; }
[[ $# -ge 1 ]] || { sed -n '2,5p' "$0"; exit 1; }

TARGET=$1 DURATION=${2:-120}
FW="python3 -m control.fwctl"
NS="ip netns exec fwtest"

# normalises the prefix, or fails with a clear message
NET=$(python3 -c "
import sys
from control.firewall import parse_cidr
try:
    print(parse_cidr(sys.argv[1]))
except ValueError as e:
    sys.exit(f'error: {e}')" "$TARGET") || exit 1
SRC=${NET%/*}       # the first address in the prefix stands in for the sender

[[ -e /sys/class/net/veth-fw ]] || ./bench/setup_netns.sh >/dev/null || exit 1
[[ -e /sys/fs/bpf/adaptfw/config ]] || ./bin/fwload -i veth-fw >/dev/null || exit 1
$FW block del "$NET" >/dev/null 2>&1

count() {   # count: send 5 SYNs from $SRC, print how many tcpdump saw
    local out tp
    out=$(mktemp)
    tcpdump -ni veth-fw -c 50 "src host $SRC" >"$out" 2>/dev/null & tp=$!
    sleep 1
    $NS hping3 -q -c 5 -i u100000 -S -p 80 -a "$SRC" 10.10.1.1 >/dev/null 2>&1
    sleep 1; kill $tp 2>/dev/null; wait $tp 2>/dev/null
    grep -c . "$out"; rm -f "$out"
}

echo "before the block: 5 packets from $SRC, tcpdump saw $(count)"
echo "\$ $FW block add $NET --duration $DURATION"
$FW block add "$NET" --duration "$DURATION"
echo "after the block:  5 packets from $SRC, tcpdump saw $(count)"
$FW block list
echo "remove it with: sudo $FW block del $NET"
