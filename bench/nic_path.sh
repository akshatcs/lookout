#!/usr/bin/env bash
# The NIC-like delivery path used by the benchmark and the evaluation.
#
#   sudo ./bench/nic_path.sh up [n]    then send with: hping3 -I gen0 ...
#   sudo ./bench/nic_path.sh down
#
# hping3 sends on gen0, a veth pair of its own in the client namespace, and
# an XDP program on the far end (gen1) redirects every frame into veth-cl.
# veth-fw then receives raw frames with no sk_buff, as from a network card
# (bench/nic_path.bpf.c explains why that matters).
#
# With n, every packet also gets a random source address from 198.18.0.1 to
# 198.18.0.0+n, so one hping3 acts as n senders. The firewall host routes
# 198.18.0.0/15 back into the client namespace, which doesn't forward, so
# replies to those addresses go nowhere and never reach a real network.
set -euo pipefail
cd "$(dirname "$0")/.."

NS="ip netns exec fwtest" IFACE=veth-fw TARGET=10.10.1.1
[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }

down() {
    $NS ip link del gen0 2>/dev/null || true
    ip route del 198.18.0.0/15 2>/dev/null || true
}

case ${1:-} in
up)
    [[ -e /sys/class/net/$IFACE ]] || { echo "run sudo ./bench/setup_netns.sh first" >&2; exit 1; }
    down
    build=$(mktemp -d); trap 'rm -rf "$build"' EXIT
    spread=${2:+-DSPREAD=$2}
    clang -O2 -g -Wall -target bpf -I/usr/include/"$(uname -m)"-linux-gnu $spread \
        -DTARGET_IFINDEX="$($NS cat /sys/class/net/veth-cl/ifindex)" \
        -c bench/nic_path.bpf.c -o "$build/redirect.o"
    Q=$(nproc)
    $NS ip link add gen0 numtxqueues "$Q" numrxqueues "$Q" type veth \
        peer name gen1 numtxqueues "$Q" numrxqueues "$Q"
    for f in gro gso tso sg; do
        $NS ethtool -K gen0 $f off; $NS ethtool -K gen1 $f off
    done >/dev/null 2>&1 || true
    $NS ip link set gen0 up
    $NS ip link set gen1 up
    $NS ip addr add 10.10.2.1/24 dev gen0
    $NS ip route add $TARGET/32 dev gen0 src 10.10.2.1
    $NS ip neigh replace $TARGET lladdr "$(cat /sys/class/net/$IFACE/address)" \
        dev gen0 nud permanent
    $NS ip link set dev gen1 xdpdrv obj "$build/redirect.o" sec xdp
    ip route replace 198.18.0.0/15 via 10.10.1.2 dev $IFACE
    # veth-fw needs GRO on to receive XDP frames when no XDP program is
    # attached to it; with one attached the kernel turns it on anyway
    ethtool -K $IFACE gro on >/dev/null
    ;;
down)
    down
    ethtool -K $IFACE gro off >/dev/null 2>&1 || true
    ;;
*)
    sed -n '2,15p' "$0"; exit 1 ;;
esac
