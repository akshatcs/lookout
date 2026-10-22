#!/usr/bin/env bash
# Build the test network inside one VM:
#
#   netns fwtest                         root namespace
#   veth-cl 10.10.1.2/.3/.4  <======>  veth-fw 10.10.1.1   <- XDP goes here
#   (traffic comes from here)
#
# veth supports native XDP, so the program runs in a real driver receive
# path. The three client addresses let you show different sources being
# treated differently at the same time. Your SSH session uses a different
# interface and isn't affected.
set -euo pipefail

NS=fwtest
[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }

ip netns del $NS 2>/dev/null || true
ip link del veth-fw 2>/dev/null || true

ip netns add $NS
# One queue pair per CPU, like a NIC with RSS. With a single queue every
# sender funnels into one XDP receive ring, which serialises the XDP path
# (but not the non-XDP one) as soon as there is more than one sender.
Q=$(nproc)
ip link add veth-fw numtxqueues $Q numrxqueues $Q type veth \
    peer name veth-cl numtxqueues $Q numrxqueues $Q
ip link set veth-cl netns $NS

ip addr add 10.10.1.1/24 dev veth-fw
ip link set veth-fw up

ip netns exec $NS ip link set lo up
ip netns exec $NS ip addr add 10.10.1.2/24 dev veth-cl
ip netns exec $NS ip addr add 10.10.1.3/24 dev veth-cl noprefixroute
ip netns exec $NS ip addr add 10.10.1.4/24 dev veth-cl noprefixroute
ip netns exec $NS ip link set veth-cl up

# Without this, veth hands XDP large merged packets (GRO/GSO): counters read
# far lower than what was sent, and native attach can fail.
for f in gro gso tso lro sg tx-udp-segmentation; do
    ethtool -K veth-fw $f off 2>/dev/null || true
    ip netns exec $NS ethtool -K veth-cl $f off 2>/dev/null || true
done

if ip netns exec $NS ping -c 2 -W 2 10.10.1.1 >/dev/null; then
    echo "testbed ready: veth-fw 10.10.1.1 <-> netns $NS (10.10.1.2, .3, .4)"
    echo "next: sudo ./bin/fwload -i veth-fw"
else
    echo "testbed created but ping failed; check 'ip netns exec $NS ip addr'" >&2
    exit 1
fi
