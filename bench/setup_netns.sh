#!/usr/bin/env bash
# =============================================================================
# setup_netns.sh -- build the test topology inside one Ubuntu VM.
#
# WHY NETWORK NAMESPACES
# ---------------------------------------------------------------------------
# The project needs a "client" host and a "firewall" host on the same link, so
# we can send attack traffic at an interface running XDP. Two VMs would work
# but are slow to set up and hard to replicate.
#
# Network namespaces give us the same thing inside a single VM: a veth pair is
# a virtual cable with an interface at each end, and we put one end in an
# isolated namespace. Crucially, the veth driver supports NATIVE XDP, so the
# program runs in the driver receive path exactly as it would on real hardware
# -- not in the slower generic/SKB fallback.
#
#   +---------------------------+          +------------------------------+
#   |  netns: fwtest            |          |  root namespace              |
#   |                           |          |                              |
#   |  veth-cl   10.10.1.2/24   |==========|  veth-fw   10.10.1.1/24      |
#   |            10.10.1.3      |   veth   |            <-- XDP HERE      |
#   |            10.10.1.4      |   pair   |                              |
#   |  (traffic generators)     |          |  (the protected "server")    |
#   +---------------------------+          +------------------------------+
#
# Three addresses on the client side let us demonstrate per-source behaviour:
# allowlist .2, let .3 get rate limited, let .4 get blocked by the model --
# all at the same time, all visible in one screen.
#
# Our SSH SESSION IS SAFE. It runs over a completely different interface
# (enp0s3 or similar). Nothing here touches it, and the XDP program is only
# ever attached to veth-fw.
# =============================================================================

set -euo pipefail

NS="${NS:-fwtest}"
VETH_FW="${VETH_FW:-veth-fw}"
VETH_CL="${VETH_CL:-veth-cl}"
SUBNET="${SUBNET:-10.10.1}"
FW_IP="${SUBNET}.1"
CLIENT_IPS=("${SUBNET}.2" "${SUBNET}.3" "${SUBNET}.4")

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

echo "=== tearing down any previous setup ==="
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_FW" 2>/dev/null || true
sleep 0.2

echo "=== creating namespace '$NS' and the veth pair ==="
ip netns add "$NS"
ip link add "$VETH_FW" type veth peer name "$VETH_CL"
ip link set "$VETH_CL" netns "$NS"

echo "=== addressing the firewall side ($FW_IP) ==="
ip addr add "${FW_IP}/24" dev "$VETH_FW"
ip link set "$VETH_FW" up

echo "=== addressing the client side ==="
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "${CLIENT_IPS[0]}/24" dev "$VETH_CL"
for ip_extra in "${CLIENT_IPS[@]:1}"; do
    # Secondary addresses. `noprefixroute` stops each alias adding a duplicate
    # route for the same /24, which otherwise clutters the routing table.
    ip netns exec "$NS" ip addr add "${ip_extra}/24" dev "$VETH_CL" noprefixroute
done
ip netns exec "$NS" ip link set "$VETH_CL" up
ip netns exec "$NS" ip route add default via "$FW_IP" 2>/dev/null || true

# -----------------------------------------------------------------------------
# Offload settings. THIS IS THE STEP PEOPLE SKIP AND THEN SPEND HOURS DEBUGGING.
#
# By default veth does GRO/GSO, so the kernel hands XDP one large aggregated
# "packet" instead of the individual frames on the wire. Two consequences:
#   * the packet counters read far lower than the traffic we are generating,
#     which looks like the firewall is silently dropping things;
#   * native XDP attach can fail outright, because an XDP program cannot be
#     given a multi-buffer frame unless it declared support for it.
#
# Turning these off makes the virtual link behave like a plain physical NIC.
# -----------------------------------------------------------------------------
echo "=== disabling offloads (required for sane XDP behaviour) ==="
# Only the segmentation/aggregation offloads matter for XDP. Checksum
# offload (tx/rx) is irrelevant here and turning it off on veth is an
# unnecessary risk, so it is deliberately left alone.
for feature in gro gso tso lro sg tx-udp-segmentation; do
    ethtool -K "$VETH_FW" "$feature" off 2>/dev/null || true
    ip netns exec "$NS" ethtool -K "$VETH_CL" "$feature" off 2>/dev/null || true
done

ip link set "$VETH_FW" mtu 1500
ip netns exec "$NS" ip link set "$VETH_CL" mtu 1500

# Stop the host replying to the flood at the IP layer where we can avoid it:
# an ICMP flood that generates an equal volume of ICMP replies measures your
# transmit path as much as the firewall.
sysctl -qw net.ipv4.icmp_echo_ignore_broadcasts=1

echo
echo "=== verifying connectivity ==="
if ip netns exec "$NS" ping -c 2 -W 2 "$FW_IP" >/dev/null 2>&1; then
    echo "OK: ${CLIENT_IPS[0]} can reach $FW_IP"
else
    echo "WARNING: ping failed. Check 'ip netns exec $NS ip addr' and that no" >&2
    echo "         firewall rule on the host is dropping the traffic." >&2
fi

cat <<EOF

=========================================================================
 testbed ready
=========================================================================
  namespace      : $NS
  firewall iface : $VETH_FW  ($FW_IP)   <-- attach XDP here
  client addrs   : ${CLIENT_IPS[*]}

 Load the firewall:
   sudo ./bin/fwload -i $VETH_FW

 Send traffic from the client side by prefixing commands with:
   sudo ip netns exec $NS <command>

 For example:
   sudo ip netns exec $NS ping -c 3 $FW_IP
   sudo ip netns exec $NS hping3 --flood -S -p 80 $FW_IP
   sudo ip netns exec $NS hping3 --flood -S -a ${CLIENT_IPS[1]} -p 80 $FW_IP

 Tear down when finished:
   sudo ./bench/teardown_netns.sh
=========================================================================
EOF
