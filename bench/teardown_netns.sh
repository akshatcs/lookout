#!/usr/bin/env bash
# Remove the test topology. Safe to run repeatedly and safe to run even if
# setup never completed -- every step tolerates the object not existing.
set -uo pipefail

NS="${NS:-fwtest}"
VETH_FW="${VETH_FW:-veth-fw}"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

# Detach XDP before deleting the interface. Not strictly required (deleting
# the link frees the program too) but it keeps `bpftool prog show` tidy and
# makes the teardown explicit.
if ip link show "$VETH_FW" >/dev/null 2>&1; then
    ip link set dev "$VETH_FW" xdp off 2>/dev/null || true
    echo "detached XDP from $VETH_FW"
fi

# Deleting one end of a veth pair deletes both, and deleting the namespace
# would take the peer with it anyway.
ip link del "$VETH_FW" 2>/dev/null && echo "deleted $VETH_FW" || true
ip netns del "$NS" 2>/dev/null && echo "deleted namespace $NS" || true

echo "teardown complete"
echo "note: pinned maps in /sys/fs/bpf/adaptfw are NOT removed by this script."
echo "      clear them with: sudo ./bin/fwload -i $VETH_FW -u"
