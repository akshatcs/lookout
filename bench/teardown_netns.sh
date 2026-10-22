#!/usr/bin/env bash
# Remove the testbed. Safe to run more than once. Pinned maps are left
# alone; use `sudo ./bin/fwload -i veth-fw -u` first to remove those.
[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }
ip link del veth-fw 2>/dev/null && echo "deleted veth-fw"
ip netns del fwtest 2>/dev/null && echo "deleted namespace fwtest"
exit 0
