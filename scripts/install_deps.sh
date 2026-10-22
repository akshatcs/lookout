#!/usr/bin/env bash
# Install everything needed on Ubuntu 22.04 / 24.04, then run `make`.
set -euo pipefail

SUDO=; [[ $EUID -eq 0 ]] || SUDO=sudo
export DEBIAN_FRONTEND=noninteractive   # no install-time questions

echo "kernel $(uname -r) (5.10 or newer needed)"

$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
    build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config \
    iproute2 ethtool iputils-ping hping3 tcpdump nftables curl \
    python3 python3-matplotlib

# bpftool is handy for poking at the maps but not required; its package
# name differs between releases.
command -v bpftool >/dev/null ||
    $SUDO apt-get install -y bpftool 2>/dev/null ||
    $SUDO apt-get install -y "linux-tools-$(uname -r)" linux-tools-common 2>/dev/null ||
    echo "bpftool not installed (optional)"

if ! mount | grep -q 'type bpf'; then
    $SUDO mount -t bpf bpf /sys/fs/bpf
    echo "mounted /sys/fs/bpf (add 'bpffs /sys/fs/bpf bpf defaults 0 0' to /etc/fstab to keep it)"
fi

missing=0
for t in clang gcc hping3 tcpdump nft ethtool ip curl; do
    command -v $t >/dev/null || { echo "missing: $t"; missing=1; }
done
[[ $missing == 0 ]] && echo "all set. next: make"
