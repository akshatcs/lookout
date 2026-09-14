#!/usr/bin/env bash
# =============================================================================
# install_deps.sh -- install everything the project needs on Ubuntu Server.
#
# Tested on Ubuntu 22.04 and 24.04. Run once:
#     ./scripts/install_deps.sh
#
# The packages fall into four groups:
#   build     clang/llvm to compile eBPF, gcc to compile the loader
#   bpf       libbpf headers, bpftool for inspection
#   traffic   hping3 / iperf3 to generate load, sysstat for CPU measurement
#   python    scikit-learn for the model (optional but wanted)
# =============================================================================
set -euo pipefail

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

echo "=== detecting distribution ==="
. /etc/os-release 2>/dev/null || true
echo "  ${PRETTY_NAME:-unknown}"
echo "  kernel $(uname -r)"

KVER=$(uname -r | cut -d. -f1,2)
KMAJOR=${KVER%%.*}
KMINOR=${KVER##*.}
if (( KMAJOR < 5 || (KMAJOR == 5 && KMINOR < 10) )); then
    echo "WARNING: kernel $KVER is old. This project needs 5.10+ for reliable" >&2
    echo "         BPF spin locks and LPM tries. 5.15+ is strongly preferred." >&2
fi

echo
echo "=== updating package lists ==="
$SUDO apt-get update -qq

echo
echo "=== installing build + BPF toolchain ==="
$SUDO apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    gcc-multilib \
    pkg-config

# bpftool ships under different names depending on release. Try each.
echo
echo "=== installing bpftool ==="
if ! command -v bpftool >/dev/null; then
    $SUDO apt-get install -y bpftool 2>/dev/null \
      || $SUDO apt-get install -y "linux-tools-$(uname -r)" 2>/dev/null \
      || $SUDO apt-get install -y linux-tools-common linux-tools-generic 2>/dev/null \
      || echo "  note: bpftool unavailable; it is useful for inspection but not required"
fi

echo
echo "=== installing traffic generation + measurement tools ==="
$SUDO apt-get install -y --no-install-recommends \
    hping3 \
    iperf3 \
    iproute2 \
    ethtool \
    nftables \
    sysstat \
    tcpdump \
    tmux \
    curl

echo
echo "=== installing Python tooling ==="
$SUDO apt-get install -y --no-install-recommends python3 python3-pip

# Ubuntu 24.04 marks the system Python as externally managed (PEP 668), so a
# plain `pip install` fails. Prefer distro packages, and fall back to pip with
# the override only if those are unavailable.
if ! python3 -c "import sklearn" 2>/dev/null; then
    echo "  installing scikit-learn..."
    if ! $SUDO apt-get install -y python3-sklearn python3-numpy python3-joblib 2>/dev/null \
        && ! pip3 install --break-system-packages scikit-learn joblib numpy 2>/dev/null \
        && ! pip3 install scikit-learn joblib numpy 2>/dev/null; then
        echo "  WARNING: scikit-learn not installed. The firewall still works;"
        echo "           run the controller with --no-ml to use thresholds."
    fi
fi

python3 -c "import matplotlib" 2>/dev/null || \
  $SUDO apt-get install -y python3-matplotlib 2>/dev/null || \
  echo "  note: matplotlib missing; bench/plot.py will emit text only"

echo
echo "=== mounting bpffs if needed ==="
if ! mount | grep -q "type bpf"; then
    $SUDO mount -t bpf bpf /sys/fs/bpf && echo "  mounted /sys/fs/bpf"
    echo "  (to make this permanent, add to /etc/fstab:)"
    echo "    bpffs /sys/fs/bpf bpf defaults 0 0"
else
    echo "  /sys/fs/bpf already mounted"
fi

echo
echo "=== verification ==="
ok=0; bad=0
check() {
    if command -v "$1" >/dev/null 2>&1; then
        printf "  %-14s %s\n" "$1" "OK"; ok=$((ok+1))
    else
        printf "  %-14s %s\n" "$1" "MISSING"; bad=$((bad+1))
    fi
}
for t in clang gcc hping3 iperf3 nft ethtool mpstat tmux; do check "$t"; done

if python3 -c "import sklearn" 2>/dev/null; then
    printf "  %-14s %s\n" "scikit-learn" "OK"
else
    printf "  %-14s %s\n" "scikit-learn" "MISSING (use --no-ml)"
fi

echo
if (( bad == 0 )); then
    echo "all dependencies present."
else
    echo "$bad tool(s) missing -- see above."
fi
echo
echo "next:  make"
