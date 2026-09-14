#!/usr/bin/env bash
# =============================================================================
# gen_traffic.sh -- generate one named traffic class, for demos and for
# building a real (non-synthetic) training set.
#
#   sudo ./bench/gen_traffic.sh <class> [duration] [source-ip]
#
# Benign classes:
#   web          bursty TCP with real connections (needs a listener)
#   bulk         high-throughput transfer (iperf3)
#   game         steady small UDP at a fixed rate to one port
#   dns          low-rate small UDP
#   ping         ICMP echo
#
# Attack classes:
#   syn_flood    high-rate SYN flood
#   low_slow_syn low-rate SYN flood -- the class a pps threshold cannot catch
#   udp_flood    high-rate UDP flood
#   icmp_flood   high-rate ICMP flood
#   port_scan    SYN scan across a port range
#
# Typical training capture, in two terminals:
#   A: sudo python3 -m control.collect --label malicious --class syn_flood \
#        --duration 180 --only 10.10.1.3 --out data/syn_flood.csv
#   B: sudo ./bench/gen_traffic.sh syn_flood 180 10.10.1.3
# =============================================================================
set -uo pipefail

NS="${NS:-fwtest}"
TARGET="${TARGET:-10.10.1.1}"
CLASS="${1:-}"
DURATION="${2:-60}"
SRC="${3:-}"

[[ $EUID -eq 0 ]] || { echo "error: must run as root" >&2; exit 1; }
[[ -n "$CLASS" ]] || { sed -n '2,30p' "$0"; exit 1; }

SPOOF=""
[[ -n "$SRC" ]] && SPOOF="-a $SRC"

run() { ip netns exec "$NS" timeout "$DURATION" "$@" >/dev/null 2>&1 || true; }

echo "generating '$CLASS' -> $TARGET for ${DURATION}s ${SRC:+(source $SRC)}"

case "$CLASS" in
  web)
    # Real connections, so SYNs are balanced by FINs -- this is what teaches
    # the model that a high SYN count alone is not an attack.
    #
    # This NEEDS something listening on port 80, otherwise every connection is
    # refused with a RST and you capture connection-churn rather than web
    # traffic. Start one first if nothing is there:
    #     sudo python3 -m http.server 80 --bind 10.10.1.1
    if ! timeout 2 bash -c "</dev/tcp/$TARGET/80" 2>/dev/null; then
        echo "  WARNING: nothing is listening on $TARGET:80." >&2
        echo "           Start one in another terminal, or this captures" >&2
        echo "           refused connections instead of web traffic:" >&2
        echo "             sudo python3 -m http.server 80 --bind $TARGET" >&2
    fi
    ip netns exec "$NS" timeout "$DURATION" bash -c \
      "while true; do curl -s -m 2 http://$TARGET/ >/dev/null 2>&1 || true; sleep 0.05; done"
    ;;
  bulk)
    command -v iperf3 >/dev/null || { echo "needs iperf3"; exit 1; }
    echo "  (start a server first:  iperf3 -s -B $TARGET)"
    run iperf3 -c "$TARGET" -t "$DURATION"
    ;;
  game)
    # Steady 60 pps of small UDP to one port: the latency-sensitive workload
    # this project is motivated by, and a deliberate hard negative.
    run hping3 --udp -p 27015 -d 80 -i u16666 $SPOOF "$TARGET"
    ;;
  dns)
    run hping3 --udp -p 53 -d 60 -i u20000 $SPOOF "$TARGET"
    ;;
  ping)
    run ping -i 0.2 "$TARGET"
    ;;
  syn_flood)
    run hping3 --flood -S -p 80 $SPOOF "$TARGET"
    ;;
  low_slow_syn)
    # ~200 pps: indistinguishable from ordinary web traffic on rate alone.
    # Only the SYN-to-FIN imbalance gives it away.
    run hping3 -S -p 80 -i u5000 $SPOOF "$TARGET"
    ;;
  udp_flood)
    run hping3 --flood --udp -p 53 -d 100 $SPOOF "$TARGET"
    ;;
  icmp_flood)
    run hping3 --flood --icmp $SPOOF "$TARGET"
    ;;
  port_scan)
    run hping3 -S --scan 1-1024 -i u2000 $SPOOF "$TARGET"
    ;;
  *)
    echo "unknown class: $CLASS" >&2; sed -n '6,30p' "$0"; exit 1 ;;
esac

echo "done"
