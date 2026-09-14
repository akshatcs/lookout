#!/usr/bin/env bash
# =============================================================================
# run_experiment.sh -- the automated benchmark that produces results.
#
# Runs the SAME traffic against three configurations and records what happened:
#
#   none      no firewall at all        -> baseline forwarding capacity
#   nftables  conventional Linux filter -> the conventional comparison
#   xdp       this project              -> the proposed system
#
# For each configuration it sweeps a set of offered packet rates and records
# throughput, loss, CPU utilisation and p99 latency into results/*.csv.
#
# METHODOLOGY NOTES (these belong in the report)
# ---------------------------------------------------------------------------
#  * Every run is fixed-duration and repeated --repeat times. We report the
#    MEDIAN of the repeats, not the best run. Reporting the best is a way to
#    accidentally publish measurement noise as a result.
#  * Counters are reset between runs so each measurement starts clean.
#  * A settle delay separates runs, because the previous run's traffic can
#    still be draining from queues when the next one starts.
#  * Latency is measured CONCURRENTLY with the attack, from a separate source
#    address. Measuring it afterwards tells us nothing -- the whole question
#    is what happens to a legitimate user *while* an attack is in progress.
#  * CPU is sampled with mpstat across all cores. On a VM, note how many vCPUs
#    we allocated; softirq processing is single-queue on veth, so one core
#    saturating while others idle is expected and worth explaining.
#
# USAGE
#   sudo ./bench/run_experiment.sh                      # full sweep
#   sudo ./bench/run_experiment.sh --systems xdp,none   # subset
#   sudo ./bench/run_experiment.sh --duration 20 --repeat 5
# =============================================================================
set -uo pipefail

NS="${NS:-fwtest}"
IFACE="${IFACE:-veth-fw}"
FW_IP="${FW_IP:-10.10.1.1}"
ATTACKER="${ATTACKER:-10.10.1.3}"
LEGIT="${LEGIT:-10.10.1.2}"

DURATION=15
REPEAT=3
SETTLE=3
SYSTEMS="none,nftables,xdp"
OUTDIR="results"
LAT_PORT=9999

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --repeat)   REPEAT="$2"; shift 2 ;;
        --systems)  SYSTEMS="$2"; shift 2 ;;
        --iface)    IFACE="$2"; shift 2 ;;
        --outdir)   OUTDIR="$2"; shift 2 ;;
        -h|--help)  sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "error: must run as root" >&2; exit 1; }

for tool in hping3 ip; do
    command -v "$tool" >/dev/null || {
        echo "error: '$tool' not found. Run ./scripts/install_deps.sh" >&2
        exit 1
    }
done

ip netns list | grep -q "^${NS}" || {
    echo "error: namespace '$NS' missing. Run: sudo ./bench/setup_netns.sh" >&2
    exit 1
}

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d-%H%M%S)
CSV="$OUTDIR/throughput-$STAMP.csv"
LATCSV="$OUTDIR/latency-$STAMP.csv"

echo "system,rate_label,run,duration_s,tx_packets,rx_packets,forwarded,dropped,tx_pps,rx_pps,fwd_pps,drop_pps,filtered_pct,cpu_busy_pct,cpu_softirq_pct,cpu_per_mpps" > "$CSV"

# -----------------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------------

iface_stat() { cat "/sys/class/net/$1/statistics/$2" 2>/dev/null || echo 0; }

# Aggregate CPU jiffies from /proc/stat: prints "<total> <idle> <softirq>".
#
# Sampling this immediately before and after the traffic window gives the CPU
# utilisation of EXACTLY that interval. mpstat was used previously and proved
# unreliable here: its one-second samples drift relative to the generator's
# own timeout, so under heavy load several samples landed outside the flood
# and the reported average came out lower at higher offered rates.
cpu_snapshot() {
    awk '/^cpu /{
        total=0; for (i=2; i<=NF; i++) total+=$i;
        idle=$5+$6;          # idle + iowait
        soft=$8;             # softirq -- where packet processing shows up
        print total, idle, soft
    }' /proc/stat
}

ns_iface_stat() {
    ip netns exec "$NS" cat "/sys/class/net/veth-cl/statistics/$1" 2>/dev/null || echo 0
}

unload_all() {
    ./bin/fwload -i "$IFACE" -u >/dev/null 2>&1 || true
    ./bench/nftables_baseline.sh remove >/dev/null 2>&1 || true
    sleep 0.5
}

setup_system() {
    local sys="$1"
    unload_all
    case "$sys" in
        none)
            echo "    [no firewall]"
            ;;
        nftables)
            ./bench/nftables_baseline.sh apply "$IFACE" >/dev/null
            echo "    [nftables prerouting ruleset applied]"
            ;;
        xdp)
            ./bin/fwload -i "$IFACE" >/dev/null 2>&1 || {
                echo "    ERROR: fwload failed" >&2; return 1; }
            python3 -m control.fwctl allow add "$LEGIT" >/dev/null
            python3 -m control.fwctl reset >/dev/null
            echo "    [XDP firewall loaded, $LEGIT allowlisted]"
            ;;
    esac
    sleep 1
}

# Sweep points. hping3 is not a precise rate generator, so we drive it with
# inter-packet delays and record the ACHIEVED rate from the sender's own
# interface counters rather than the requested one. Recording the requested
# rate would be fiction.
#   label:hping-interval
# Sweep points.
#
# IMPORTANT: hping3's -i uN inter-packet delay is implemented with usleep and
# becomes unreliable below roughly 1 ms. Requesting u50 (20k pps) in practice
# yields under 2k pps, which silently collapses several sweep points onto the
# same offered rate. The points below were chosen after measuring what hping3
# actually achieves on this testbed rather than what it is asked for.
#
# The high-rate points use PARALLEL flood instances, which is the only way to
# push a veth link hard enough for the firewalls to become the bottleneck
# rather than the generator.
#   label:mode:parameter
RATE_POINTS=(
    "low:paced:u2000"      # ~500 pps
    "medium:paced:u500"    # ~1.5k pps
    "high:flood:1"         # 1 flood instance
    "saturate:flood:4"     # 4 parallel flood instances
)

run_one() {
    local sys="$1" label="$2" hping_mode="$3" hping_arg="$4" run="$5"

    python3 -m control.fwctl reset >/dev/null 2>&1 || true
    ./bench/nftables_baseline.sh zero >/dev/null 2>&1 || true

    local tx0 rx0
    tx0=$(ns_iface_stat tx_packets)
    rx0=$(iface_stat "$IFACE" rx_packets)

    # CPU sampled from /proc/stat across exactly the traffic window.
    local cpu0 cpu_total0 cpu_idle0 cpu_soft0
    cpu0=$(cpu_snapshot)
    cpu_total0=$(echo "$cpu0" | cut -d' ' -f1)
    cpu_idle0=$(echo "$cpu0" | cut -d' ' -f2)
    cpu_soft0=$(echo "$cpu0" | cut -d' ' -f3)

    # Concurrent latency probe from the legitimate source. This is the
    # measurement that answers "does a real user still get service".
    ( ip netns exec "$NS" timeout $(( DURATION + 8 )) python3 bench/latency.py \
        --client "$FW_IP" --port "$LAT_PORT" --bind "$LEGIT" \
        --count $(( DURATION * 50 )) --warmup 20 --interval 0.01 \
        --timeout 0.2 --max-seconds "$DURATION" \
        --csv "$LATCSV" --scenario "${sys}-${label}-run${run}" \
        >/dev/null 2>&1 ) &
    local lat_pid=$!

    # ---- the attack itself -------------------------------------------------
    # Dispatch on $hping_mode, NOT on $hping_arg. With the three-field rate
    # points, $hping_arg is a pacing interval for "paced" mode and an INSTANCE
    # COUNT for "flood" mode. Testing $hping_arg against the string "flood"
    # (as an earlier version did) is never true, and falls through to
    # `-i 1`, which is a one-second delay -- one packet per second.
    if [[ "$hping_mode" == "flood" ]]; then
        # Parallel instances with distinct spoofed sources, so the per-source
        # rate limiter is genuinely exercised rather than all traffic landing
        # in a single token bucket. One hping3 process is single-threaded and
        # cannot saturate the link on its own.
        local i srcs=("$ATTACKER" 10.10.1.5 10.10.1.6 10.10.1.7)
        local hping_pids=()
        for (( i=0; i<hping_arg; i++ )); do
            ip netns exec "$NS" timeout "$DURATION" \
                hping3 --flood -S -p 80 -a "${srcs[$((i % 4))]}" "$FW_IP" \
                >/dev/null 2>&1 &
            hping_pids+=($!)
        done
        # Wait ONLY on the generators. A bare `wait` would also block on the
        # mpstat sampler and the concurrent latency probe, and a lossy probe
        # can outlive the measurement window by many minutes.
        wait "${hping_pids[@]}" 2>/dev/null || true
    else
        # Paced mode: $hping_arg is an hping3 interval such as "u2000",
        # meaning 2000 microseconds between packets.
        ip netns exec "$NS" timeout "$DURATION" \
            hping3 -S -p 80 -a "$ATTACKER" -i "$hping_arg" "$FW_IP" \
            >/dev/null 2>&1 || true
    fi

    local cpu1 cpu_total1 cpu_idle1 cpu_soft1
    cpu1=$(cpu_snapshot)
    cpu_total1=$(echo "$cpu1" | cut -d' ' -f1)
    cpu_idle1=$(echo "$cpu1" | cut -d' ' -f2)
    cpu_soft1=$(echo "$cpu1" | cut -d' ' -f3)

    kill $lat_pid 2>/dev/null || true
    wait $lat_pid 2>/dev/null || true

    local tx1 rx1
    tx1=$(ns_iface_stat tx_packets)
    rx1=$(iface_stat "$IFACE" rx_packets)

    local tx=$(( tx1 - tx0 ))
    local rx=$(( rx1 - rx0 ))

    # ---- goodput accounting ------------------------------------------------
    # The interface rx_packets counter increments when a frame ARRIVES. An XDP
    # program drops it afterwards, so rx always equals tx and (tx-rx)/tx is
    # always zero no matter how much the firewall discarded. Computing loss
    # that way makes the firewall invisible.
    #
    # Goodput -- what actually reached the protected stack -- therefore has to
    # come from each system's own accounting:
    #     xdp       the pass_* counters in the stats map
    #     nftables  rx minus the sum of its drop-rule counters
    #     none      everything arrived
    local dropped=0 forwarded=$rx
    if [[ "$sys" == "xdp" ]]; then
        dropped=$(python3 -m control.fwctl stats 2>/dev/null \
                  | tr -d ',' \
                  | awk '/^drop_/ {s+=$2} END {print s+0}')
        forwarded=$(( rx - dropped ))
    elif [[ "$sys" == "nftables" ]]; then
        dropped=$(./bench/nftables_baseline.sh drops 2>/dev/null || echo 0)
        forwarded=$(( rx - dropped ))
    fi
    (( forwarded < 0 )) && forwarded=0

    # Busy fraction over the window, averaged across all cores.
    local cpu_busy cpu_soft
    cpu_busy=$(awk -v t0="$cpu_total0" -v t1="$cpu_total1" \
                   -v i0="$cpu_idle0"  -v i1="$cpu_idle1" \
        'BEGIN{d=t1-t0; if(d<=0){print 0; exit} printf "%.2f", 100*(1-(i1-i0)/d)}')
    cpu_soft=$(awk -v t0="$cpu_total0" -v t1="$cpu_total1" \
                   -v s0="$cpu_soft0"  -v s1="$cpu_soft1" \
        'BEGIN{d=t1-t0; if(d<=0){print 0; exit} printf "%.2f", 100*(s1-s0)/d}')
    cpu_busy=${cpu_busy:-0}; cpu_soft=${cpu_soft:-0}

    local tx_pps=$(( tx / DURATION ))
    local rx_pps=$(( rx / DURATION ))
    local drop_pps=$(( dropped / DURATION ))
    local fwd_pps=$(( forwarded / DURATION ))

    # Fraction of offered traffic the firewall discarded.
    local filtered=0
    (( rx > 0 )) && filtered=$(awk "BEGIN{printf \"%.2f\", 100*$dropped/$rx}")

    # CPU cost per million packets offered. THIS is the column that makes the
    # three systems comparable: hping3 does not reach the same offered rate on
    # every run, so raw CPU percentages measured at different loads cannot be
    # compared directly. Normalising by achieved rate removes that confound.
    local cpu_per_mpps=0
    (( tx_pps > 0 )) && cpu_per_mpps=$(awk "BEGIN{printf \"%.2f\", $cpu_busy/($tx_pps/1000000.0)}")

    echo "$sys,$label,$run,$DURATION,$tx,$rx,$forwarded,$dropped,$tx_pps,$rx_pps,$fwd_pps,$drop_pps,$filtered,$cpu_busy,$cpu_soft,$cpu_per_mpps" >> "$CSV"
    printf "      run %d: offered %'d pps | forwarded %'d pps | filtered %s%% | cpu %s%% (%s %%/Mpps)\n" \
        "$run" "$tx_pps" "$fwd_pps" "$filtered" "$cpu_busy" "$cpu_per_mpps"
}

# -----------------------------------------------------------------------------
# main
# -----------------------------------------------------------------------------

echo "========================================================"
echo " benchmark sweep"
echo "   interface : $IFACE"
echo "   duration  : ${DURATION}s x ${REPEAT} repeats"
echo "   systems   : $SYSTEMS"
echo "   output    : $CSV"
echo "========================================================"

# Echo server for the latency probe, in the root namespace alongside the
# protected "service".
python3 bench/latency.py --server --bind "$FW_IP" --port "$LAT_PORT" \
    >/dev/null 2>&1 &
ECHO_PID=$!
trap 'kill $ECHO_PID 2>/dev/null; unload_all' EXIT
sleep 1

IFS=',' read -ra SYS_LIST <<< "$SYSTEMS"
for sys in "${SYS_LIST[@]}"; do
    echo
    echo ">>> system: $sys"
    setup_system "$sys" || continue

    for point in "${RATE_POINTS[@]}"; do
        label=$(echo "$point" | cut -d: -f1)
        mode=$(echo "$point" | cut -d: -f2)
        arg=$(echo "$point" | cut -d: -f3)
        echo "  rate point: $label ($mode $arg)"
        for run in $(seq 1 "$REPEAT"); do
            run_one "$sys" "$label" "$mode" "$arg" "$run"
            sleep "$SETTLE"
        done
    done
done

unload_all
echo
echo "========================================================"
echo " done"
echo "   throughput/cpu : $CSV"
echo "   latency        : $LATCSV"
echo
echo " plot it:"
echo "   python3 bench/plot.py $CSV $LATCSV"
echo "========================================================"

