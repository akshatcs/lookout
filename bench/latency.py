#!/usr/bin/env python3
"""
latency.py -- UDP ping-pong latency measurement with percentiles.

WHY A CUSTOM TOOL RATHER THAN sockperf OR netperf
---------------------------------------------------------------------------
Those tools are excellent but they are extra packages, and more importantly
they report a mean by default. The mean is the least interesting number here.

This project's stated motivation is latency-sensitive services -- game
servers, VoIP, VPN concentrators. For those, what ruins the user experience is
not the average packet, it is the worst few percent. A service with a 0.4 ms
mean and a 90 ms 99th percentile feels broken, and the mean hides that
completely.

So this reports p50/p90/p99/p99.9 and the maximum, and p99 is the number that
belongs in the summary.

MEASUREMENT NOTES
---------------------------------------------------------------------------
  * Timing uses time.perf_counter_ns(), a monotonic high-resolution clock.
  * One request is outstanding at a time, so a slow reply delays the next
    send. That is deliberate: it measures round-trip latency, not throughput.
  * The first --warmup samples are discarded. They include ARP resolution,
    route cache population, and Python's own JIT-less warm-up, and they would
    otherwise dominate the tail.
  * Lost packets are counted separately rather than recorded as huge latencies
    -- mixing loss into a latency distribution makes both numbers meaningless.

USAGE
---------------------------------------------------------------------------
  # on the firewall/server host (root namespace)
  python3 bench/latency.py --server --bind 10.10.1.1 --port 9999

  # on the client (inside the namespace)
  sudo ip netns exec fwtest python3 bench/latency.py \
       --client 10.10.1.1 --port 9999 --count 2000 --interval 0.002

Run the client while an attack is in progress: the difference between the
idle p99 and the under-attack p99, with and without the firewall, is the
single most persuasive result this project can produce.
"""

import argparse
import socket
import statistics
import sys
import time


def percentile(sorted_values, pct):
    """Nearest-rank percentile. No numpy dependency on the measurement path."""
    if not sorted_values:
        return float("nan")
    k = max(0, min(len(sorted_values) - 1,
                   int(round(pct / 100.0 * len(sorted_values) + 0.5)) - 1))
    return sorted_values[k]


def run_server(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print(f"echo server listening on {args.bind}:{args.port} (Ctrl-C to stop)")
    n = 0
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            sock.sendto(data, addr)   # echo it straight back
            n += 1
            if n % 5000 == 0:
                sys.stdout.write(f"\r  echoed {n:,} packets ")
                sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\nechoed {n:,} packets total")
    finally:
        sock.close()
    return 0


def run_client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    if args.bind:
        sock.bind((args.bind, 0))
    target = (args.client, args.port)
    payload = b"x" * max(16, args.size)

    samples = []
    lost = 0
    total = args.count + args.warmup

    print(f"probing {args.client}:{args.port}  "
          f"{args.count} samples (+{args.warmup} warm-up), "
          f"{args.size}B payload")

    start_wall = time.time()
    deadline = (start_wall + args.max_seconds) if args.max_seconds else None
    for i in range(total):
        if deadline and time.time() >= deadline:
            break
        seq = i.to_bytes(4, "little")
        t0 = time.perf_counter_ns()
        try:
            sock.sendto(seq + payload[4:], target)
            while True:
                data, _ = sock.recvfrom(4096)
                # Ignore stale replies from earlier probes, otherwise a late
                # reply would be timed against the wrong send.
                if data[:4] == seq:
                    break
            rtt_us = (time.perf_counter_ns() - t0) / 1000.0
            if i >= args.warmup:
                samples.append(rtt_us)
        except socket.timeout:
            if i >= args.warmup:
                lost += 1
        except OSError as e:
            print(f"\nsend error: {e}", file=sys.stderr)
            break

        if args.interval:
            time.sleep(args.interval)

        if i % 200 == 0 and i:
            sys.stdout.write(f"\r  {i}/{total} ")
            sys.stdout.flush()

    duration = time.time() - start_wall
    sock.close()
    print("\r" + " " * 30 + "\r", end="")

    if not samples:
        print("no replies received. Is the echo server running? Is the "
              "traffic being dropped by the firewall?", file=sys.stderr)
        return 1

    samples.sort()
    sent = len(samples) + lost
    loss_pct = 100.0 * lost / sent if sent else 0.0

    results = {
        "samples": len(samples),
        "lost": lost,
        "loss_pct": loss_pct,
        "duration_s": duration,
        "min_us": samples[0],
        "mean_us": statistics.fmean(samples),
        "p50_us": percentile(samples, 50),
        "p90_us": percentile(samples, 90),
        "p99_us": percentile(samples, 99),
        "p999_us": percentile(samples, 99.9),
        "max_us": samples[-1],
    }

    if args.csv:
        import csv
        import os
        new = not os.path.exists(args.csv)
        with open(args.csv, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["scenario"] + list(results))
            if new:
                w.writeheader()
            w.writerow({"scenario": args.scenario, **{
                k: round(v, 3) if isinstance(v, float) else v
                for k, v in results.items()
            }})
        print(f"appended to {args.csv}")

    print(f"\n  scenario     {args.scenario}")
    print(f"  replies      {len(samples):,} / {sent:,}   "
          f"loss {loss_pct:.2f}%")
    print(f"  min          {results['min_us']:9.1f} us")
    print(f"  mean         {results['mean_us']:9.1f} us")
    print(f"  p50          {results['p50_us']:9.1f} us")
    print(f"  p90          {results['p90_us']:9.1f} us")
    print(f"  p99          {results['p99_us']:9.1f} us   <-- report this one")
    print(f"  p99.9        {results['p999_us']:9.1f} us")
    print(f"  max          {results['max_us']:9.1f} us")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", action="store_true", help="run the echo server")
    mode.add_argument("--client", metavar="HOST", help="probe this host")

    p.add_argument("--bind", default="0.0.0.0",
                   help="server: address to listen on; client: source address")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--count", type=int, default=1000, help="samples to record")
    p.add_argument("--warmup", type=int, default=50,
                   help="discarded leading samples (default 50)")
    p.add_argument("--interval", type=float, default=0.002,
                   help="seconds between probes (default 0.002 = 500/s)")
    p.add_argument("--size", type=int, default=64, help="payload bytes")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--max-seconds", type=float, default=0,
                   help="stop sending after this many seconds and report what "
                        "was collected. Without it, a probe on a saturated "
                        "link cannot finish inside its measurement window and "
                        "is killed before writing any result at all.")
    p.add_argument("--csv", help="append results to this CSV")
    p.add_argument("--scenario", default="unnamed",
                   help="label for the CSV row, e.g. 'xdp-under-attack'")
    args = p.parse_args()

    return run_server(args) if args.server else run_client(args)


if __name__ == "__main__":
    sys.exit(main())

