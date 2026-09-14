"""
collect.py -- capture labelled feature vectors from live traffic.

This is how we might replace the synthetic training set with real data. Run it
while generating traffic of a known kind, and it writes one CSV row per source
per second, tagged with the label we supply.

    # terminal A: capture, labelling everything as benign
    sudo python3 -m control.collect --label benign --class web \\
         --duration 300 --out data/benign_web.csv

    # terminal B: generate the matching traffic
    ip netns exec fwtest iperf3 -c 10.10.1.1 -t 300

Then repeat for each attack class, and train on the lot:

    python3 -m control.train --csv data/*.csv

============================================================================
GETTING THE LABELS RIGHT
============================================================================
The label comes from us, not from any detection. That means the capture has
to be clean: while collecting benign data, do not run attacks, and vice versa.
Background noise from the host (ARP, DHCP, your own ssh session) will be
recorded too, so:

  * --exclude your ssh client address, or every benign capture is polluted
    with your own interactive session and every attack capture is polluted
    with a mislabelled benign source;
  * --only restricts capture to specific sources, which is the safer option
    when we know exactly which addresses our generator uses.

A single mislabelled source repeated over a 300-second capture contributes 300
wrong rows, which is enough to visibly damage a few-thousand-row training set.
Spend the extra thirty seconds getting this right.

============================================================================
HOW MUCH TO CAPTURE
============================================================================
One row per source per second. A 300-second run with 3 active sources gives
~900 rows. Aim for roughly 2,000-4,000 rows total across all classes, which is
about 20-30 minutes of captures. Beyond that the forest stops improving.
"""

import argparse
import csv
import os
import signal
import sys
import time

from . import schema
from .features import FeatureExtractor
from .firewall import Firewall
from .model import LABEL_BENIGN, LABEL_MALICIOUS

# Columns: the model features, plus label, plus bookkeeping that is useful for
# sanity-checking a capture afterwards but never fed to the model.
EXTRA_COLUMNS = ["label", "class", "ip", "ts", "packets", "dropped"]


def main(argv=None):
    p = argparse.ArgumentParser(prog="control.collect")
    p.add_argument("--label", choices=["benign", "malicious"], required=True,
                   help="ground truth for everything captured in this run")
    p.add_argument("--class", dest="cls", default=None,
                   help="traffic class name, e.g. syn_flood, web, game. Used "
                        "for the per-class breakdown in training.")
    p.add_argument("--out", required=True, help="CSV to write")
    p.add_argument("--duration", type=float, default=120.0,
                   help="seconds to capture (default 120)")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--pin-dir", default=schema.PIN_DIR)
    p.add_argument("--only", action="append", metavar="IP",
                   help="capture ONLY these source IPs (repeatable)")
    p.add_argument("--exclude", action="append", metavar="IP",
                   help="never capture these source IPs (repeatable). Put "
                        "your ssh client address here.")
    p.add_argument("--min-pps", type=float, default=1.0,
                   help="ignore sources slower than this (default 1.0); "
                        "filters out incidental background chatter")
    p.add_argument("--append", action="store_true",
                   help="append to an existing CSV instead of overwriting")
    args = p.parse_args(argv)

    if os.geteuid() != 0:
        print("error: BPF map access requires root. Re-run with sudo.",
              file=sys.stderr)
        return 1

    label = LABEL_BENIGN if args.label == "benign" else LABEL_MALICIOUS
    cls = args.cls or args.label
    only = set(args.only or [])
    exclude = set(args.exclude or [])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    exists = os.path.exists(args.out) and args.append
    mode = "a" if args.append else "w"

    running = {"v": True}

    def stop(signum, frame):
        running["v"] = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    fw = Firewall(pin_dir=args.pin_dir)
    fx = FeatureExtractor()
    written = 0
    sources_seen = set()
    deadline = time.time() + args.duration

    print(f"capturing label={args.label} class={cls} for {args.duration:g}s")
    if only:
        print(f"  restricted to: {', '.join(sorted(only))}")
    if exclude:
        print(f"  excluding:     {', '.join(sorted(exclude))}")
    print(f"  writing to:    {args.out}")
    print("  generate your traffic NOW. Ctrl-C to stop early.\n")

    with open(args.out, mode, newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=list(schema.FEATURE_NAMES) + EXTRA_COLUMNS
        )
        if not exists:
            writer.writeheader()

        while running["v"] and time.time() < deadline:
            cycle_start = time.time()
            rows = fx.update(fw.read_states(), fw.ktime_ns())

            batch = 0
            for ip, r in rows.items():
                if only and ip not in only:
                    continue
                if ip in exclude:
                    continue
                if r["pps"] < args.min_pps:
                    continue

                out = {name: round(float(r[name]), 6)
                       for name in schema.FEATURE_NAMES}
                out.update({
                    "label": label, "class": cls, "ip": ip,
                    "ts": round(time.time(), 3),
                    "packets": int(r["_packets"]),
                    "dropped": int(r["_dropped"]),
                })
                writer.writerow(out)
                sources_seen.add(ip)
                written += 1
                batch += 1

            f.flush()  # so an interrupted capture still leaves usable data
            remaining = max(0.0, deadline - time.time())
            sys.stdout.write(
                f"\r  {written:>6} rows   {len(sources_seen)} sources   "
                f"{batch} this window   {remaining:5.0f}s left "
            )
            sys.stdout.flush()

            time.sleep(max(0.0, args.interval - (time.time() - cycle_start)))

    fw.close()
    print(f"\n\nwrote {written} rows from {len(sources_seen)} sources "
          f"to {args.out}")
    if written == 0:
        print("\nNo rows captured. Check that:")
        print("  * traffic is actually reaching the interface the XDP program")
        print("    is attached to  (sudo python3 -m control.fwctl top)")
        print("  * --only / --exclude are not filtering everything out")
        print(f"  * sources are sending more than --min-pps ({args.min_pps})")
        return 1
    if len(sources_seen) < 2:
        print("\nnote: only one source was captured. A training set built "
              "from a single address teaches the model very little about "
              "variation between hosts -- consider adding IP aliases to the "
              "client namespace (bench/setup_netns.sh adds three).")
    print(f"\nnext:  python3 -m control.train --csv {args.out} [more...]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
