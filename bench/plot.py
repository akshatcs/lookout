#!/usr/bin/env python3
"""
plot.py -- turn benchmark CSVs into the charts for your report.

    python3 bench/plot.py results/throughput-*.csv results/latency-*.csv

Produces, in results/:
    headline.png   CPU cost at saturation, with offered load alongside it so
                   the reader can see the comparison is load-matched
    cpu.png        CPU cost at both load points where CPU is measurable
    summary.txt    every number as text, for pasting into a document


The two that remain each do a job. headline.png is the result. cpu.png shows
the systems TIED at the lower load point, which is what makes the saturation
result credible rather than an artefact.

Reports the MEDIAN across repeats, not the mean: with three runs a single
outlier (a background process waking up, the VM being descheduled by the
Windows host) drags a mean badly, and the median is robust to exactly that.

matplotlib is optional. Without it we still get summary.txt, which is enough
to build the tables by hand.
"""
import csv, os, statistics, sys
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use("Agg")            # no display inside an ssh session
    import matplotlib.pyplot as plt
    HAVE_MPL = True
except ImportError:
    HAVE_MPL = False

RATE_ORDER = ["low", "medium", "high", "saturate", "flood"]
COLOURS = {"none": "#888888", "nftables": "#d95f02", "xdp": "#1b9e77"}


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else 0.0


def load_throughput(path):
    by = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                by[r["system"]][r["rate_label"]].append({
                    "tx_pps": float(r["tx_pps"]),
                    "rx_pps": float(r["rx_pps"]),
                    "fwd_pps": float(r.get("fwd_pps", r["rx_pps"])),
                    "drop_pps": float(r.get("drop_pps", 0)),
                    "filtered": float(r.get("filtered_pct", 0)),
                    "cpu": float(r["cpu_busy_pct"]),
                    "soft": float(r["cpu_softirq_pct"]),
                    "cpu_per_mpps": float(r.get("cpu_per_mpps", 0)),
                })
            except (ValueError, KeyError):
                continue
    return by


def load_latency(path):
    by = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            parts = r["scenario"].split("-")
            if len(parts) < 2:
                continue
            sysname, label = parts[0], parts[1]
            try:
                by[sysname][label].append({
                    "p50": float(r["p50_us"]), "p99": float(r["p99_us"]),
                    "loss": float(r["loss_pct"]),
                })
            except (ValueError, KeyError):
                continue
    return by


def main(argv):
    if len(argv) < 2:
        print(__doc__); return 1
    tput_csv = argv[1]
    lat_csv = argv[2] if len(argv) > 2 else None
    outdir = os.path.dirname(tput_csv) or "results"
    os.makedirs(outdir, exist_ok=True)

    tput = load_throughput(tput_csv)
    lat = load_latency(lat_csv) if lat_csv and os.path.exists(lat_csv) else {}
    systems = [s for s in ("none", "nftables", "xdp") if s in tput]
    labels = [l for l in RATE_ORDER if any(l in tput[s] for s in systems)]

    lines = ["BENCHMARK SUMMARY (median of repeats)", "=" * 78, ""]
    lines.append(f"{'system':<10}{'rate':<10}{'offered pps':>13}"
                 f"{'forwarded pps':>15}{'filtered%':>11}{'cpu%':>7}"
                 f"{'cpu %/Mpps':>12}")
    lines.append("-" * 80)
    for s in systems:
        for l in labels:
            runs = tput[s].get(l, [])
            if not runs:
                continue
            lines.append(
                f"{s:<10}{l:<10}{med([r['tx_pps'] for r in runs]):>13,.0f}"
                f"{med([r['fwd_pps'] for r in runs]):>15,.0f}"
                f"{med([r['filtered'] for r in runs]):>11.1f}"
                f"{med([r['cpu'] for r in runs]):>7.1f}"
                f"{med([r['cpu_per_mpps'] for r in runs]):>12.1f}")
    lines.append("")

    if lat:
        lines += ["LEGITIMATE-TRAFFIC LATENCY DURING ATTACK", "=" * 78, ""]
        lines.append(f"{'system':<10}{'rate':<9}{'p50 us':>10}{'p99 us':>10}"
                     f"{'loss%':>8}")
        lines.append("-" * 78)
        for s in systems:
            for l in labels:
                runs = lat.get(s, {}).get(l, [])
                if not runs:
                    continue
                lines.append(
                    f"{s:<10}{l:<9}{med([r['p50'] for r in runs]):>10.1f}"
                    f"{med([r['p99'] for r in runs]):>10.1f}"
                    f"{med([r['loss'] for r in runs]):>8.2f}")
        lines.append("")
        lines.append("p99 is the number to lead with: it is what a user of a")
        lines.append("latency-sensitive service actually experiences.")

    summary = "\n".join(lines)
    with open(os.path.join(outdir, "summary.txt"), "w") as f:
        f.write(summary + "\n")
    print(summary)
    print(f"\nwrote {outdir}/summary.txt")

    if not HAVE_MPL:
        print("matplotlib not installed; skipping charts "
              "(pip install matplotlib)")
        return 0

    # -----------------------------------------------------------------------
    # Plotting notes
    #
    # 1. LOG SCALE ON RATE AXES. The sweep spans roughly 350 pps to 400,000
    #    pps, a factor of a thousand. On a linear axis the two low points are
    #    sub-pixel and the chart looks like it has missing data. A log axis is
    #    not cosmetic here; it is the only way the low points are visible at
    #    all.
    #
    # 2. LOW AND MEDIUM ARE EXCLUDED FROM THE CPU CHARTS. Below about a
    #    thousand packets per second every configuration sits at 3-6% CPU,
    #    which on a virtual machine is the background noise floor. Plotting
    #    noise next to a real measurement invites the reader to compare them.
    #
    # 3. THE SATURATE LATENCY POINT IS EXCLUDED BY DEFAULT. It is reported in
    #    the text as anomalous and unreliable; drawing it as a bar presents it
    #    as a finding. Pass --include-unreliable to draw it anyway.
    # -----------------------------------------------------------------------

    include_unreliable = "--include-unreliable" in argv
    cpu_labels = [l for l in labels if l in ("high", "saturate")]

    def grouped_bars(ax, labels_used, value_fn, source, label_fmt=None):
        width = 0.8 / max(len(systems), 1)
        xs = range(len(labels_used))
        for i, sysname in enumerate(systems):
            vals = [value_fn(source[sysname].get(l, [])) for l in labels_used]
            pos = [x + i * width for x in xs]
            bars = ax.bar(pos, vals, width, label=sysname,
                          color=COLOURS.get(sysname), edgecolor="white",
                          linewidth=0.6)
            for b, v in zip(bars, vals):
                if v > 0:
                    txt = label_fmt(v) if label_fmt else fmt_val(v)
                    ax.annotate(txt, (b.get_x() + b.get_width() / 2, v),
                                ha="center", va="bottom", fontsize=7,
                                rotation=0, xytext=(0, 2),
                                textcoords="offset points")
        ax.set_xticks([x + 0.4 - width / 2 for x in xs])
        ax.set_xticklabels(labels_used)
        ax.legend(frameon=False)
        ax.grid(axis="y", alpha=0.25, linestyle=":")
        ax.set_axisbelow(True)

    def fmt_val(v):
        if v >= 1e6:
            return f"{v/1e6:.1f}M"
        if v >= 1e4:
            return f"{v/1e3:.0f}k"
        if v >= 1e3:
            return f"{v/1e3:.1f}k"   # 1.5k, not an unhelpful 2k
        if v >= 10:
            return f"{v:.0f}"
        return f"{v:.1f}"

    def autoscale(ax, values):
        """Log axis only when the data actually spans orders of magnitude.

        A log axis on a narrow range compresses real differences into
        invisibility; a linear axis on a 1000x range hides the small bars
        entirely. Pick whichever suits the data in front of us."""
        vals = [v for v in values if v > 0]
        if vals and max(vals) / min(vals) >= 20:
            ax.set_yscale("log")
            return True
        return False

    # =======================================================================
    # TWO FIGURES ONLY, DELIBERATELY.
    #
    # Figure 1 (cpu.png)      CPU cost at the two loads where CPU is
    #                         measurable. Includes the `high` point where the
    #                         systems are TIED. It is what makes
    #                         the saturation result credible, and it answers
    #                         "does the advantage hold at all loads?" before
    #                         anyone has to ask it.
    #
    # Figure 2 (headline.png) The principal result: CPU at saturation beside
    #                         offered load. The second panel exists to show
    #                         the comparison is matched.
    #
    # =======================================================================

    # --- Figure 1: CPU at meaningful load only ------------------------------
    if cpu_labels:
        fig, ax = plt.subplots(figsize=(7, 4.5))
        grouped_bars(ax, cpu_labels, lambda rs: med([r["cpu"] for r in rs]),
                     tput, label_fmt=lambda v: f"{v:.1f}%")
        ax.set_xlabel("offered load")
        ax.set_ylabel("CPU busy (%)")
        ax.set_title("CPU cost of filtering at equivalent policy\n"
                     "(low/medium omitted: below this VM's noise floor)",
                     fontsize=11)
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "cpu.png"), dpi=150)
        plt.close(fig)
        print(f"wrote {outdir}/cpu.png")

    # --- Figure 2: the headline, saturate point only -------------------------
    if "saturate" in tput.get("xdp", {}) and "saturate" in tput.get("nftables", {}):
        fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.2))
        order = [s for s in ("none", "nftables", "xdp") if s in systems]
        cpu_v = [med([r["cpu"] for r in tput[s].get("saturate", [])])
                 for s in order]
        off_v = [med([r["tx_pps"] for r in tput[s].get("saturate", [])])
                 for s in order]
        cols = [COLOURS.get(s) for s in order]

        b = a1.bar(order, cpu_v, color=cols, edgecolor="white")
        for bb, v in zip(b, cpu_v):
            a1.annotate(f"{v:.1f}%", (bb.get_x() + bb.get_width()/2, v),
                        ha="center", va="bottom", fontsize=9,
                        xytext=(0, 2), textcoords="offset points")
        a1.set_ylabel("CPU busy (%)")
        a1.set_title("CPU cost at saturation", fontsize=11)
        a1.grid(axis="y", alpha=0.25, linestyle=":"); a1.set_axisbelow(True)

        b = a2.bar(order, off_v, color=cols, edgecolor="white")
        for bb, v in zip(b, off_v):
            a2.annotate(fmt_val(v), (bb.get_x() + bb.get_width()/2, v),
                        ha="center", va="bottom", fontsize=9,
                        xytext=(0, 2), textcoords="offset points")
        a2.set_ylabel("offered packets/s")
        a2.set_title("Offered load (comparison is matched)", fontsize=11)
        a2.grid(axis="y", alpha=0.25, linestyle=":"); a2.set_axisbelow(True)

        fig.suptitle("Equivalent policy, matched offered load", fontsize=12)
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, "headline.png"), dpi=150)
        plt.close(fig)
        print(f"wrote {outdir}/headline.png")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

