#!/usr/bin/env python3
"""Summarise a benchmark run, check it, and draw the CPU chart.

    python3 bench/plot.py results/run-<stamp>

Writes summary.txt and cpu.png next to results.csv. Figures are medians of
the repeats. Without matplotlib you still get summary.txt.

The chart shows CPU utilisation normalised to the same packet rate: how
much of one CPU core each system needs to drop 100,000 packets a second.
Raw CPU-busy percentages can't be compared directly, because every hping3
sender keeps its own core busy and the offered rate differs a little
between systems.
"""

import csv
import os
import statistics
import sys
from collections import defaultdict

SYSTEMS = ["none", "nftables", "nft-ingress", "xdp", "xdp-empty"]
WORKLOADS = {"block": "traffic from a blocked IP",
             "limit": "traffic over the rate limit"}
LABELS = {"none": "no firewall", "nftables": "nftables (prerouting)",
          "nft-ingress": "nftables (ingress)", "xdp": "XDP (this project)",
          "xdp-empty": "empty XDP program (floor)"}
COLOURS = {"none": "#2a78d6", "nftables": "#eb6834",       # validated
           "nft-ingress": "#1baf7a", "xdp": "#eda100",     # categorical order;
           "xdp-empty": "#a3a29c"}                         # grey: a baseline
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e1"


def load(path):
    """{(workload, senders): {system: [rows]}}"""
    out = defaultdict(lambda: defaultdict(list))
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            out[(r["workload"], int(r["senders"]))][r["system"]].append(r)
    return out


def points(data):
    order = list(WORKLOADS)
    return sorted(data, key=lambda k: (order.index(k[0]) if k[0] in order else 9, k[1]))


def med(rows, field):
    return statistics.median(float(r[field]) for r in rows)


def core_pct(rows):
    """% of one core needed per 100,000 packets/s = ns per packet / 100."""
    return med(rows, "ns_per_pkt") / 100


def summary(data, env):
    reps = max(len(v) for g in data.values() for v in g.values())
    out = ["environment", "-----------", env.rstrip(), "",
           f"CPU per packet (median of {reps} runs)",
           "-------------------------------------",
           f"{'workload':<9}{'senders':<8}{'system':<14}{'offered pps':>12}{'dropped':>9}{'IP saw':>9}"
           f"{'busy':>7}{'softirq':>9}{'ns/pkt':>9}{'core% per 100k pps':>20}"]
    for key in points(data):
        for s in SYSTEMS:
            rows = data[key].get(s)
            if not rows:
                continue
            rx = med(rows, "received")
            out.append(f"{key[0]:<9}{key[1]:<8}{s:<14}{med(rows, 'offered') / med(rows, 'duration_s'):>12,.0f}"
                       f"{100 * med(rows, 'fw_dropped') / rx:>8.1f}%"
                       f"{100 * med(rows, 'ip_in') / rx:>8.1f}%"
                       f"{med(rows, 'cpu_busy_pct'):>6.0f}%{med(rows, 'cpu_softirq_pct'):>8.1f}%"
                       f"{med(rows, 'ns_per_pkt'):>9.0f}{core_pct(rows):>19.1f}%")
        out.append("")
    for key in points(data):
        fw, floor = data[key].get("xdp"), data[key].get("xdp-empty")
        if fw and floor:
            out.append(f"{key[0]}/{key[1]}: the XDP firewall's own work is "
                       f"{med(fw, 'ns_per_pkt') - med(floor, 'ns_per_pkt'):.0f} ns per packet "
                       "(xdp minus the empty program)")
    if out[-1]:
        out.append("")
    return "\n".join(out + ["checks", "------"] + checks(data))


def checks(data):
    worst, noisy, busy = 0.0, [], []
    for (wl, n), by_sys in data.items():
        for s, rows in by_sys.items():
            for r in rows if s != "xdp-empty" else ():     # no counters to check
                rx = float(r["received"])
                # nftables at prerouting drops after the IP layer has counted
                # the packet; the others drop (or pass) before it.
                expect = rx if s == "nftables" else rx - float(r["fw_dropped"])
                if rx:
                    worst = max(worst, abs(float(r["ip_in"]) - expect) / rx * 100)
            vals = [float(r["ns_per_pkt"]) for r in rows]
            if len(vals) > 1 and (max(vals) - min(vals)) / statistics.median(vals) > 0.25:
                noisy.append(f"{s} {wl}/{n}")
            if med(rows, "cpu_busy_pct") > 90:
                busy.append(f"{s} {wl}/{n}")
    return [
        f"[{'ok' if worst < 1 else 'CHECK'}] the kernel's IP counter agrees with the "
        f"firewalls' drop counters (worst difference {worst:.2f}% of packets)",
        "[ok] runs within 25% of each other" if not noisy else
        f"[note] runs more than 25% apart: {', '.join(noisy)} (try --repeat 5)",
        "[ok] no run above 90% CPU busy" if not busy else
        f"[note] CPU saturated: {', '.join(busy)} (use fewer senders than vCPUs)",
    ]


def chart(data, outdir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.size": 9, "axes.labelcolor": MUTED,
                         "xtick.color": MUTED, "ytick.color": MUTED})
    wls = [w for w in WORKLOADS if any(k[0] == w for k in data)]
    fig, axes = plt.subplots(1, len(wls), figsize=(4.3 * len(wls) + 0.6, 4.2),
                             sharey=True, squeeze=False)
    for ax, wl in zip(axes[0], wls):
        keys = [k for k in points(data) if k[0] == wl]
        systems = [s for s in SYSTEMS if any(s in data[k] for k in keys)]
        width = 0.8 / len(systems)
        for i, s in enumerate(systems):
            xs, vals, lo, hi = [], [], [], []
            for j, k in enumerate(keys):
                rows = data[k].get(s)
                if not rows:
                    continue
                v = [float(r["ns_per_pkt"]) / 100 for r in rows]
                xs.append(j + (i - (len(systems) - 1) / 2) * width)
                vals.append(core_pct(rows))
                lo.append(vals[-1] - min(v))
                hi.append(max(v) - vals[-1])
            bars = ax.bar(xs, vals, width * 0.9, color=COLOURS[s], label=LABELS[s],
                          yerr=[lo, hi],
                          error_kw={"ecolor": MUTED, "elinewidth": 0.8, "capsize": 2})
            for b, v, e in zip(bars, vals, hi):
                ax.annotate(f"{v:.1f}", (b.get_x() + b.get_width() / 2, v + e),
                            ha="center", va="bottom", fontsize=7, color=INK,
                            xytext=(0, 2), textcoords="offset points")
        ax.set_xticks(range(len(keys)))
        ax.set_xticklabels([f"{k[1]} sender{'s' if k[1] > 1 else ''}" for k in keys])
        ax.set_title(WORKLOADS[wl], loc="left", fontsize=10, color=INK)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        ax.tick_params(length=0)
    axes[0][0].set_ylabel("CPU utilisation: % of one core per 100,000 packets/s")
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels), frameon=False,
               fontsize=8)
    fig.text(0.01, 0.99, "Lower is better. Median of runs; bars show min-max.",
             fontsize=7.5, color=MUTED, va="top")
    fig.tight_layout(rect=(0, 0.07, 1, 0.96))
    fig.savefig(os.path.join(outdir, "cpu.png"), dpi=160)
    plt.close(fig)
    print(f"wrote {outdir}/cpu.png")


def main():
    if len(sys.argv) != 2 or not os.path.isfile(os.path.join(sys.argv[1], "results.csv")):
        sys.exit(__doc__)
    d = sys.argv[1]
    data = load(os.path.join(d, "results.csv"))
    env_path = os.path.join(d, "environment.txt")
    env = open(env_path).read() if os.path.exists(env_path) else ""
    text = summary(data, env)
    with open(os.path.join(d, "summary.txt"), "w") as f:
        f.write(text + "\n")
    print(text, f"\nwrote {d}/summary.txt", sep="\n")
    try:
        chart(data, d)
    except ImportError:
        print("matplotlib not installed, skipping the chart")


if __name__ == "__main__":
    main()
