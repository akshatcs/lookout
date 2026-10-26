#!/usr/bin/env python3
"""Summarise the evaluation experiments.

    python3 bench/eval_report.py results/collateral-<stamp>
    python3 bench/eval_report.py results/detection-<stamp>

Writes summary.txt next to the data and the figures:
  collateral  stack.png    attack traffic reaching the network stack, and the
                           CPU spent receiving packets, for each system
              latency.png  how the normal client's response times were spread
  detection   detection.png  which attack rates and normal clients were blocked

A detection run whose sender reached less than half the requested rate is
flagged and left out: it did not test that rate.
"""

import csv
import glob
import os
import re
import statistics
import sys
from collections import defaultdict

TIMEOUT_MS = 3000       # bench/clients.py gives up on a request after 3 s
SLOW_MS = 100           # on this testbed, slower than this means TCP had to
                        # retransmit (its minimum timeout is 200 ms)
SYSTEMS = ["none", "nft-ingress", "xdp", "xdp-adaptive"]
LABELS = {"none": "no firewall", "nft-ingress": "nftables (ingress), fixed limit",
          "xdp": "XDP, fixed limit", "xdp-adaptive": "XDP + adaptive controller"}
# same entities, same colours as cpu.png; the adaptive system takes the next
# slot in the fixed categorical order
COLOURS = {"none": "#2a78d6", "nft-ingress": "#1baf7a", "xdp": "#eda100",
           "xdp-adaptive": "#e87ba4"}
ATTACKS = {"single": "SYN flood, one source",
           "spread": "UDP flood, 100 sources",
           "random": "SYN flood, 65,000 random sources"}
DASHES = {"none": (None, None), "nft-ingress": (6, 2), "xdp": (2, 2),
          "xdp-adaptive": (6, 2, 2, 2)}
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e1"


def rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def pct(values, q):
    """Nearest-rank percentile; nan for no values."""
    if not values:
        return float("nan")
    v = sorted(values)
    return v[min(len(v) - 1, max(0, round(q * len(v)) - 1))]


def figure(ncols, width, height):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 9, "axes.labelcolor": MUTED,
                         "xtick.color": MUTED, "ytick.color": MUTED})
    fig, axes = plt.subplots(1, ncols, figsize=(width, height), squeeze=False)
    for ax in axes[0]:
        ax.set_axisbelow(True)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(GRID)
        ax.tick_params(length=0)
    return plt, fig, axes[0]


def save(plt, fig, d, name):
    fig.savefig(os.path.join(d, name), dpi=160)
    plt.close(fig)
    print(f"wrote {d}/{name}")


def first_block(watch_path, start, prefix):
    """Seconds from start until prefix first shows in the blocklist."""
    if not os.path.exists(watch_path):
        return None
    for w in rows(watch_path):
        if prefix in w["blocked"].split():
            return float(w["time"]) - start
    return None


# ---------------------------------------------------------------- collateral

WINDOWS = [("before", -10, 0), ("first 5 s", 0, 5), ("5-40 s", 5, 40)]


def collateral(d, ncpu):
    runs = rows(os.path.join(d, "runs.csv"))
    by = defaultdict(list)          # (attack, system) -> [run rows]
    for r in runs:
        by[(r["attack"], r["system"])].append(r)
    attacks = [a for a in ATTACKS if any(k[0] == a for k in by)]

    out = ["Normal client during an attack (requests pooled over all runs)",
           "-" * 62,
           "ok: requests answered within 3 s. p50/p99: response time of the answered",
           f"ones. slow: requests slower than {SLOW_MS} ms or unanswered (here that means TCP",
           "retransmitted). attack pps: what the sender managed. at IP: packets per",
           "second reaching the IP layer. softirq: share of all CPU time spent in",
           "the receive path. ns/pkt: that CPU time per attack packet received (the",
           "benchmark's measure). All three over the attack; medians of the runs.", ""]
    dist, load = {}, {}
    for a in attacks:
        out.append(f"{ATTACKS[a]}")
        out.append(f"  {'system':<14}{'attack pps':>11}{'at IP':>9}{'softirq':>9}{'ns/pkt':>8}"
                   + "".join(f"{w:>31}" for w, _, _ in WINDOWS))
        out.append(f"  {'':<14}{'':>11}{'':>9}{'':>9}{'':>8}"
                   + "".join(f"{'ok':>8}{'p50 ms':>8}{'p99 ms':>8}{'slow':>7}" for _ in WINDOWS))
        for s in SYSTEMS:
            rs = by.get((a, s))
            if not rs:
                continue
            reqs, blocks, tiers = [], [], []
            for r in rs:
                tag, start = f"{s}-{a}-{r['run']}", float(r["attack_start"])
                reqs += [(float(p["time"]) - start, p["ok"] == "1",
                          float(p["latency_ms"] or TIMEOUT_MS))
                         for p in rows(os.path.join(d, f"probe-{tag}.csv"))]
                wp = os.path.join(d, f"watch-{tag}.csv")
                if s == "xdp-adaptive" and os.path.exists(wp):
                    w = rows(wp)
                    t = next((float(x["time"]) - start for x in w if x["blocked"]), None)
                    blocks.append(t)
                    tiers.append(max(int(x["tier"]) for x in w))
            cells = []
            for _, lo, hi in WINDOWS:
                win = [q for q in reqs if lo <= q[0] < hi]
                ok = [q[2] for q in win if q[1]]
                slow = sum(1 for q in win if not q[1] or q[2] > SLOW_MS)
                cells.append(f"{100 * len(ok) / len(win):>7.1f}%{pct(ok, .5):>8.1f}"
                             f"{pct(ok, .99):>8.1f}{100 * slow / len(win):>6.1f}%"
                             if win else f"{'-':>31}")
            med = lambda f: statistics.median(float(r[f]) for r in rs)
            load[(a, s)] = {f: (med(f), min(float(r[f]) for r in rs),
                                max(float(r[f]) for r in rs))
                            for f in ("ip_pps", "softirq_pct")}
            ns = statistics.median(float(r["softirq_pct"]) / 100 * ncpu * 1e9
                                   / float(r["attack_pps"]) for r in rs)
            out.append(f"  {s:<14}{med('attack_pps'):>11,.0f}{med('ip_pps'):>9,.0f}"
                       f"{med('softirq_pct'):>8.1f}%{ns:>8,.0f}" + "".join(cells))
            if s == "xdp-adaptive":
                got = [b for b in blocks if b is not None]
                out.append(f"  {'':<14}controller: highest tier L{max(tiers)}; "
                           + (f"first block {statistics.median(got):.1f} s after the "
                              f"attack began (median of {len(got)})" if got else
                              "blocked nothing"))
            # every response time during the attack, failures as the timeout
            dist[(a, s)] = sorted(ms if ok else TIMEOUT_MS
                                  for t, ok, ms in reqs if 0 <= t < 40)
        out.append("")
    return "\n".join(out), dist, load, attacks


def stack_chart(load, attacks, d):
    """Where each system stops the attack: packets that still reach the
    network stack, and the CPU spent receiving."""
    plt, fig, axes = figure(2, 11.5, 4.0)
    panels = [("ip_pps", 1e-3, "attack packets reaching the network stack\n(thousands per second)", "{:.0f}k"),
              ("softirq_pct", 1, "CPU spent receiving packets\n(% of all CPU time)", "{:.1f}%")]
    width = 0.8 / len(SYSTEMS)
    for ax, (field, scale, label, fmt) in zip(axes, panels):
        for i, s in enumerate(SYSTEMS):
            xs, vals, lo, hi = [], [], [], []
            for j, a in enumerate(attacks):
                if (a, s) not in load:
                    continue
                m, mn, mx = (v * scale for v in load[(a, s)][field])
                xs.append(j + (i - (len(SYSTEMS) - 1) / 2) * width)
                vals.append(m)
                lo.append(m - mn)
                hi.append(mx - m)
            bars = ax.bar(xs, vals, width * 0.9, color=COLOURS[s], label=LABELS[s],
                          yerr=[lo, hi], error_kw={"ecolor": MUTED, "elinewidth": 0.8,
                                                   "capsize": 2})
            for b, v, e in zip(bars, vals, hi):
                txt = f"{v:.1f}k" if field == "ip_pps" and v < 10 else fmt.format(v)
                ax.annotate(txt, (b.get_x() + b.get_width() / 2, v + e), ha="center",
                            va="bottom", fontsize=6.5, color=INK, xytext=(0, 2),
                            textcoords="offset points")
        ax.set_xticks(range(len(attacks)))
        ax.set_xticklabels([ATTACKS[a].replace(", ", ",\n") for a in attacks])
        ax.set_ylabel(label)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels), frameon=False,
               fontsize=8)
    fig.text(0.01, 0.99, "Lower is better. Over the 40 s of each attack; median of three "
             "runs, bars show min-max.", fontsize=7.5, color=MUTED, va="top")
    fig.tight_layout(rect=(0, 0.07, 1, 0.96))
    save(plt, fig, d, "stack.png")


def latency_chart(dist, attacks, d):
    plt, fig, axes = figure(len(attacks), 4.4 * len(attacks), 3.9)
    for ax, a in zip(axes, attacks):
        ax.axvline(200, color=MUTED, linewidth=0.8, linestyle=":")
        ax.text(215, 0.55, "TCP\nretransmits\n(200 ms)", color=MUTED, fontsize=7,
                va="top")
        for s in SYSTEMS:
            v = dist.get((a, s))
            if not v:
                continue
            # share of requests slower than x: a step down at every response
            n = len(v)
            ax.step(v, [1 - (i + 1) / n for i in range(n)], where="post",
                    color=COLOURS[s], linewidth=1.6, label=LABELS[s],
                    dashes=DASHES[s] if DASHES[s][0] else (None, None))
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlim(0.5, 4000)
        ax.set_ylim(5e-4, 1.2)
        ax.set_title(ATTACKS[a], loc="left", fontsize=10, color=INK)
        ax.set_xlabel("response time (ms)")
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        if ax is not axes[0]:
            ax.set_yticklabels([])
    axes[0].set_ylabel("share of requests slower than this")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels), frameon=False,
               fontsize=8)
    fig.text(0.01, 0.99, "Requests made during the attack, all runs pooled. Lower and "
             "further left is better; unanswered requests count as 3,000 ms.",
             fontsize=7.5, color=MUTED, va="top")
    fig.tight_layout(rect=(0, 0.08, 1, 0.95))
    save(plt, fig, d, "latency.png")


# ---------------------------------------------------------------- detection

def from_log(log, src):
    """From the controller's screen output: the reasons it blocked src for,
    the highest packets/s it measured for src, and the median share of
    src's packets the firewall dropped in the seconds src was not blocked."""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", open(log, errors="replace").read())
    why = set(re.findall(rf"BLOCKED {re.escape(src)} for \d+s \(([^)]+)\)", text))
    scale = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9}
    # source  pps  B/pkt  syn%  s/f  ports  drop%  status
    seen = re.findall(rf"^ {re.escape(src)}\s+([\d.]+)([kMG]?)(?:\s+\d+){{4}}\s+(\d+)\s+(\S+)",
                      text, re.M)
    peak = max((float(n) * scale[u] for n, u, _, _ in seen), default=0.0)
    drops = [int(p) for _, _, p, status in seen if status != "BLOCKED"]
    return why, peak, statistics.median(drops) if drops else 0


# what each attack row is called in the figure, and its rule's threshold in
# packets per second (the scan rule counts ports, not a rate)
ATTACK_ROWS = {"syn_flood": ("SYN flood", 40, "> 40 SYNs/s that never close"),
               "udp_flood": ("UDP flood", 8000, "> 8,000 pps, small packets"),
               "icmp_flood": ("ICMP flood", 2000, "> 2,000 pps"),
               "port_scan": ("port scan", None, "> 24 ports in total, any rate")}
NORMAL_ROWS = {("browse", "-"): "page loads",
               ("download", "-"): "large download",
               ("upload", "-"): "large upload",
               ("nat", "100"): "100 users, one address",
               ("nat", "1000"): "1,000 users, one address",
               ("udp", "1000"): "UDP client, 1,000 pps",
               ("udp", "10000"): "UDP client, 10,000 pps",
               ("services", "-"): "a new port every second"}


def valid(r):
    """False if the sender reached less than half the requested rate."""
    return not (r["kind"] == "attack" and r["setting"] != "max"
                and float(r["rx_pps"]) < 0.5 * float(r["setting"]))


def detection(d):
    by = defaultdict(list)
    for r in rows(os.path.join(d, "runs.csv")):
        by[(r["kind"], r["traffic"], r["setting"])].append(r)
    out, points = [], []
    for kind, title in (("attack", "Attacks: is the source blocked, and how fast?"),
                        ("normal", "Normal clients: is the source wrongly blocked?")):
        keys = [k for k in by if k[0] == kind]
        if not keys:
            continue
        out += [title, "-" * len(title),
                f"  {'traffic':<11}{'setting':>8}{'peak pps':>10}{'bytes':>7}{'dropped':>9}"
                f"{'blocked':>9}{'time to block':>15}  rule"]
        for k in keys:
            rs = [r for r in by[k] if valid(r)]
            if not rs:
                sent = statistics.median(float(r["rx_pps"]) for r in by[k])
                out.append(f"  {k[1]:<11}{k[2]:>8}   not measured: the sender reached only "
                           f"{sent:g} pps in all {len(by[k])} runs")
                continue
            times, why, peaks, drops = [], set(), [], []
            for r in rs:
                tag = f"{k[1]}-{k[2]}-{r['run']}"
                reason, peak, dropped = from_log(
                    os.path.join(d, f"controller-{tag}.log"), r["source"])
                peaks.append(peak)
                drops.append(dropped)
                t = first_block(os.path.join(d, f"watch-{tag}.csv"),
                                float(r["start"]), r["source"] + "/32")
                if t is not None:
                    times.append(t)
                    why |= reason
            when = (f"{statistics.median(times):.1f} s" if len(times) == len(rs) else
                    f"{statistics.median(times):.1f} s*" if times else "-")
            mean_bytes = statistics.median(float(r["mean_bytes"]) for r in rs)
            skipped = len(by[k]) - len(rs)
            out.append(f"  {k[1]:<11}{k[2]:>8}{statistics.median(peaks):>10,.0f}"
                       f"{mean_bytes:>7.0f}{statistics.median(drops):>8.0f}%"
                       f"{len(times):>5}/{len(rs):<3}"
                       f"{when:>15}  {', '.join(sorted(why))}"
                       + (f"  ({skipped} run(s) left out)" if skipped else ""))
            points.append((k, statistics.median(peaks), len(times), len(rs)))
        out.append("")
    out.append("setting: target packets per second (max = as fast as hping3 can) for")
    out.append("attacks; ports per second for port_scan; users or packets per second for")
    out.append("normal clients. peak pps: the highest one-second rate the controller")
    out.append("measured for the source (median over runs), which is what the rules see.")
    out.append("bytes: mean packet size. dropped: share of the source's packets the")
    out.append("firewall dropped in a typical second before any block (rate limiting).")
    out.append("Time to block is the median from the first packet; * means only some")
    out.append("runs were blocked, and the median is of those. A run whose sender")
    out.append("reached less than half the requested rate is left out.")
    return "\n".join(out), points


def detection_chart(points, d):
    """One row per attack type (a dot per rate) and per normal client: filled
    if the source was blocked in every run, hollow if in none."""
    labels, ys = [], {}
    for t in ATTACK_ROWS:
        if any(k[1] == t for k, *_ in points if k[0] == "attack"):
            ys[("attack", t)] = len(labels)
            labels.append(ATTACK_ROWS[t][0])
    gap = len(labels)
    labels.append("")
    for key, name in NORMAL_ROWS.items():
        if any(k[1:] == key for k, *_ in points if k[0] == "normal"):
            ys[("normal",) + key] = len(labels)
            labels.append(name)
    plt, fig, axes = figure(1, 10.5, 0.36 * len(labels) + 1.5)
    ax = axes[0]
    colour = COLOURS["none"]
    for k, peak, blocked, n in points:
        y = ys[("attack", k[1])] if k[0] == "attack" else ys[k]
        full = blocked == n
        ax.scatter([max(peak, 1)], [y], s=46, zorder=3, linewidths=1.4,
                   facecolors=colour if full else "white", edgecolors=colour,
                   marker="o" if full or blocked == 0 else "D")
    for t, (_, thr, rule) in ATTACK_ROWS.items():
        if ("attack", t) not in ys:
            continue
        y = ys[("attack", t)]
        if thr:
            ax.plot([thr, thr], [y - 0.35, y + 0.35], color=INK, linewidth=1.2)
        ax.annotate(f"rule: {rule}", (1.02, y), xycoords=("axes fraction", "data"),
                    ha="left", va="center", fontsize=7.5, color=MUTED)
    ax.axhline(gap, color=GRID, linewidth=0.8)
    ax.text(0.8, -0.75, "attacks (one dot per rate tried)", fontsize=7.5, color=MUTED)
    ax.text(0.8, gap + 0.38, "normal clients (should never be blocked)", fontsize=7.5,
            color=MUTED)
    ax.set_xscale("log")
    ax.set_xlim(0.7, 2.2e6)
    ax.set_ylim(len(labels) - 0.5, -1.1)
    ax.set_yticks([y for y, l in enumerate(labels) if l])
    ax.set_yticklabels([l for l in labels if l])
    ax.set_xlabel("highest packets per second the controller measured for the source")
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    from matplotlib.lines import Line2D
    handles = [Line2D([], [], marker="o", linestyle="", markersize=7, color=colour,
                      label="blocked in every run"),
               Line2D([], [], marker="o", linestyle="", markersize=7, color=colour,
                      markerfacecolor="white", label="never blocked"),
               Line2D([], [], color=INK, linewidth=1.2, label="rule's threshold")]
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, fontsize=8)
    fig.text(0.01, 0.995, "Each source sent for 30 s; three runs each.", fontsize=7.5,
             color=MUTED, va="top")
    fig.tight_layout(rect=(0, 0.05, 0.8, 0.97))
    save(plt, fig, d, "detection.png")


def main():
    if len(sys.argv) != 2 or not os.path.isfile(os.path.join(sys.argv[1], "runs.csv")):
        sys.exit(__doc__)
    d = sys.argv[1]
    env = open(os.path.join(d, "environment.txt")).read().rstrip()
    if glob.glob(os.path.join(d, "probe-*.csv")):
        m = re.search(r"^cpus\s+(\d+)", env, re.M)
        text, dist, load, attacks = collateral(d, int(m.group(1)) if m else 1)
        charts = [lambda: stack_chart(load, attacks, d),
                  lambda: latency_chart(dist, attacks, d)]
    else:
        text, points = detection(d)
        charts = [lambda: detection_chart(points, d)]
    text = f"environment\n-----------\n{env}\n\n{text}"
    with open(os.path.join(d, "summary.txt"), "w") as f:
        f.write(text + "\n")
    print(text, f"\nwrote {d}/summary.txt", sep="\n")
    try:
        for draw in charts:
            draw()
    except ImportError:
        print("matplotlib not installed, skipping the figures")


if __name__ == "__main__":
    main()
