"""
controller.py -- the adaptive control plane. This is the process we run.

Once per second it:
    1. snapshots the srcstate and stats maps
    2. differences them into per-source behavioural features
    3. asks the detector (Random Forest, or thresholds) for a verdict
    4. hands the verdicts to the policy engine, which may write blocklist
       entries under its safety rails
    5. adjusts the global rate limit based on observed load
    6. garbage-collects expired blocks and idle source state
    7. redraws the live display

Run it:
    sudo python3 -m control.controller --iface veth-fw
    sudo python3 -m control.controller --dry-run      # decide, don't enforce
    sudo python3 -m control.controller --no-ml        # thresholds only
    sudo python3 -m control.controller --json         # machine-readable

KILL IT AND THE FIREWALL KEEPS RUNNING. The XDP program stays attached to the
interface and the maps stay pinned, so the last policy written remains in
force -- blocks still expire on schedule because the kernel checks the
deadlines itself.
"""

import argparse
import json
import os
import signal
import sys
import time

from . import schema
from .features import FeatureExtractor
from .firewall import Firewall
from .model import DEFAULT_MODEL_PATH, LABEL_MALICIOUS, get_detector
from .policy import AggressivenessController, PolicyEngine

# ANSI escapes. We redraw a full frame each cycle rather than using curses:
# curses fights with terminal resizing over ssh, and a plain redraw survives
# being piped into a file or a recording tool.
CLEAR = "\033[H\033[2J"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def human(n):
    """Compact number formatting so columns stay aligned at any magnitude."""
    n = float(n)
    for unit, div in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.1f}{unit}"
    return f"{n:.0f}"


class Controller:
    def __init__(self, args):
        self.args = args
        self.fw = Firewall(pin_dir=args.pin_dir)
        self.extractor = FeatureExtractor()
        self.detector, self.detector_note = get_detector(
            model_path=args.model, use_ml=not args.no_ml,
            threshold=args.confidence,
        )
        self.policy = PolicyEngine(self.fw, dry_run=args.dry_run)
        self.aggression = AggressivenessController(enabled=not args.no_auto_tune)

        self.running = True
        self.cycles = 0
        self.started = time.time()
        self._prev_stats = None
        self._prev_stats_t = None
        self.global_pps = 0.0
        self.global_drop_ratio = 0.0
        self.last_actions = []
        self.gc_counts = (0, 0)

        # Seed the allowlist so the operator cannot lock themselves out.
        for cidr in args.allow or []:
            self.fw.allow(cidr)

    # -- one cycle ---------------------------------------------------------

    def cycle(self):
        now_ns = self.fw.ktime_ns()
        now = time.time()

        states = self.fw.read_states()
        stats = self.fw.read_stats()

        # Global rates, differenced the same way per-source features are.
        if self._prev_stats is not None:
            dt = now - self._prev_stats_t
            if dt > 0.01:
                d_rx = stats["rx_packets"] - self._prev_stats["rx_packets"]
                d_drop = stats["drops_total"] - self._prev_stats["drops_total"]
                # Counters can go backwards if someone ran `fwctl reset`.
                if d_rx >= 0:
                    self.global_pps = d_rx / dt
                    self.global_drop_ratio = (d_drop / d_rx) if d_rx > 0 else 0.0
        self._prev_stats = stats
        self._prev_stats_t = now

        # Features -> verdicts -> actions.
        rows = self.extractor.update(states, now_ns)
        verdicts = self.detector.predict(rows) if rows else {}
        self.last_actions = self.policy.apply(verdicts, rows)

        # The non-ML adaptive loop.
        level, rate, burst, changed = self.aggression.evaluate(
            self.global_pps, self.global_drop_ratio
        )
        if changed and not self.args.dry_run:
            self.fw.update_config(rate_pps=rate, burst_pkts=burst,
                                  aggressiveness=level)
            self.policy._log(
                f"aggressiveness -> L{level} (rate {rate} pps, burst {burst})"
            )

        # Housekeeping. Both sweeps snapshot keys before deleting; see the
        # warning in bpfmap.BpfMap.keys about deleting mid-iteration.
        if self.cycles % 5 == 0 and not self.args.dry_run:
            self.gc_counts = (self.fw.gc_blocklist(), self.fw.gc_states())

        self.cycles += 1
        return rows, verdicts, stats

    # -- output ------------------------------------------------------------

    def render_json(self, rows, verdicts, stats):
        blocked = list(self.fw.list_blocked(include_expired=False))
        cfg = self.fw.read_config()
        print(json.dumps({
            "ts": time.time(),
            "cycle": self.cycles,
            "global": {
                "pps": round(self.global_pps, 1),
                "drop_ratio": round(self.global_drop_ratio, 4),
                "aggressiveness": self.aggression.level,
            },
            "config": {
                "rate_pps": cfg["rate_pps"],
                "burst_pkts": cfg["burst_pkts"],
                "features": schema.describe_features(cfg["features"]),
            },
            "stats": {k: v for k, v in stats.items()},
            "sources": {
                ip: {
                    "pps": round(r["pps"], 1),
                    "mean_len": round(r["mean_len"], 1),
                    "syn_ratio": round(r["syn_ratio"], 3),
                    "port_spread": r["port_spread"],
                    "verdict": ("malicious"
                                if verdicts.get(ip, (0,))[0] == LABEL_MALICIOUS
                                else "benign"),
                    "confidence": round(verdicts.get(ip, (0, 0.0))[1], 3),
                }
                for ip, r in rows.items()
            },
            "blocked": blocked,
            "actions": self.last_actions,
        }, default=str), flush=True)

    def render_tui(self, rows, verdicts, stats):
        cfg = self.fw.read_config()
        blocked = list(self.fw.list_blocked(include_expired=False))
        uptime = time.time() - self.started

        out = [CLEAR]
        mode = []
        if self.args.dry_run:
            mode.append(f"{YELLOW}DRY RUN (no enforcement){RESET}")
        if self.args.no_ml:
            mode.append(f"{DIM}thresholds only{RESET}")
        mode_s = ("  " + "  ".join(mode)) if mode else ""

        out.append(f"{BOLD}{CYAN} Adaptive XDP/eBPF Firewall {RESET}"
                   f"{DIM}-- control plane{RESET}{mode_s}")
        out.append(f"{DIM} {self.detector_note}{RESET}")
        out.append("")

        # --- global ---
        lvl = self.aggression.level
        lvl_colour = [GREEN, GREEN, YELLOW, RED][lvl]
        out.append(f"{BOLD} GLOBAL{RESET}   "
                   f"rx {human(self.global_pps)} pps   "
                   f"drop-ratio {self.global_drop_ratio * 100:5.1f}%   "
                   f"aggressiveness {lvl_colour}L{lvl}{RESET}   "
                   f"rate {cfg['rate_pps']} pps/src   "
                   f"burst {cfg['burst_pkts']}")
        out.append(f" {DIM}uptime {uptime:6.0f}s   cycles {self.cycles}   "
                   f"tracked {len(rows)} active   "
                   f"gc {self.gc_counts[0]}blk/{self.gc_counts[1]}st{RESET}")
        out.append("")

        # --- counters ---
        out.append(f"{BOLD} COUNTERS{RESET}")
        out.append(f"   rx {human(stats['rx_packets']):>7}   "
                   f"pass {human(stats['passes_total']):>7}   "
                   f"{RED}drop {human(stats['drops_total']):>7}{RESET}   "
                   f"{DIM}(allow {human(stats['pass_allowlist'])} | "
                   f"block {human(stats['drop_blocklist'])} | "
                   f"rate {human(stats['drop_ratelimit'])} | "
                   f"proto {human(stats['drop_proto'])} | "
                   f"bad {human(stats['drop_malformed'])}){RESET}")
        if stats["state_full"]:
            out.append(f"   {YELLOW}srcstate map full {stats['state_full']} "
                       f"times -- raise MAX_TRACKED in common.h{RESET}")
        out.append("")

        # --- per source ---
        out.append(f"{BOLD} SOURCES{RESET}  "
                   f"{DIM}(top {self.args.top} by packet rate){RESET}")
        out.append(f" {'source':<16}{'pps':>9}{'B/pkt':>8}{'syn%':>7}"
                   f"{'s/f':>7}{'ports':>7}{'drop%':>7}  verdict")
        out.append(f" {DIM}{'-' * 88}{RESET}")

        ranked = sorted(rows.items(), key=lambda kv: kv[1]["pps"], reverse=True)
        watching = self.policy.watching()

        for ip, r in ranked[: self.args.top]:
            label, conf, reason = verdicts.get(ip, (0, 0.0, ""))
            if self.fw.is_allowed(ip):
                tag = f"{GREEN}allowlisted{RESET}"
            elif self.fw.is_blocked(ip):
                tag = f"{RED}BLOCKED{RESET} {DIM}{reason}{RESET}"
            elif label == LABEL_MALICIOUS:
                strikes = watching.get(ip, 0)
                need = self.policy.CONSECUTIVE_WINDOWS_TO_BLOCK
                tag = (f"{YELLOW}malicious p={conf:.2f}{RESET} "
                       f"{DIM}[{strikes}/{need}] {reason}{RESET}")
            else:
                tag = f"{DIM}benign{RESET}"

            out.append(
                f" {ip:<16}{human(r['pps']):>9}{r['mean_len']:>8.0f}"
                f"{r['syn_ratio'] * 100:>7.0f}{min(r['syn_fin_ratio'], 999):>7.0f}"
                f"{int(r['port_spread']):>7}{r['_drop_ratio'] * 100:>7.0f}  {tag}"
            )

        if not ranked:
            out.append(f" {DIM}(no active sources -- send some traffic){RESET}")
        out.append("")

        # --- blocklist ---
        out.append(f"{BOLD} BLOCKLIST{RESET} {DIM}({len(blocked)} active){RESET}")
        for b in sorted(blocked, key=lambda b: b["hits"], reverse=True)[:8]:
            rem = "permanent" if b["remaining_s"] is None else f"{b['remaining_s']:5.0f}s left"
            out.append(f"   {RED}{b['cidr']:<20}{RESET}{rem:>14}   "
                       f"{human(b['hits']):>8} pkts dropped   "
                       f"{DIM}{b['reason']}{RESET}")
        if not blocked:
            out.append(f"   {DIM}(empty){RESET}")
        out.append("")

        # --- action log ---
        out.append(f"{BOLD} RECENT ACTIONS{RESET}")
        for ts, msg in self.policy.recent_actions[-6:]:
            out.append(f"   {DIM}{ts}{RESET}  {msg}")
        if not self.policy.recent_actions:
            out.append(f"   {DIM}(none yet){RESET}")

        out.append("")
        out.append(f" {DIM}Ctrl-C to stop. The firewall keeps running "
                   f"without this process.{RESET}")

        sys.stdout.write("\n".join(out) + "\n")
        sys.stdout.flush()

    # -- main loop ---------------------------------------------------------

    def run(self):
        def stop(signum, frame):
            self.running = False

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

        if not self.args.json:
            print(f"starting control plane: {self.detector_note}")
            print("collecting a baseline window...")

        while self.running:
            start = time.time()
            try:
                rows, verdicts, stats = self.cycle()
            except OSError as e:
                # A transient map error should not kill the control plane --
                # but if the firewall was unloaded underneath us, say so
                # plainly rather than spinning on errors forever.
                print(f"\n{RED}map error: {e}{RESET}", file=sys.stderr)
                if "ENOENT" in str(e) or "No such file" in str(e):
                    print("the firewall appears to have been unloaded; exiting",
                          file=sys.stderr)
                    break
                time.sleep(1)
                continue

            if self.args.json:
                self.render_json(rows, verdicts, stats)
            else:
                self.render_tui(rows, verdicts, stats)

            if self.args.once:
                break

            elapsed = time.time() - start
            time.sleep(max(0.0, self.args.interval - elapsed))

        if not self.args.json:
            print("\ncontrol plane stopped. "
                  "The XDP firewall is still attached and enforcing.")
            print(f"  blocks issued this session: "
                  f"{self.policy.stats['blocks_issued']}")
            print("  to unload the firewall:  sudo ./bin/fwload -i "
                  f"{self.args.iface or '<iface>'} -u")
        self.fw.close()


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="control.controller",
        description="Adaptive control plane for the XDP/eBPF firewall.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--iface", help="interface name (display only)")
    p.add_argument("--pin-dir", default=schema.PIN_DIR,
                   help=f"bpffs pin directory (default {schema.PIN_DIR})")
    p.add_argument("--interval", type=float, default=1.0,
                   help="seconds between polls (default 1.0)")
    p.add_argument("--model", default=DEFAULT_MODEL_PATH,
                   help="trained model bundle")
    p.add_argument("--confidence", type=float, default=0.75,
                   help="minimum P(malicious) before acting (default 0.75)")
    p.add_argument("--no-ml", action="store_true",
                   help="use the static-threshold baseline instead of the model")
    p.add_argument("--no-auto-tune", action="store_true",
                   help="disable load-based aggressiveness scaling")
    p.add_argument("--dry-run", action="store_true",
                   help="classify and report, but never write to the maps")
    p.add_argument("--allow", action="append", metavar="CIDR",
                   help="add to the allowlist at startup (repeatable)")
    p.add_argument("--top", type=int, default=12,
                   help="how many sources to show (default 12)")
    p.add_argument("--json", action="store_true",
                   help="emit one JSON object per cycle instead of the display")
    p.add_argument("--once", action="store_true",
                   help="run a single cycle and exit")
    args = p.parse_args(argv)

    if os.geteuid() != 0:
        print("error: BPF map access requires root. Re-run with sudo.",
              file=sys.stderr)
        return 1

    try:
        Controller(args).run()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
