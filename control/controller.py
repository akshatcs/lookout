"""The adaptive control plane.

Once a second it reads the per-source counters, flags sources that behave
like floods or scans, blocks the persistent ones, adjusts the per-source
rate limit to the current load, cleans up stale map entries, and redraws
the screen. It never touches the port rules or the default policy; those
are the operator's (fwctl port / fwctl policy).

    sudo python3 -m control.controller --iface veth-fw
    sudo python3 -m control.controller --dry-run     # decide, don't write

Stopping it doesn't stop the firewall. The XDP program and its maps stay in
the kernel with the last policy written, and blocks still expire on time
because the kernel checks the deadlines itself.
"""

import argparse
import os
import signal
import sys
import time

from .detect import Window, classify
from .firewall import ACTIONS, LIMITER_INPUT, Firewall, ktime_ns
from .fwctl import BOLD, CLEAR, DIM, GREEN, RED, RESET, YELLOW, human
from .policy import Aggressiveness, Blocker


class Controller:
    def __init__(self, args):
        self.args = args
        self.fw = Firewall()
        self.window = Window()
        self.blocker = Blocker(self.fw, dry_run=args.dry_run)
        self.aggr = Aggressiveness()
        self.cycles = 0
        self.prev = None        # (stats, monotonic time) from the last step
        self.pps = 0.0
        self.drop_ratio = 0.0
        for cidr in args.allow or []:
            self.fw.allow(cidr)

    def step(self):
        stats, now = self.fw.read_stats(), time.monotonic()
        rows = self.window.update(self.fw.read_states(), ktime_ns())
        verdicts = {ip: classify(r) for ip, r in rows.items()}
        self.blocker.update(verdicts)

        # Load over the last interval: the packets that reached the rate
        # limiter. Traffic the allowlist, blocklist, port rules or default
        # policy have already decided doesn't count; squeezing everyone's
        # rate limit wouldn't change anything about it. A negative delta
        # means someone ran `fwctl reset`; skip that interval.
        if self.prev:
            old, then = self.prev
            delta = {k: stats[k] - old[k] for k in stats}
            load = sum(delta[k] for k in LIMITER_INPUT)
            if delta["rx_packets"] >= 0 and load >= 0 and now > then:
                self.pps = load / (now - then)
                self.drop_ratio = delta["drop_ratelimit"] / load if load else 0.0
        self.prev = stats, now

        if not self.args.no_auto_tune and self.aggr.update(self.pps, self.drop_ratio):
            rate, burst = self.aggr.limits
            if not self.args.dry_run:
                self.fw.update_config(rate_pps=rate, burst_pkts=burst,
                                      aggressiveness=self.aggr.level)
            verb = "would set" if self.args.dry_run else "aggressiveness ->"
            self.blocker.note(f"{verb} L{self.aggr.level} (rate {rate} pps, burst {burst})")

        if self.cycles % 5 == 0 and not self.args.dry_run:
            self.fw.remove_expired_blocks()
            self.fw.remove_idle_states()
        self.cycles += 1
        return rows, verdicts, stats

    def draw(self, rows, verdicts, stats):
        cfg = self.fw.read_config()
        blocked = sorted(self.fw.list_blocked(), key=lambda b: -b["hits"])
        lvl = self.aggr.level
        mode = f"  {YELLOW}DRY RUN (nothing is written){RESET}" if self.args.dry_run else ""

        out = [CLEAR + f"{BOLD} Adaptive XDP firewall{RESET}{DIM} - control plane{RESET}{mode}", ""]
        out.append(f"{BOLD} LOAD{RESET}     {human(self.pps)} pps at the rate limiter   "
                   f"rate-limited {self.drop_ratio * 100:5.1f}%   "
                   f"aggressiveness {[GREEN, GREEN, YELLOW, RED][lvl]}L{lvl}{RESET}"
                   f"{' (not applied)' if self.args.dry_run else ''}   "
                   f"rate {cfg['rate_pps']} pps/src   burst {cfg['burst_pkts']}   "
                   f"policy {ACTIONS[cfg['default_policy']]}")
        out.append(f"{BOLD} COUNTERS{RESET} rx {human(stats['rx_packets'])}   "
                   f"pass {human(stats['passes_total'])}   "
                   f"{RED}drop {human(stats['drops_total'])}{RESET}   "
                   f"{DIM}(blocklist {human(stats['drop_blocklist'])} | "
                   f"port rule {human(stats['drop_port_rule'])} | "
                   f"default {human(stats['drop_default'])} | "
                   f"rate {human(stats['drop_ratelimit'])} | "
                   f"flags {human(stats['drop_proto'])} | "
                   f"bad {human(stats['drop_malformed'])}){RESET}")
        if stats["state_full"]:
            out.append(f"   {YELLOW}srcstate map full {stats['state_full']:,} times{RESET}")

        out += ["", f"{BOLD} SOURCES{RESET}",
                f" {'source':<16}{'pps':>9}{'B/pkt':>8}{'syn%':>7}{'s/f':>7}"
                f"{'ports':>7}{'drop%':>7}  status"]
        ranked = sorted(rows.items(), key=lambda kv: -kv[1]["pps"])[:self.args.top]
        for ip, r in ranked:
            reason = verdicts.get(ip)
            if self.fw.is_allowed(ip):
                tag = f"{GREEN}allowlisted{RESET}"
            elif self.fw.is_blocked(ip):
                tag = f"{RED}BLOCKED{RESET}"
            elif self.blocker.is_blocked(ip):     # only happens in a dry run
                tag = f"{YELLOW}would be blocked{RESET}"
            elif reason:
                n = self.blocker.strikes.get(ip, 0)
                tag = f"{YELLOW}{reason}{RESET} {DIM}[{n}/{Blocker.STRIKES}]{RESET}"
            else:
                tag = f"{DIM}ok{RESET}"
            out.append(f" {ip:<16}{human(r['pps']):>9}{r['mean_len']:>8.0f}"
                       f"{r['syn_ratio'] * 100:>7.0f}{min(r['syn_fin_ratio'], 999):>7.0f}"
                       f"{r['port_spread']:>7}{r['drop_ratio'] * 100:>7.0f}  {tag}")
        if not ranked:
            out.append(f" {DIM}(no traffic in the last second){RESET}")

        out += ["", f"{BOLD} BLOCKLIST{RESET} {DIM}({len(blocked)} active){RESET}"]
        for b in blocked[:8]:
            left = "permanent" if b["remaining_s"] is None else f"{b['remaining_s']:.0f}s left"
            out.append(f"   {RED}{b['cidr']:<20}{RESET}{left:>14}   "
                       f"{human(b['hits']):>8} pkts dropped   {DIM}{b['reason']}{RESET}")

        out += ["", f"{BOLD} RECENT ACTIONS{RESET}"]
        out += [f"   {DIM}{ts}{RESET}  {msg}" for ts, msg in list(self.blocker.log)[-6:]]
        out += ["", f" {DIM}Ctrl-C to stop. The firewall keeps running without this process.{RESET}"]
        print("\n".join(out), flush=True)

    def run(self):
        running = True

        def stop(*_):
            nonlocal running
            running = False
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

        while running:
            start = time.time()
            self.draw(*self.step())
            time.sleep(max(0.0, self.args.interval - (time.time() - start)))

        print("\ncontrol plane stopped. The XDP firewall is still attached and enforcing.")
        what = "would have blocked" if self.args.dry_run else "blocks issued"
        print(f"  {what} this session: {self.blocker.blocks_issued}")
        print(f"  to unload it: sudo ./bin/fwload -i {self.args.iface} -u")
        self.fw.close()


def main(argv=None):
    p = argparse.ArgumentParser(prog="control.controller",
                                description="Adaptive control plane for the XDP firewall.")
    p.add_argument("--iface", default="veth-fw", help="only used in messages")
    p.add_argument("--interval", type=float, default=1.0, help="seconds per cycle")
    p.add_argument("--dry-run", action="store_true",
                   help="show decisions but never write to the maps")
    p.add_argument("--no-auto-tune", action="store_true",
                   help="leave the rate limit alone")
    p.add_argument("--allow", action="append", metavar="CIDR",
                   help="allowlist this at startup (repeatable)")
    p.add_argument("--top", type=int, default=12, help="sources to show")
    args = p.parse_args(argv)

    if os.geteuid() != 0:
        sys.exit("error: needs root, re-run with sudo")
    try:
        Controller(args).run()
    except OSError as e:
        sys.exit(f"error: {e.strerror or e}")


if __name__ == "__main__":
    main()
