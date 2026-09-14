"""
fwctl.py -- command-line control for the running firewall.

This is the "userspace control program" from the project deliverables, and it
is what we drive the first half of the demo with. It talks to the same pinned
maps as the adaptive controller, so we can run both at once: block something
by hand here and watch it appear in the controller's live display.

    sudo python3 -m control.fwctl status
    sudo python3 -m control.fwctl allow add 10.10.1.2
    sudo python3 -m control.fwctl block add 10.10.1.3 --duration 60
    sudo python3 -m control.fwctl block list
    sudo python3 -m control.fwctl top
    sudo python3 -m control.fwctl config set --rate 1000 --burst 2000
    sudo python3 -m control.fwctl stats --watch
    sudo python3 -m control.fwctl reset
"""

import argparse
import os
import struct
import sys
import time

from . import schema
from .firewall import Firewall

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
)


def human(n):
    n = float(n)
    for unit, div in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.1f}{unit}"
    return f"{n:.0f}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(fw, args):
    cfg = fw.read_config()
    stats = fw.read_stats()
    n_allow = fw.allowlist.count()
    blocked = list(fw.list_blocked(include_expired=False))
    n_state = fw.srcstate.count()

    print(f"{BOLD}firewall status{RESET}")
    print(f"  pin dir        {fw.pin_dir}")
    print(f"  rate limit     {cfg['rate_pps']} pps/source, "
          f"burst {cfg['burst_pkts']}")
    print(f"  aggressiveness L{cfg['aggressiveness']}")
    print(f"  features       {schema.describe_features(cfg['features'])}")
    print(f"  allowlist      {n_allow} entries")
    print(f"  blocklist      {len(blocked)} active")
    print(f"  tracked srcs   {n_state} / {schema.MAX_TRACKED}")
    print()
    print(f"{BOLD}counters{RESET}")
    print(f"  received       {stats['rx_packets']:>14,}  "
          f"({human(stats['rx_bytes'])}B)")
    print(f"  {GREEN}passed{RESET}         {stats['passes_total']:>14,}")
    print(f"  {RED}dropped{RESET}        {stats['drops_total']:>14,}")
    for name in schema.DROP_STATS:
        if stats[name]:
            print(f"    {name:<18} {stats[name]:>12,}")
    if stats["state_full"]:
        print(f"  {YELLOW}state map full {stats['state_full']:,} times{RESET}")
    return 0


def cmd_allow(fw, args):
    if args.allow_cmd == "add":
        for cidr in args.cidr:
            fw.allow(cidr)
            print(f"{GREEN}allowed{RESET} {cidr}")
    elif args.allow_cmd == "del":
        for cidr in args.cidr:
            ok = fw.unallow(cidr)
            print(f"{'removed' if ok else 'not found:'} {cidr}")
    else:
        entries = list(fw.list_allowed())
        if not entries:
            print("(allowlist is empty)")
            return 0
        print(f"{BOLD}{'prefix':<22}{'hits':>14}{RESET}")
        for e in sorted(entries, key=lambda e: e["hits"], reverse=True):
            print(f"{e['cidr']:<22}{e['hits']:>14,}")
    return 0


def cmd_block(fw, args):
    if args.block_cmd == "add":
        for cidr in args.cidr:
            # Refuse to block something that is allowlisted. The kernel would
            # ignore the entry anyway (allowlist is checked first), so silently
            # accepting it would be misleading.
            ip = cidr.split("/")[0]
            if fw.is_allowed(ip):
                print(f"{YELLOW}refused{RESET} {cidr}: it is allowlisted. "
                      f"Remove it from the allowlist first.")
                continue
            fw.block(cidr, duration_s=args.duration,
                     reason=schema.BLOCK_REASON_MANUAL)
            how = ("permanently" if args.duration <= 0
                   else f"for {args.duration:g}s")
            print(f"{RED}blocked{RESET} {cidr} {how}")
    elif args.block_cmd == "del":
        for cidr in args.cidr:
            ok = fw.unblock(cidr)
            print(f"{'unblocked' if ok else 'not found:'} {cidr}")
    elif args.block_cmd == "flush":
        keys = list(fw.blocklist.keys())
        for k in keys:
            fw.blocklist.delete(k)
        print(f"removed {len(keys)} blocklist entries")
    else:
        entries = list(fw.list_blocked(include_expired=args.all))
        if not entries:
            print("(blocklist is empty)")
            return 0
        print(f"{BOLD}{'prefix':<20}{'remaining':>12}{'hits':>14}"
              f"  {'reason':<12}{RESET}")
        for e in sorted(entries, key=lambda e: e["hits"], reverse=True):
            if e["expired"]:
                rem = "EXPIRED"
            elif e["remaining_s"] is None:
                rem = "permanent"
            else:
                rem = f"{e['remaining_s']:.0f}s"
            print(f"{e['cidr']:<20}{rem:>12}{e['hits']:>14,}  {e['reason']:<12}")
    return 0


def cmd_top(fw, args):
    """Show live per-source state straight from the kernel map.

    Unlike the controller's display this shows CUMULATIVE totals, not rates.
    It is the rawest possible view of the map and is useful for convincing
    yourself the kernel side works before any Python logic is involved.
    """
    def once():
        states = fw.read_states()
        ranked = sorted(states.items(), key=lambda kv: kv[1]["packets"],
                        reverse=True)[: args.count]
        print(f"{BOLD}{'source':<16}{'packets':>12}{'bytes':>10}"
              f"{'dropped':>10}{'syn':>9}{'udp':>9}{'icmp':>8}"
              f"{'tokens':>9}{'ports':>7}{RESET}")
        for ip, s in ranked:
            ports = bin(s["port_bitmap"]).count("1")
            print(f"{ip:<16}{s['packets']:>12,}{human(s['bytes']):>10}"
                  f"{s['dropped']:>10,}{s['syn']:>9,}{s['udp']:>9,}"
                  f"{s['icmp']:>8,}{s['tokens']:>9,}{ports:>7}")
        if not ranked:
            print(f"{DIM}(no tracked sources){RESET}")

    if args.watch:
        try:
            while True:
                sys.stdout.write("\033[H\033[2J")
                once()
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        once()
    return 0


def cmd_config(fw, args):
    if args.config_cmd == "set":
        changes = {}
        if args.rate is not None:
            changes["rate_pps"] = args.rate
        if args.burst is not None:
            changes["burst_pkts"] = args.burst
        if args.aggressiveness is not None:
            changes["aggressiveness"] = args.aggressiveness

        cfg = fw.read_config()
        feats = cfg["features"]
        for name, bit in (("allowlist", schema.FEAT_ALLOWLIST),
                          ("blocklist", schema.FEAT_BLOCKLIST),
                          ("proto", schema.FEAT_PROTO_SANITY),
                          ("ratelimit", schema.FEAT_RATELIMIT),
                          ("state", schema.FEAT_TRACK_STATE),
                          ("frags", schema.FEAT_DROP_FRAGS)):
            if name in (args.enable or []):
                feats |= bit
            if name in (args.disable or []):
                feats &= ~bit
        changes["features"] = feats

        cfg = fw.update_config(**changes)
        print(f"rate {cfg['rate_pps']} pps/src, burst {cfg['burst_pkts']}, "
              f"L{cfg['aggressiveness']}")
        print(f"features: {schema.describe_features(cfg['features'])}")
    else:
        cfg = fw.read_config()
        print(f"rate_pps        {cfg['rate_pps']}")
        print(f"burst_pkts      {cfg['burst_pkts']}")
        print(f"aggressiveness  L{cfg['aggressiveness']}")
        print(f"features        {schema.describe_features(cfg['features'])}")
        print(f"default_action  "
              f"{'PASS' if cfg['default_action'] == schema.XDP_PASS else 'DROP'}")
    return 0


def cmd_stats(fw, args):
    """Print counters, optionally as a repeating rate view."""
    if not args.watch:
        stats = fw.read_stats()
        width = max(len(n) for n in schema.STAT_NAMES)
        for name in schema.STAT_NAMES:
            print(f"{name:<{width}}  {stats[name]:>16,}")
        return 0

    prev, prev_t = None, None
    try:
        while True:
            stats = fw.read_stats()
            now = time.time()
            sys.stdout.write("\033[H\033[2J")
            print(f"{BOLD}{'counter':<18}{'total':>16}{'per second':>14}{RESET}")
            for name in schema.STAT_NAMES:
                rate = ""
                if prev and now > prev_t:
                    d = stats[name] - prev[name]
                    if d:
                        rate = human(d / (now - prev_t))
                print(f"{name:<18}{stats[name]:>16,}{rate:>14}")
            prev, prev_t = stats, now
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_reset(fw, args):
    """Zero the counters and forget per-source state.

    Do this between benchmark runs so each measurement starts from a clean
    slate. It does NOT touch the allow or block lists.
    """
    fw.reset_stats()
    n = fw.clear_states()
    print(f"counters zeroed; forgot {n} tracked sources")
    if args.blocks:
        keys = list(fw.blocklist.keys())
        for k in keys:
            fw.blocklist.delete(k)
        print(f"removed {len(keys)} blocklist entries")
    return 0


def cmd_selftest(fw, args):
    """Prove the Python <-> kernel plumbing is correct, end to end.

    Worth running once after every build. It catches struct layout drift, byte
    order mistakes, and pin path problems immediately, instead of letting them
    show up later disguised as a model that behaves strangely.
    """
    ok = True
    test_ip = "203.0.113.42"   # TEST-NET-3, safe to use

    print("1. reading config map ...", end=" ")
    cfg = fw.read_config()
    print(f"OK (rate={cfg['rate_pps']})")

    print("2. round-tripping a blocklist entry ...", end=" ")
    fw.block(test_ip, duration_s=5, reason=schema.BLOCK_REASON_MANUAL)
    found = [e for e in fw.list_blocked() if e["cidr"] == f"{test_ip}/32"]
    if not found:
        print("FAIL: entry not found after insert")
        ok = False
    elif not (4.0 < (found[0]["remaining_s"] or 0) <= 5.0):
        # Catches the CLOCK_REALTIME vs CLOCK_MONOTONIC mistake: if the wrong
        # clock were used, remaining_s would be about 1.7 billion.
        print(f"FAIL: expiry is {found[0]['remaining_s']:.0f}s, expected ~5s "
              f"(clock source mismatch?)")
        ok = False
    else:
        print(f"OK (expires in {found[0]['remaining_s']:.1f}s)")

    print("3. checking address byte order ...", end=" ")
    if found and found[0]["cidr"] == f"{test_ip}/32":
        print(f"OK ({found[0]['cidr']})")
    else:
        got = found[0]["cidr"] if found else "nothing"
        print(f"FAIL: wrote {test_ip}/32, read back {got}")
        ok = False
    fw.unblock(test_ip)

    print("4. round-tripping an allowlist prefix ...", end=" ")
    fw.allow("198.51.100.0/24")
    if fw.is_allowed("198.51.100.7"):
        print("OK (LPM /24 matched a /32 lookup)")
    else:
        print("FAIL: LPM prefix match not working")
        ok = False
    fw.unallow("198.51.100.0/24")

    print("5. summing per-CPU stats ...", end=" ")
    stats = fw.read_stats()
    print(f"OK ({fw.stats.ncpu} CPUs, rx_packets={stats['rx_packets']:,})")

    print("6. reading srcstate with BPF_F_LOCK ...", end=" ")
    states = fw.read_states()
    print(f"OK ({len(states)} sources)")
    for ip, s in list(states.items())[:1]:
        if s["bytes"] and s["packets"]:
            avg = s["bytes"] / s["packets"]
            if not 20 <= avg <= 65536:
                print(f"   {YELLOW}warning: {ip} avg packet size {avg:.0f}B "
                      f"looks wrong -- possible struct layout drift{RESET}")
                ok = False

    print()
    print(f"{GREEN}self-test passed{RESET}" if ok
          else f"{RED}self-test FAILED{RESET}")
    return 0 if ok else 1


# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="fwctl",
                                description="Control the XDP/eBPF firewall.")
    p.add_argument("--pin-dir", default=schema.PIN_DIR)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="overall state and counters")

    a = sub.add_parser("allow", help="manage the allowlist")
    asub = a.add_subparsers(dest="allow_cmd")
    for name in ("add", "del"):
        s = asub.add_parser(name)
        s.add_argument("cidr", nargs="+", help="IP or CIDR")
    asub.add_parser("list")
    a.set_defaults(allow_cmd="list")

    b = sub.add_parser("block", help="manage the blocklist")
    bsub = b.add_subparsers(dest="block_cmd")
    sa = bsub.add_parser("add")
    sa.add_argument("cidr", nargs="+")
    sa.add_argument("--duration", type=float, default=60.0,
                    help="seconds; 0 or less means permanent (default 60)")
    sd = bsub.add_parser("del")
    sd.add_argument("cidr", nargs="+")
    sl = bsub.add_parser("list")
    sl.add_argument("--all", action="store_true", help="include expired")
    bsub.add_parser("flush", help="remove every entry")
    b.set_defaults(block_cmd="list", all=False)

    t = sub.add_parser("top", help="per-source state from the kernel map")
    t.add_argument("-n", "--count", type=int, default=20)
    t.add_argument("-w", "--watch", action="store_true")

    c = sub.add_parser("config", help="show or change runtime configuration")
    csub = c.add_subparsers(dest="config_cmd")
    csub.add_parser("show")
    cs = csub.add_parser("set")
    cs.add_argument("--rate", type=int, help="per-source pps")
    cs.add_argument("--burst", type=int, help="bucket capacity")
    cs.add_argument("--aggressiveness", type=int, choices=[0, 1, 2, 3])
    cs.add_argument("--enable", action="append",
                    choices=["allowlist", "blocklist", "proto", "ratelimit",
                             "state", "frags"])
    cs.add_argument("--disable", action="append",
                    choices=["allowlist", "blocklist", "proto", "ratelimit",
                             "state", "frags"])
    c.set_defaults(config_cmd="show")

    st = sub.add_parser("stats", help="raw counters")
    st.add_argument("-w", "--watch", action="store_true")

    r = sub.add_parser("reset", help="zero counters and per-source state")
    r.add_argument("--blocks", action="store_true", help="also clear blocklist")

    sub.add_parser("selftest", help="verify the kernel/Python plumbing")
    return p


HANDLERS = {
    "status": cmd_status, "allow": cmd_allow, "block": cmd_block,
    "top": cmd_top, "config": cmd_config, "stats": cmd_stats,
    "reset": cmd_reset, "selftest": cmd_selftest,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        print("error: BPF map access requires root. Re-run with sudo.",
              file=sys.stderr)
        return 1
    try:
        with Firewall(pin_dir=args.pin_dir) as fw:
            return HANDLERS[args.cmd](fw, args)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
