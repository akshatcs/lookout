"""Manual control of the running firewall.

    sudo python3 -m control.fwctl status
    sudo python3 -m control.fwctl allow add 10.10.1.2
    sudo python3 -m control.fwctl block add 10.10.1.3 --duration 60
    sudo python3 -m control.fwctl block list
    sudo python3 -m control.fwctl port deny tcp 23
    sudo python3 -m control.fwctl port allow tcp 22 80 443
    sudo python3 -m control.fwctl policy deny
    sudo python3 -m control.fwctl top [--watch]
    sudo python3 -m control.fwctl stats
    sudo python3 -m control.fwctl config set --rate 1000 --burst 2000
    sudo python3 -m control.fwctl reset [--blocks | --all]
    sudo python3 -m control.fwctl selftest

It works on the same pinned maps as the controller, so both can run at once.
"""

import argparse
import os
import sys
import time

from .firewall import (ACTIONS, ALLOW, DENY, FEATURES, MAX_TRACKED,
                       STAT_NAMES, Firewall, describe_features, parse_cidr)

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m")
CLEAR = "\033[H\033[2J"


def human(n):
    for unit, div in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.1f}{unit}"
    return f"{n:.0f}"


def watch(fn):
    """Redraw fn() every second until Ctrl-C."""
    try:
        while True:
            sys.stdout.write(CLEAR)
            fn()
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_status(fw, args):
    cfg = fw.read_config()
    s = fw.read_stats()
    prog = fw.prog_info()
    print(f"{BOLD}firewall status{RESET}")
    print(f"  program        {prog['name']} id {prog['id']}, tag {prog['tag']}, "
          f"{prog['xlated_bytes'] // 8} BPF instructions, "
          f"JIT-compiled to {prog['jited_bytes']:,} bytes")
    if prog["run_cnt"]:
        print(f"  time in XDP    {prog['run_time_ns'] / prog['run_cnt']:.0f} ns per packet "
              f"over {prog['run_cnt']:,} runs")
    print(f"  default policy {ACTIONS[cfg['default_policy']]}   "
          f"({len(fw.portrules.keys())} port rules)")
    print(f"  rate limit     {cfg['rate_pps']} pps/source, burst {cfg['burst_pkts']}")
    print(f"  aggressiveness L{cfg['aggressiveness']}")
    print(f"  features       {describe_features(cfg['features'])}")
    print(f"  allowlist      {len(fw.allowlist.keys())} entries")
    print(f"  blocklist      {len(list(fw.list_blocked()))} active")
    print(f"  tracked srcs   {len(fw.srcstate.keys())} / {MAX_TRACKED}")
    print(f"\n{BOLD}counters{RESET}")
    print(f"  received       {s['rx_packets']:>14,}  ({human(s['rx_bytes'])}B)")
    print(f"  {GREEN}passed{RESET}         {s['passes_total']:>14,}")
    for name in STAT_NAMES:
        if name.startswith("pass_") and s[name]:
            print(f"    {name:<18} {s[name]:>12,}")
    print(f"  {RED}dropped{RESET}        {s['drops_total']:>14,}")
    for name in STAT_NAMES:
        if name.startswith("drop_") and s[name]:
            print(f"    {name:<18} {s[name]:>12,}")
    if s["state_full"]:
        print(f"  {YELLOW}srcstate full {s['state_full']:,} times{RESET}")


def cmd_allow(fw, args):
    if args.action == "add":
        for cidr in args.cidr:
            fw.allow(cidr)
            print(f"{GREEN}allowed{RESET} {parse_cidr(cidr)}")
    elif args.action == "del":
        for cidr in args.cidr:
            print(f"{'removed' if fw.unallow(cidr) else 'not found:'} {cidr}")
    else:
        rows = sorted(fw.list_allowed(), key=lambda e: -e["hits"])
        if not rows:
            print("(allowlist is empty)")
        for e in rows:
            print(f"{e['cidr']:<22}{e['hits']:>14,}")


def cmd_block(fw, args):
    if args.action == "add":
        for cidr in args.cidr:
            # The kernel checks the allowlist first and would ignore this
            # entry, so refuse rather than pretend it worked.
            if fw.is_allowed(cidr.split("/")[0]):
                print(f"{YELLOW}refused{RESET} {cidr}: it is allowlisted. "
                      "Remove it from the allowlist first.")
                continue
            fw.block(cidr, args.duration)
            how = "permanently" if args.duration <= 0 else f"for {args.duration:g}s"
            print(f"{RED}blocked{RESET} {parse_cidr(cidr)} {how}")
    elif args.action == "del":
        for cidr in args.cidr:
            print(f"{'unblocked' if fw.unblock(cidr) else 'not found:'} {cidr}")
    elif args.action == "flush":
        print(f"removed {fw.clear_blocks()} blocklist entries")
    else:
        rows = sorted(fw.list_blocked(args.all), key=lambda e: -e["hits"])
        if not rows:
            print("(blocklist is empty)")
            return
        print(f"{BOLD}{'prefix':<20}{'remaining':>12}{'hits':>14}  reason{RESET}")
        for e in rows:
            if e["expired"]:
                left = "EXPIRED"
            elif e["remaining_s"] is None:
                left = "permanent"
            else:
                left = f"{e['remaining_s']:.0f}s"
            print(f"{e['cidr']:<20}{left:>12}{e['hits']:>14,}  {e['reason']}")


def cmd_port(fw, args):
    if args.action in ("allow", "deny"):
        action = ALLOW if args.action == "allow" else DENY
        for port in args.ports:
            fw.set_port_rule(args.proto, port, action)
            colour = GREEN if action == ALLOW else RED
            print(f"{colour}{args.action}{RESET} {args.proto}/{port}")
    elif args.action == "del":
        for port in args.ports:
            print(f"{'removed' if fw.del_port_rule(args.proto, port) else 'not found:'} "
                  f"{args.proto}/{port}")
    elif args.action == "flush":
        print(f"removed {fw.clear_port_rules()} port rules")
    else:
        policy = ACTIONS[fw.read_config()["default_policy"]]
        rows = sorted(fw.list_port_rules(), key=lambda r: (r["proto"], r["port"]))
        print(f"{BOLD}{'rule':<14}{'action':<8}{'hits':>14}{RESET}")
        for r in rows:
            colour = GREEN if r["action"] == "allow" else RED
            print(f"{r['proto'] + '/' + str(r['port']):<14}"
                  f"{colour}{r['action']:<8}{RESET}{r['hits']:>14,}")
        print(f"{'anything else':<14}{policy:<8}  (default policy)")


def cmd_policy(fw, args):
    if args.policy is None:
        print(f"default policy: {ACTIONS[fw.read_config()['default_policy']]}")
        return
    fw.update_config(default_policy=ALLOW if args.policy == "allow" else DENY)
    print(f"default policy: {args.policy}")
    if args.policy == "deny":
        allows = [r for r in fw.list_port_rules() if r["action"] == "allow"]
        if not allows:
            print(f"{YELLOW}note: there are no allow rules, so every IPv4 packet "
                  f"from a source that isn't allowlisted is dropped{RESET}")
        elif not any(r["proto"] == "icmp" for r in allows):
            print(f"{DIM}ping is now dropped too; `port allow icmp 8` lets it "
                  f"through{RESET}")


def cmd_top(fw, args):
    """Cumulative per-source counters, straight from the kernel map."""
    def show():
        states = sorted(fw.read_states().items(),
                        key=lambda kv: -kv[1]["packets"])[:args.count]
        print(f"{BOLD}{'source':<16} {'packets':>12} {'bytes':>8} {'dropped':>12} "
              f"{'syn':>12} {'udp':>10} {'icmp':>8} {'tokens':>8} {'ports':>5}{RESET}")
        for ip, s in states:
            print(f"{ip:<16} {s['packets']:>12,} {human(s['bytes']):>8} "
                  f"{s['dropped']:>12,} {s['syn']:>12,} {s['udp']:>10,} "
                  f"{s['icmp']:>8,} {s['tokens']:>8,} "
                  f"{bin(s['port_bitmap']).count('1'):>5}")
        if not states:
            print(f"{DIM}(no tracked sources){RESET}")
    if args.watch:
        watch(show)
    else:
        show()


def cmd_stats(fw, args):
    s = fw.read_stats()
    for name in STAT_NAMES:
        print(f"{name:<15}  {s[name]:>16,}")


def cmd_config(fw, args):
    if args.action != "set":
        cfg = fw.read_config()
        print(f"rate_pps        {cfg['rate_pps']}")
        print(f"burst_pkts      {cfg['burst_pkts']}")
        print(f"aggressiveness  L{cfg['aggressiveness']}")
        print(f"default_policy  {ACTIONS[cfg['default_policy']]}")
        print(f"features        {describe_features(cfg['features'])}")
        return

    cfg = fw.read_config()
    feats = cfg["features"]
    for name in args.enable or []:
        feats |= FEATURES[name]
    for name in args.disable or []:
        feats &= ~FEATURES[name]
    changes = {"features": feats}
    if args.rate is not None:
        changes["rate_pps"] = args.rate
    if args.burst is not None:
        changes["burst_pkts"] = args.burst
    # The kernel multiplies elapsed nanoseconds by the rate, so keep it far
    # from overflow; a burst of 0 would drop every packet.
    if not 0 <= changes.get("rate_pps", 0) <= 100_000_000:
        raise ValueError("--rate must be between 0 (no limit) and 100000000")
    if changes.get("burst_pkts", 1) < 1:
        raise ValueError("--burst must be at least 1")
    if args.aggressiveness is not None:
        changes["aggressiveness"] = args.aggressiveness
    cfg = fw.update_config(**changes)
    print(f"rate {cfg['rate_pps']} pps/src, burst {cfg['burst_pkts']}, "
          f"L{cfg['aggressiveness']}")
    print(f"features: {describe_features(cfg['features'])}")


def cmd_reset(fw, args):
    """Zero counters and forget per-source state. Rules are kept unless
    --blocks (blocklist) or --all (every list, rule and setting) is given."""
    fw.reset_stats()
    print(f"counters zeroed; forgot {fw.clear_states()} tracked sources")
    if args.blocks or args.all:
        print(f"removed {fw.clear_blocks()} blocklist entries")
    if args.all:
        n = 0
        for e in list(fw.list_allowed()):
            n += fw.unallow(e["cidr"])
        print(f"removed {n} allowlist entries and {fw.clear_port_rules()} port rules")
        fw.update_config(rate_pps=20000, burst_pkts=40000, aggressiveness=0,
                         default_policy=ALLOW,
                         features=sum(FEATURES.values()) & ~FEATURES["frags"])
        print("settings back to the defaults: policy allow, 20000 pps/source, "
              "burst 40000, all stages on except frags")


def cmd_selftest(fw, args):
    """Checks the Python side agrees with the kernel on layout, byte order,
    clock and per-CPU sizing. Run it after every build."""
    ok = True
    ip = "203.0.113.42"     # TEST-NET-3

    def check(label, passed, detail):
        nonlocal ok
        ok &= passed
        print(f"{label} ... {'OK' if passed else 'FAIL'} ({detail})")

    cfg = fw.read_config()
    check("1. reading config map", cfg["burst_pkts"] > 0, f"rate={cfg['rate_pps']}")

    fw.block(ip, 5)
    entry = next((e for e in fw.list_blocked() if e["cidr"].startswith(ip)), None)
    left = entry["remaining_s"] if entry else None
    # With the wrong clock this would be ~1.7 billion seconds.
    check("2. round-tripping a blocklist entry",
          left is not None and 4.0 < left <= 5.0,
          f"expires in {left:.1f}s" if left is not None else "not found")
    check("3. checking address byte order",
          entry is not None and entry["cidr"] == f"{ip}/32",
          entry["cidr"] if entry else "nothing read back")
    fw.unblock(ip)

    fw.allow("198.51.100.0/24")
    check("4. round-tripping an allowlist prefix",
          fw.is_allowed("198.51.100.7"), "LPM /24 matched a /32 lookup")
    fw.unallow("198.51.100.0/24")

    had = {(r["proto"], r["port"]) for r in fw.list_port_rules()}
    fw.set_port_rule("udp", 65001, DENY)
    rule = next((r for r in fw.list_port_rules()
                 if r["proto"] == "udp" and r["port"] == 65001), None)
    check("5. round-tripping a port rule", rule is not None and rule["action"] == "deny",
          "udp/65001 deny" if rule else "not found")
    if ("udp", 65001) not in had:
        fw.del_port_rule("udp", 65001)

    s = fw.read_stats()
    identity = s["passes_total"] + s["drops_total"]
    check("6. summing per-CPU stats", identity <= s["rx_packets"],
          f"{fw.stats.ncpu} CPUs, rx_packets={s['rx_packets']:,}")

    states = fw.read_states()
    sane = all(20 <= st["bytes"] / st["packets"] <= 65536
               for st in states.values() if st["packets"])
    check("7. reading srcstate with BPF_F_LOCK", sane, f"{len(states)} sources")

    prog = fw.prog_info()
    check("8. reading the program's info", prog["name"] == "xdp_firewall",
          f"id {prog['id']}, {prog['jited_bytes']} bytes of JIT code")

    print()
    print(f"{GREEN}self-test passed{RESET}" if ok else f"{RED}self-test FAILED{RESET}")
    return 0 if ok else 1


def parser():
    p = argparse.ArgumentParser(prog="fwctl", description="Control the XDP firewall.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="settings and counters")

    a = sub.add_parser("allow", help="manage the allowlist")
    asub = a.add_subparsers(dest="action")
    a.set_defaults(action="list")
    for name in ("add", "del"):
        asub.add_parser(name).add_argument("cidr", nargs="+")
    asub.add_parser("list")

    b = sub.add_parser("block", help="manage the blocklist")
    bsub = b.add_subparsers(dest="action")
    b.set_defaults(action="list", all=False)
    add = bsub.add_parser("add")
    add.add_argument("cidr", nargs="+")
    add.add_argument("--duration", type=float, default=60,
                     help="seconds, 0 for permanent (default 60)")
    bsub.add_parser("del").add_argument("cidr", nargs="+")
    bsub.add_parser("list").add_argument("--all", action="store_true",
                                         help="include expired entries")
    bsub.add_parser("flush")

    pr = sub.add_parser("port", help="manage port rules")
    prsub = pr.add_subparsers(dest="action")
    pr.set_defaults(action="list")
    for name in ("allow", "deny", "del"):
        x = prsub.add_parser(name)
        x.add_argument("proto", help="tcp, udp, icmp or a protocol number")
        x.add_argument("ports", nargs="+", type=int,
                       help="destination ports (the ICMP type for icmp)")
    prsub.add_parser("list")
    prsub.add_parser("flush")

    po = sub.add_parser("policy", help="show or set the default policy")
    po.add_argument("policy", nargs="?", choices=("allow", "deny"))

    t = sub.add_parser("top", help="per-source counters from the kernel")
    t.add_argument("-n", "--count", type=int, default=20)
    t.add_argument("-w", "--watch", action="store_true")

    sub.add_parser("stats", help="raw counters")

    c = sub.add_parser("config", help="show or change runtime settings")
    csub = c.add_subparsers(dest="action")
    c.set_defaults(action="show")
    csub.add_parser("show")
    cs = csub.add_parser("set")
    cs.add_argument("--rate", type=int)
    cs.add_argument("--burst", type=int)
    cs.add_argument("--aggressiveness", type=int, choices=range(4))
    cs.add_argument("--enable", action="append", choices=FEATURES)
    cs.add_argument("--disable", action="append", choices=FEATURES)

    r = sub.add_parser("reset", help="zero counters and per-source state")
    r.add_argument("--blocks", action="store_true", help="also clear the blocklist")
    r.add_argument("--all", action="store_true",
                   help="also clear every list and rule and restore default settings")
    sub.add_parser("selftest", help="check the Python/kernel plumbing")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if os.geteuid() != 0:
        sys.exit("error: needs root, re-run with sudo")
    handler = globals()[f"cmd_{args.cmd}"]
    try:
        with Firewall() as fw:
            return handler(fw, args) or 0
    except (OSError, ValueError) as e:
        sys.exit(f"error: {getattr(e, 'strerror', None) or e}")


if __name__ == "__main__":
    sys.exit(main())
