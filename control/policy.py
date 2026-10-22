"""The two adaptive mechanisms.

Aggressiveness reacts to the load and tightens the per-source rate limit
for everyone, within a second. Blocker reacts to individual sources that the
rules in detect.py flag, more slowly but more precisely.
"""

import time
from collections import deque

from .firewall import BLOCK_AUTO


class Aggressiveness:
    """Picks a rate-limit tier from the load and the share of it that is
    already being rate limited. Load means packets that reached the rate
    limiter, so traffic that the allowlist, blocklist or port rules have
    already decided doesn't count.

    Escalation is immediate and can skip tiers. Relaxing needs CALM_WINDOWS
    quiet seconds in a row and goes down one tier at a time; relaxing as
    soon as traffic dips would let an attacker pulse the flood and spend
    half its time at the loose limit.
    """

    TIERS = [(20000, 40000), (5000, 10000), (1000, 2000), (200, 400)]
    ESCALATE_PPS = [0, 20000, 80000, 200000]   # tuned for the veth testbed
    ESCALATE_DROP_RATIO = 0.5                  # limiter already drops most of it
    CALM_WINDOWS = 5

    def __init__(self):
        self.level = 0
        self.calm = 0

    def update(self, pps, drop_ratio):
        """Feed one second of load. Returns True if the tier changed."""
        target = max(lvl for lvl, limit in enumerate(self.ESCALATE_PPS)
                     if pps >= limit)
        if drop_ratio >= self.ESCALATE_DROP_RATIO:
            target = max(target, 2)

        if target > self.level:
            self.level, self.calm = target, 0
            return True
        if target == self.level:
            self.calm = 0
            return False
        self.calm += 1
        if self.calm >= self.CALM_WINDOWS:
            self.level, self.calm = self.level - 1, 0
            return True
        return False

    @property
    def limits(self):
        return self.TIERS[self.level]


class Blocker:
    """Turns per-second verdicts into blocklist entries, with guard rails:

    - a source must be flagged in STRIKES consecutive windows (one bad
      second is often just a burst);
    - allowlisted sources are never blocked (the kernel enforces this too);
    - repeat offenders get longer blocks: 60 s, then 300 s, then 900 s;
    - at most MAX_PER_WINDOW new blocks per second, so a bad rule can't
      block the whole network at once;
    - dry_run decides everything but writes nothing.
    """

    STRIKES = 2
    DURATIONS = [60, 300, 900]
    MAX_PER_WINDOW = 32

    def __init__(self, fw, dry_run=False):
        self.fw = fw
        self.dry_run = dry_run
        self.strikes = {}       # ip -> consecutive flagged windows
        self.offences = {}      # ip -> times blocked so far
        self.until = {}         # ip -> time.time() when our block ends
        self.blocks_issued = 0
        self.log = deque(maxlen=12)

    def is_blocked(self, ip):
        """True while a block we issued (or would have, in a dry run) lasts."""
        return self.until.get(ip, 0) > time.time()

    def note(self, msg):
        self.log.append((time.strftime("%H:%M:%S"), msg))

    def update(self, verdicts):
        """verdicts: {ip: reason or None} for one window."""
        now = time.time()
        issued = 0
        for ip, reason in verdicts.items():
            if reason is None:
                self.strikes.pop(ip, None)
                continue
            self.strikes[ip] = self.strikes.get(ip, 0) + 1
            if self.strikes[ip] < self.STRIKES:
                continue
            if self.is_blocked(ip):
                self.strikes.pop(ip)
                continue
            if self.fw.is_allowed(ip):
                self.note(f"{ip} flagged ({reason}) but allowlisted")
                self.strikes.pop(ip)
                continue
            if issued >= self.MAX_PER_WINDOW:
                continue                        # try again next window

            n = self.offences.get(ip, 0)
            duration = self.DURATIONS[min(n, len(self.DURATIONS) - 1)]
            if not self.dry_run:
                self.fw.block(ip, duration, reason=BLOCK_AUTO)
            self.offences[ip] = n + 1
            self.until[ip] = now + duration
            self.strikes.pop(ip)
            self.blocks_issued += 1
            issued += 1
            verb = "WOULD BLOCK" if self.dry_run else "BLOCKED"
            self.note(f"{verb} {ip} for {duration}s ({reason})")
