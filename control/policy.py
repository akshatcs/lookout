"""
policy.py -- turns detector verdicts into map writes, safely.

============================================================================
THIS FILE IS MORE IMPORTANT THAN model.py
============================================================================
A classifier that is 99% accurate on a per-second basis will, on a box seeing
a hundred sources, produce roughly one wrong verdict per second. Wired
directly to the blocklist, that is a hundred wrongly-blocked hosts per hour --
a firewall that attacks its own users.

Everything below exists to make a wrong verdict survivable. When we present
this project, the safety rails are the part worth talking about: anyone can
call predict(), the logic is in deciding what to do with the answer.

THE RAILS, in the order they apply:

  1. ALLOWLIST IMMUNITY. An allowlisted source is never blocked, whatever the
     model says. Enforced here AND independently in the kernel (the XDP
     program checks the allowlist before the blocklist), so a bug in this file
     still cannot black-hole the SSH session.

  2. HYSTERESIS. A source must look malicious in N consecutive windows before
     anything happens. One bad second is noise -- a burst of retransmits, a
     backup kicking off. Sustained badness is a signal. This single rule
     removes the overwhelming majority of false positives, at the cost of
     N seconds of reaction latency.

  3. ESCALATING DURATIONS. First offence 60s, then 300s, then 900s. A
     mistakenly blocked host recovers quickly; a genuine attacker that comes
     straight back gets progressively less of the attention.

  4. INSERTION RATE CAP. At most MAX_BLOCKS_PER_WINDOW new blocks per cycle.
     If the model melts down and declares everything malicious, it can take
     out a handful of hosts per second, not the entire network at once. This
     is a circuit breaker, and the fact that it is almost never hit in normal
     operation is the point.

  5. DRY RUN. --dry-run computes everything and writes nothing. Use it while
     developing.

============================================================================
THE SECOND, NON-ML ADAPTIVE LOOP
============================================================================
AggressivenessController below has nothing to do with the model. It watches
GLOBAL load -- total pps and drop ratio -- and scales the per-source rate
limit up or down in tiers.

It is deliberately independent, for two reasons. It responds in one second
where the model needs N windows of evidence, so it is the first line of
defence under a sudden flood. And it means the project's "adaptive" claim
still holds with the model entirely disabled, which keeps the ML component a
genuine stretch goal rather than a load-bearing dependency.
"""

import time
from collections import defaultdict

from . import schema
from .model import LABEL_MALICIOUS


# ===========================================================================
# Load-driven aggressiveness (works with no model at all)
# ===========================================================================

class AggressivenessController:
    """Scales the per-source rate limit according to observed global load.

    Tiers, from calm to under-attack. Each is (rate_pps, burst_pkts):
      0  20000 / 40000  -- effectively off; normal service
      1   5000 / 10000  -- elevated load
      2   1000 /  2000  -- heavy load
      3    200 /   400  -- under attack; only modest per-source rates survive

    ASYMMETRIC RESPONSE: escalation is immediate, de-escalation requires
    several consecutive calm windows. Under attack we want to clamp down at
    once; relaxing the moment traffic dips lets an attacker oscillate us and
    is worse than staying clamped a few seconds too long.
    """

    TIERS = [
        (20000, 40000),
        (5000, 10000),
        (1000, 2000),
        (200, 400),
    ]

    # Global received packets-per-second at which each tier engages.
    # Tuned for a veth/VM testbed. On real hardware these want to be
    # substantially higher -- see docs/EVALUATION.md.
    ESCALATE_PPS = [0, 20000, 80000, 200000]

    # Independent trigger: if we are already dropping most of what arrives,
    # we are under attack regardless of the absolute rate.
    ESCALATE_DROP_RATIO = 0.5

    CALM_WINDOWS_TO_RELAX = 5

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.level = 0
        self._calm_windows = 0
        self.last_change = None

    def evaluate(self, global_pps: float, drop_ratio: float):
        """Return (level, rate_pps, burst_pkts, changed)."""
        if not self.enabled:
            rate, burst = self.TIERS[self.level]
            return self.level, rate, burst, False

        target = 0
        for lvl in range(len(self.TIERS) - 1, 0, -1):
            if global_pps >= self.ESCALATE_PPS[lvl]:
                target = lvl
                break

        if drop_ratio >= self.ESCALATE_DROP_RATIO:
            target = max(target, 2)

        changed = False
        if target > self.level:
            self.level = target          # escalate immediately
            self._calm_windows = 0
            changed = True
        elif target < self.level:
            self._calm_windows += 1      # de-escalate slowly
            if self._calm_windows >= self.CALM_WINDOWS_TO_RELAX:
                self.level -= 1          # one tier at a time
                self._calm_windows = 0
                changed = True
        else:
            self._calm_windows = 0

        if changed:
            self.last_change = time.time()

        rate, burst = self.TIERS[self.level]
        return self.level, rate, burst, changed


# ===========================================================================
# Model-driven blocking, with rails
# ===========================================================================

class PolicyEngine:
    """Applies detector verdicts to the blocklist under the safety rails."""

    CONSECUTIVE_WINDOWS_TO_BLOCK = 2
    BLOCK_DURATIONS_S = [60, 300, 900]
    MAX_BLOCKS_PER_WINDOW = 32
    SUSPICION_DECAY_WINDOWS = 5  # forget a source that goes quiet

    def __init__(self, firewall, dry_run=False):
        self.fw = firewall
        self.dry_run = dry_run

        self._strikes = defaultdict(int)    # ip -> consecutive bad windows
        self._misses = defaultdict(int)     # ip -> consecutive clean windows
        self._offences = defaultdict(int)   # ip -> lifetime block count
        self._blocked_until = {}            # ip -> wall-clock expiry estimate

        self.stats = {
            "blocks_issued": 0,
            "blocks_suppressed_allowlist": 0,
            "blocks_suppressed_cap": 0,
            "verdicts_malicious": 0,
            "verdicts_benign": 0,
        }
        self.recent_actions = []  # rolling log for the live display

    def _log(self, msg):
        self.recent_actions.append((time.strftime("%H:%M:%S"), msg))
        del self.recent_actions[:-12]

    def apply(self, verdicts: dict, rows: dict):
        """Act on one window of verdicts.

        Args:
            verdicts: {ip: (label, confidence, reason)} from a detector
            rows:     {ip: feature_dict} for the same window

        Returns a list of action dicts describing what was done.
        """
        actions = []
        issued = 0
        now = time.time()

        for ip, (label, confidence, reason) in verdicts.items():
            if label == LABEL_MALICIOUS:
                self.stats["verdicts_malicious"] += 1
                self._misses[ip] = 0
                self._strikes[ip] += 1
            else:
                self.stats["verdicts_benign"] += 1
                self._misses[ip] += 1
                # Decay suspicion so a source that misbehaved once, went
                # quiet, and misbehaved again days later is not treated as
                # having two consecutive strikes.
                if self._misses[ip] >= self.SUSPICION_DECAY_WINDOWS:
                    self._strikes.pop(ip, None)
                continue

            # -- RAIL 2: hysteresis ---------------------------------------
            if self._strikes[ip] < self.CONSECUTIVE_WINDOWS_TO_BLOCK:
                actions.append({
                    "ip": ip, "action": "watch", "reason": reason,
                    "confidence": confidence,
                    "strikes": self._strikes[ip],
                    "needed": self.CONSECUTIVE_WINDOWS_TO_BLOCK,
                })
                continue

            # -- RAIL 1: allowlist immunity -------------------------------
            if self.fw.is_allowed(ip):
                self.stats["blocks_suppressed_allowlist"] += 1
                actions.append({
                    "ip": ip, "action": "exempt", "reason": "allowlisted",
                    "confidence": confidence,
                })
                self._log(f"{ip} flagged but allowlisted -- not blocked")
                continue

            # Already blocked and the block has not lapsed: nothing to do.
            if self._blocked_until.get(ip, 0) > now:
                continue

            # -- RAIL 4: insertion rate cap -------------------------------
            if issued >= self.MAX_BLOCKS_PER_WINDOW:
                self.stats["blocks_suppressed_cap"] += 1
                actions.append({
                    "ip": ip, "action": "deferred",
                    "reason": "per-window block cap reached",
                    "confidence": confidence,
                })
                continue

            # -- RAIL 3: escalating duration ------------------------------
            offence = self._offences[ip]
            idx = min(offence, len(self.BLOCK_DURATIONS_S) - 1)
            duration = self.BLOCK_DURATIONS_S[idx]

            block_reason = (schema.BLOCK_REASON_REPEAT if offence > 0
                            else schema.BLOCK_REASON_MODEL)

            if not self.dry_run:
                try:
                    self.fw.block(ip, duration_s=duration, reason=block_reason)
                except OSError as e:
                    actions.append({
                        "ip": ip, "action": "error", "reason": str(e),
                        "confidence": confidence,
                    })
                    continue

            self._offences[ip] = offence + 1
            self._blocked_until[ip] = now + duration
            self._strikes[ip] = 0
            self.stats["blocks_issued"] += 1
            issued += 1

            verb = "WOULD BLOCK" if self.dry_run else "BLOCKED"
            self._log(f"{verb} {ip} for {duration}s ({reason}, "
                      f"p={confidence:.2f})")
            actions.append({
                "ip": ip, "action": "block", "reason": reason,
                "confidence": confidence, "duration_s": duration,
                "offence": offence + 1, "dry_run": self.dry_run,
            })

        return actions

    def watching(self):
        """Sources with at least one strike but not yet blocked."""
        return {ip: n for ip, n in self._strikes.items() if n > 0}
