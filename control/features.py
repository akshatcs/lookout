"""
features.py -- turn raw kernel counters into per-window behavioural features.

============================================================================
THE CORE IDEA
============================================================================
The eBPF program keeps CUMULATIVE counters per source IP: total packets, total
SYNs, total bytes, and so on, counting up forever. Cumulative counters are the
only sane thing to keep in the kernel, because they need no coordination --
every CPU just adds to them.

But "this source has sent 4,000,000 packets" tells us nothing on its own. A
busy web server says that too. What matters is the RATE and the SHAPE:
4,000,000 packets in four seconds, all 54 bytes, all SYN, to one port.

So the control plane samples the map once per second and differences
successive snapshots. That difference -- what happened during the last second
-- is what the model sees.

============================================================================
WHY DELTAS AND NOT ABSOLUTE VALUES, SPECIFICALLY
============================================================================
Feeding cumulative counters to the model would make it learn "big number =
bad", which is really "old = bad". A legitimate connection that has been up
for an hour would eventually cross whatever threshold an attacker crosses in
five seconds. Differencing removes the age dependence entirely: every source
is judged on the last second of its behaviour regardless of how long it has
been around.

The one feature that is intentionally NOT a delta is `age_s`, which is there
precisely so the model can learn that brand-new sources deserve more
suspicion than long-lived ones.

============================================================================
EDGE CASES THIS MODULE HANDLES
============================================================================
  * counter went backwards -- the source's state was garbage-collected and
    recreated, so the old snapshot is meaningless. Treat it as new.
  * zero packets this window -- source is idle; every ratio would be 0/0.
  * first ever sighting -- no previous snapshot to difference against.
"""

from . import schema


def popcount(x: int) -> int:
    """Number of set bits. int.bit_count() is Python 3.10+, so fall back."""
    try:
        return x.bit_count()
    except AttributeError:
        return bin(x).count("1")


class FeatureExtractor:
    """Holds the previous snapshot and differences it against the next one.

    Usage:
        fx = FeatureExtractor()
        while True:
            states = fw.read_states()
            rows = fx.update(states, now_ns=fw.ktime_ns())
            ...
            time.sleep(1)
    """

    def __init__(self):
        self._prev = {}       # ip -> raw state dict from the last poll
        self._prev_ns = None  # kernel timestamp of the last poll

    def reset(self):
        self._prev = {}
        self._prev_ns = None

    def update(self, states: dict, now_ns: int):
        """Difference `states` against the previous snapshot.

        Args:
            states:  {ip: state_dict} straight from Firewall.read_states()
            now_ns:  CLOCK_MONOTONIC nanoseconds, from Firewall.ktime_ns()

        Returns:
            {ip: feature_dict}, one entry per source that sent at least one
            packet during the window. Sources that were idle are omitted --
            there is nothing to classify and including them would flood the
            model with all-zero rows.
        """
        rows = {}

        # First call: nothing to difference against. Record and return empty.
        if self._prev_ns is None:
            self._prev = states
            self._prev_ns = now_ns
            return rows

        window_s = (now_ns - self._prev_ns) / 1e9
        # Guard against a zero or absurd window. Sleep jitter and a suspended
        # VM can both produce one, and dividing by it yields infinities that
        # poison the model input.
        if window_s <= 0.001:
            return rows
        window_s = min(window_s, 60.0)

        for ip, cur in states.items():
            prev = self._prev.get(ip)

            # Counters only ever increase. If this one decreased, the entry
            # was GC'd and recreated between polls, so the previous snapshot
            # describes a different lifetime. Difference against zero instead.
            if prev is None or cur["packets"] < prev["packets"]:
                prev = _ZERO_STATE

            d_packets = cur["packets"] - prev["packets"]
            if d_packets <= 0:
                continue  # idle this window

            d_bytes = cur["bytes"] - prev["bytes"]
            d_syn = cur["syn"] - prev["syn"]
            d_fin = cur["fin"] - prev["fin"]
            d_rst = cur["rst"] - prev["rst"]
            d_udp = cur["udp"] - prev["udp"]
            d_icmp = cur["icmp"] - prev["icmp"]
            d_dropped = cur["dropped"] - prev["dropped"]

            cur_ports = cur["port_bitmap"]
            prev_ports = prev["port_bitmap"]

            rows[ip] = {
                # --- rate ---
                "pps": d_packets / window_s,
                "bps": d_bytes / window_s,

                # --- packet size shape ---
                # Floods are overwhelmingly minimum-size packets, because the
                # attacker is buying packets-per-second, not bandwidth. Real
                # traffic has a mix.
                "mean_len": d_bytes / d_packets,
                "len_range": max(0, cur["max_len"] - cur["min_len"]),

                # --- protocol mix ---
                # A SYN flood is ~100% SYN. A real TCP conversation is one SYN
                # followed by many non-SYN segments, so its ratio is tiny.
                "syn_ratio": d_syn / d_packets,

                # Handshake completion proxy. Real clients that open
                # connections also close them, so SYNs are roughly balanced by
                # FINs and RSTs over time. A SYN flood never closes anything,
                # so this ratio runs away.
                #
                # The +1 in the denominator is a smoothing term, not a fudge:
                # without it a single SYN with no FIN gives a ratio of
                # infinity, and one legitimate connection opening looks
                # identical to a flood.
                "syn_fin_ratio": d_syn / (d_fin + d_rst + 1),

                "udp_ratio": d_udp / d_packets,
                "icmp_ratio": d_icmp / d_packets,

                # --- destination spread ---
                # See the port_bitmap comment in common.h: this is popcount of
                # a 64-bit hashed bitmap, so it approximates "how many
                # different services is this source touching".
                "port_spread": popcount(cur_ports),

                # Bits that appeared during THIS window. A steady client keeps
                # hitting the same ports so this is 0; a scanner lights up new
                # bits continuously.
                "new_ports": popcount(cur_ports & ~prev_ports),

                # --- lifetime ---
                "age_s": max(0.0,
                             (cur["last_seen_ns"] - cur["first_seen_ns"]) / 1e9),

                # --- not model inputs; carried for display and bookkeeping ---
                "_packets": d_packets,
                "_bytes": d_bytes,
                "_dropped": d_dropped,
                "_drop_ratio": d_dropped / d_packets,
                "_total_packets": cur["packets"],
                "_tokens": cur["tokens"],
            }

        self._prev = states
        self._prev_ns = now_ns
        return rows


# A synthetic all-zero state, used when a source has no usable previous
# snapshot. Keys must cover everything update() reads.
_ZERO_STATE = {
    "packets": 0, "bytes": 0, "syn": 0, "fin": 0, "rst": 0,
    "udp": 0, "icmp": 0, "tcp": 0, "dropped": 0, "port_bitmap": 0,
    "min_len": 0, "max_len": 0, "first_seen_ns": 0, "last_seen_ns": 0,
    "tokens": 0, "last_refill_ns": 0, "lock": 0,
}


def to_vector(row: dict):
    """Flatten a feature dict into the fixed column order the model expects.

    Column order is defined once, in schema.FEATURE_NAMES, and the trained
    model stores a copy of that list. model.py compares the two on load and
    refuses to predict if they differ -- silently reordering features is an
    excellent way to build a classifier that is confidently wrong.
    """
    return [float(row[name]) for name in schema.FEATURE_NAMES]


def to_matrix(rows: dict):
    """Turn {ip: features} into (ip_list, list_of_vectors) for batch predict."""
    ips = list(rows.keys())
    return ips, [to_vector(rows[ip]) for ip in ips]
