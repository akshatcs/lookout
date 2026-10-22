"""Per-source behaviour over the last second, and the rules that flag it.

The kernel keeps cumulative counters per source because that needs no
coordination between CPUs. Totals on their own say little (a busy server
and a flood both reach millions of packets), so every second we take the
difference from the previous snapshot and judge each source on what it did
in that second only.
"""


class Window:
    """Turns successive srcstate snapshots into per-second measurements."""

    def __init__(self):
        self.prev = None        # states from the last call
        self.prev_ns = None

    def update(self, states, now_ns):
        """Return {ip: measurements} for every source that sent packets
        since the previous call. The first call only records a baseline."""
        prev, prev_ns = self.prev, self.prev_ns
        self.prev, self.prev_ns = states, now_ns
        if prev is None:
            return {}

        secs = (now_ns - prev_ns) / 1e9
        if secs < 0.001:
            return {}

        rows = {}
        for ip, cur in states.items():
            old = prev.get(ip)
            # A smaller count means the entry was deleted and recreated
            # between polls, so the old snapshot belongs to someone else.
            if old is None or cur["packets"] < old["packets"]:
                old = dict.fromkeys(cur, 0)

            d = {k: cur[k] - old[k] for k in
                 ("packets", "bytes", "dropped", "syn", "fin", "rst", "icmp")}
            if d["packets"] <= 0:
                continue
            n = d["packets"]
            rows[ip] = {
                "pps": n / secs,
                "mean_len": d["bytes"] / n,
                "syn_ratio": d["syn"] / n,
                # A real client closes what it opens, so SYNs are matched by
                # FINs/RSTs; a SYN flood never closes anything. The +1 keeps a
                # single new connection from looking infinite.
                "syn_fin_ratio": d["syn"] / (d["fin"] + d["rst"] + 1),
                "icmp_ratio": d["icmp"] / n,
                "port_spread": bin(cur["port_bitmap"]).count("1"),
                "drop_ratio": d["dropped"] / n,
            }
        return rows


# Thresholds. They are judgement calls tuned on the veth testbed, not derived.
FLOOD_PPS = 8000        # above this, small packets count as a flood
SMALL_PKT = 600         # bytes; bulk transfers use full-size packets
SYN_RATIO = 0.85        # share of packets that are SYNs
SYN_FIN_RATIO = 40      # SYNs per closing FIN/RST
SCAN_PORTS = 24         # distinct port bits for a scan
SCAN_PKT = 100


def classify(row):
    """Reason string if the source misbehaves, else None. The first rule
    that matches names the reason; the order puts the most specific
    description first (a SYN scan is also all unanswered SYNs)."""
    if row["pps"] > FLOOD_PPS and row["mean_len"] < SMALL_PKT:
        return "volumetric flood"
    if row["port_spread"] > SCAN_PORTS and row["mean_len"] < SCAN_PKT:
        return "port scan"
    if row["syn_ratio"] > SYN_RATIO and row["syn_fin_ratio"] > SYN_FIN_RATIO:
        return "syn flood"
    if row["icmp_ratio"] > 0.9 and row["pps"] > FLOOD_PPS / 4:
        return "icmp flood"
    return None
