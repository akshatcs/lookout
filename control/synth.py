"""
synth.py -- generate a labelled training set without needing a testbed.

============================================================================
WHY THIS EXISTS
============================================================================
Training on real captured traffic is better and we should do it -- that is
what control/collect.py and bench/gen_traffic.sh are for. But we need a
working model on day one, before the testbed exists, or the whole ML branch of
the project blocks on network plumbing.

So this module samples feature vectors from hand-specified distributions, one
per traffic class. It is NOT captured traffic. The correct framing is:

    "The classifier was initially trained on synthetic feature vectors drawn
     from distributions chosen to mirror the traffic classes in the testbed,
     which allowed the control-plane logic to be developed independently of
     the measurement setup. It was then retrained on N minutes of real
     captured traffic."

The distributions below encode real domain knowledge -- flood packets really
are minimum-size, real TCP conversations really do balance SYNs with FINs --
so a model trained here transfers to real traffic reasonably well. But
"reasonably well" is a claim we should verify with collect.py rather than
assert.

============================================================================
THE CLASSES
============================================================================
Benign:
    web        bursty TCP, large packets, few ports, long-lived
    bulk       high pps BUT full-size packets -- the important hard negative,
               since naive "pps > N" flags this and the model must not
    dns        small UDP, low rate, one or two ports
    game       steady small UDP at a fixed rate to one port; the latency-
               sensitive workload the project is motivated by, and the other
               hard negative because it looks superficially like a UDP flood
    ping       trickle of ICMP
    idle       almost nothing

Malicious:
    syn_flood     huge pps, all SYN, nothing closes
    udp_flood     huge pps, small UDP
    icmp_flood    huge pps ICMP
    port_scan     modest pps, tiny packets, many ports
    low_slow_syn  THE INTERESTING ONE. Packet rate overlaps ordinary web
                  traffic, so no pps threshold can separate it. Only the
                  handshake-imbalance feature can. This class is where the
                  forest earns its place, and it is what you point at when
                  someone asks what the ML bought you.
"""

import random

from . import schema
from .model import LABEL_BENIGN, LABEL_MALICIOUS


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


def _row(pps, mean_len, len_range, syn_ratio, syn_fin_ratio, udp_ratio,
         icmp_ratio, port_spread, new_ports, age_s):
    """Assemble a feature dict in the canonical column order.

    bps is derived rather than sampled independently, because bytes per second
    is by definition pps * mean packet size. Sampling it separately would let
    the model discover an impossible combination and learn from it.
    """
    return {
        "pps": pps,
        "bps": pps * mean_len,
        "mean_len": mean_len,
        "len_range": len_range,
        "syn_ratio": _clamp(syn_ratio, 0.0, 1.0),
        "syn_fin_ratio": max(0.0, syn_fin_ratio),
        "udp_ratio": _clamp(udp_ratio, 0.0, 1.0),
        "icmp_ratio": _clamp(icmp_ratio, 0.0, 1.0),
        "port_spread": _clamp(port_spread, 0, 64),
        "new_ports": _clamp(new_ports, 0, 64),
        "age_s": max(0.0, age_s),
    }


# --- benign generators -----------------------------------------------------
#
# DESIGN NOTE -- OVERLAP IS THE POINT.
#
# The first version of this file gave benign classes long lifetimes and varied
# packet sizes, and attack classes short lifetimes and uniform sizes. The
# forest promptly scored 100% accuracy by reading `age_s`, having learned
# nothing except an artefact of how the data was written.
#
# That is the single most common way a synthetic ML evaluation goes wrong, and
# a perfect score should always make us suspicious rather than pleased. The
# distributions below deliberately OVERLAP on every feature that is not a real
# signal:
#
#   * attacks can run for hours, and legitimate flows can be one second old,
#     so age_s no longer separates anything on its own;
#   * some floods use large and randomly-sized payloads (bandwidth exhaustion
#     rather than packet-rate exhaustion), so packet size is not decisive;
#   * benign traffic includes high-rate small-packet TCP (`ack_heavy`, the
#     reverse direction of any download), so "small and fast" is not decisive;
#   * benign traffic includes a busy server with genuinely high SYN share
#     (`conn_churn`), so syn_ratio alone is not decisive -- only syn_ratio
#     TOGETHER WITH syn_fin_ratio separates churn from a flood.
#
# What is left is a problem where the classes are separable, but only by
# combining several features -- which is precisely the case where a forest is
# worth more than a threshold.


def _logu(r, lo, hi):
    """Log-uniform sample. Durations and rates span orders of magnitude, and
    sampling them uniformly would put almost every value near the maximum."""
    import math
    return math.exp(r.uniform(math.log(lo), math.log(hi)))


def gen_web(r):
    """Ordinary web/API traffic: mixed sizes, occasional new connections."""
    return _row(
        pps=_logu(r, 3, 600),
        mean_len=r.uniform(180, 1450),
        len_range=r.uniform(100, 1400),
        # One SYN per connection, then many data segments.
        syn_ratio=r.uniform(0.001, 0.08),
        syn_fin_ratio=r.uniform(0.3, 3.5),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 6), new_ports=r.choice([0, 0, 0, 1, 2]),
        age_s=_logu(r, 1, 7200),
    )


def gen_bulk(r):
    """High-throughput transfer. Hard negative for any pps threshold."""
    return _row(
        pps=_logu(r, 2000, 120000),
        mean_len=r.uniform(900, 1500),
        len_range=r.uniform(400, 1450),
        syn_ratio=r.uniform(0.0, 0.004),
        syn_fin_ratio=r.uniform(0.0, 1.5),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 3), new_ports=0,
        age_s=_logu(r, 1, 3600),
    )


def gen_ack_heavy(r):
    """The reverse direction of a download: a torrent of small TCP ACKs.

    HARD NEGATIVE. High packet rate, minimum-size packets, long-lived -- it
    looks exactly like a flood on every volumetric feature. The only thing
    that distinguishes it is that essentially none of the packets are SYNs.
    Without this class in the training set, the model learns "small and fast
    = attack" and would throttle every real download on the network.
    """
    return _row(
        pps=_logu(r, 300, 40000),
        mean_len=r.uniform(54, 84),
        len_range=r.uniform(0, 40),
        syn_ratio=r.uniform(0.0, 0.01),
        syn_fin_ratio=r.uniform(0.0, 2.0),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 3), new_ports=0,
        age_s=_logu(r, 1, 3600),
    )


def gen_conn_churn(r):
    """A busy server taking many short-lived connections.

    HARD NEGATIVE for syn_ratio. A large fraction of packets really are SYNs
    here, so any rule of the form `syn_ratio > 0.3 -> attack` destroys this
    traffic. What makes it benign is that the connections COMPLETE: every SYN
    is answered eventually by a FIN or RST, so syn_fin_ratio stays near 1.
    This class is the reason syn_fin_ratio exists as a feature.
    """
    return _row(
        pps=_logu(r, 10, 5000),
        mean_len=r.uniform(70, 400),
        len_range=r.uniform(20, 900),
        syn_ratio=r.uniform(0.15, 0.48),
        syn_fin_ratio=r.uniform(0.7, 2.6),   # balanced: connections close
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 6), new_ports=r.randint(0, 2),
        age_s=_logu(r, 1, 7200),
    )


def gen_interactive(r):
    """SSH, MQTT, database chatter: small TCP packets at a low rate."""
    return _row(
        pps=_logu(r, 0.5, 120),
        mean_len=r.uniform(58, 220),
        len_range=r.uniform(0, 250),
        syn_ratio=r.uniform(0.0, 0.03),
        syn_fin_ratio=r.uniform(0.0, 2.0),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 3), new_ports=0,
        age_s=_logu(r, 1, 7200),
    )


def gen_dns(r):
    return _row(
        pps=_logu(r, 0.5, 600),
        mean_len=r.uniform(70, 520), len_range=r.uniform(20, 450),
        syn_ratio=0.0, syn_fin_ratio=0.0,
        udp_ratio=1.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 4), new_ports=r.choice([0, 0, 1]),
        age_s=_logu(r, 1, 7200),
    )


def gen_game(r):
    """Steady small UDP to one port. Superficially a UDP flood, but slow."""
    return _row(
        pps=_logu(r, 15, 400),
        mean_len=r.uniform(60, 280), len_range=r.uniform(5, 200),
        syn_ratio=0.0, syn_fin_ratio=0.0,
        udp_ratio=1.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 2), new_ports=0,
        age_s=_logu(r, 1, 7200),
    )


def gen_ping(r):
    """Includes aggressive monitoring, so ICMP alone is never conclusive."""
    return _row(
        pps=_logu(r, 0.3, 120),
        mean_len=r.uniform(84, 500), len_range=r.uniform(0, 400),
        syn_ratio=0.0, syn_fin_ratio=0.0,
        udp_ratio=0.0, icmp_ratio=1.0,
        port_spread=0, new_ports=0, age_s=_logu(r, 1, 3600),
    )


def gen_idle(r):
    return _row(
        pps=_logu(r, 0.2, 8),
        mean_len=r.uniform(60, 1200), len_range=r.uniform(0, 900),
        syn_ratio=r.uniform(0, 0.35), syn_fin_ratio=r.uniform(0, 2.5),
        udp_ratio=r.choice([0.0, 1.0]), icmp_ratio=0.0,
        port_spread=r.randint(1, 4), new_ports=r.choice([0, 1]),
        age_s=_logu(r, 1, 7200),
    )


# --- malicious generators --------------------------------------------------

def gen_syn_flood(r):
    """Overlaps bulk and ack_heavy on rate; separated by SYN share and the
    complete absence of connection teardown."""
    return _row(
        pps=_logu(r, 1500, 400000),
        mean_len=r.uniform(54, 90),
        len_range=r.uniform(0, 40),
        syn_ratio=r.uniform(0.88, 1.0),
        syn_fin_ratio=_logu(r, 25, 5000),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 4), new_ports=r.choice([0, 0, 1]),
        age_s=_logu(r, 0.5, 3600),      # attacks can run for hours
    )


def gen_udp_flood(r):
    """Two sub-shapes: packet-rate exhaustion (tiny packets) and bandwidth
    exhaustion (large, randomly sized packets). Including both stops the
    model from learning 'UDP flood == small packets'."""
    if r.random() < 0.35:
        mean_len = r.uniform(700, 1480)   # bandwidth exhaustion
        len_range = r.uniform(200, 1400)
    else:
        mean_len = r.uniform(60, 260)     # packet-rate exhaustion
        len_range = r.uniform(0, 90)
    return _row(
        pps=_logu(r, 2000, 500000),
        mean_len=mean_len, len_range=len_range,
        syn_ratio=0.0, syn_fin_ratio=0.0,
        udp_ratio=1.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 12), new_ports=r.randint(0, 6),
        age_s=_logu(r, 0.5, 3600),
    )


def gen_icmp_flood(r):
    return _row(
        pps=_logu(r, 1500, 250000),
        mean_len=r.uniform(60, 1400), len_range=r.uniform(0, 900),
        syn_ratio=0.0, syn_fin_ratio=0.0,
        udp_ratio=0.0, icmp_ratio=1.0,
        port_spread=0, new_ports=0, age_s=_logu(r, 0.5, 3600),
    )


def gen_port_scan(r):
    """Rate is unremarkable; the signature is breadth, not volume."""
    spread = r.randint(18, 64)
    return _row(
        pps=_logu(r, 15, 4000),
        mean_len=r.uniform(54, 70), len_range=r.uniform(0, 20),
        syn_ratio=r.uniform(0.8, 1.0),
        syn_fin_ratio=_logu(r, 2.5, 300),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=spread,
        new_ports=r.randint(4, min(spread, 45)),
        age_s=_logu(r, 0.5, 600),
    )


def gen_low_slow_syn(r):
    """Low-rate SYN flood: rate overlaps web, interactive and conn_churn.

    No packet-rate threshold can find this. It is separable only by the
    combination of high syn_ratio and runaway syn_fin_ratio -- and the second
    of those is what distinguishes it from benign conn_churn, which has a
    similar SYN share but closes its connections. This class is the clearest
    demonstration of what the model buys over a threshold.
    """
    return _row(
        pps=_logu(r, 15, 800),
        mean_len=r.uniform(54, 88),
        len_range=r.uniform(0, 30),
        syn_ratio=r.uniform(0.82, 1.0),
        syn_fin_ratio=_logu(r, 20, 900),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 5), new_ports=r.choice([0, 1]),
        age_s=_logu(r, 1, 1800),
    )


def gen_ack_flood(r):
    """ACK flood: spoofed mid-stream ACKs for connections that never existed.

    THE KNOWN BLIND SPOT, included on purpose.

    On the per-source aggregate features this project collects, an ACK flood
    is close to indistinguishable from gen_ack_heavy above: small TCP packets,
    high rate, almost no SYNs, in both cases. Telling them apart needs
    connection state -- knowing whether a matching handshake ever happened --
    which is exactly what a stateless XDP firewall does not have.

    Keeping this class in the training set does two useful things. It puts a
    realistic ceiling on accuracy, so the evaluation cannot report a suspicious
    100%.
    """
    return _row(
        pps=_logu(r, 3000, 300000),
        mean_len=r.uniform(54, 88),
        len_range=r.uniform(0, 40),
        syn_ratio=r.uniform(0.0, 0.03),
        syn_fin_ratio=r.uniform(0.0, 3.0),
        udp_ratio=0.0, icmp_ratio=0.0,
        port_spread=r.randint(1, 4), new_ports=r.choice([0, 1]),
        age_s=_logu(r, 0.5, 1800),
    )


BENIGN_CLASSES = [
    ("web", gen_web, 0.20),
    ("bulk", gen_bulk, 0.12),
    ("ack_heavy", gen_ack_heavy, 0.14),
    ("conn_churn", gen_conn_churn, 0.12),
    ("interactive", gen_interactive, 0.10),
    ("dns", gen_dns, 0.10),
    ("game", gen_game, 0.12),
    ("ping", gen_ping, 0.06),
    ("idle", gen_idle, 0.04),
]

MALICIOUS_CLASSES = [
    ("syn_flood", gen_syn_flood, 0.24),
    ("udp_flood", gen_udp_flood, 0.20),
    ("icmp_flood", gen_icmp_flood, 0.10),
    ("port_scan", gen_port_scan, 0.16),
    ("low_slow_syn", gen_low_slow_syn, 0.18),
    ("ack_flood", gen_ack_flood, 0.12),
]


def _pick(r, classes):
    x = r.random()
    acc = 0.0
    for name, fn, weight in classes:
        acc += weight
        if x <= acc:
            return name, fn
    return classes[-1][0], classes[-1][1]


def _jitter(r, row, strength=0.12):
    """Multiplicative noise, so no class occupies a perfectly clean region.

    Without this the classes are linearly separable by construction and the
    forest reports ~100% accuracy, which tells us nothing.
    """
    out = dict(row)
    for k in ("pps", "bps", "mean_len", "len_range", "syn_fin_ratio"):
        out[k] = max(0.0, out[k] * r.uniform(1 - strength, 1 + strength))
    for k in ("syn_ratio", "udp_ratio", "icmp_ratio"):
        out[k] = _clamp(out[k] + r.uniform(-0.03, 0.03), 0.0, 1.0)
    out["bps"] = out["pps"] * out["mean_len"]  # keep the identity consistent
    return out


def generate(n=6000, malicious_fraction=0.4, seed=42, noise=0.12):
    """Return (X, y, class_names) ready for model.train_model().

    malicious_fraction defaults to 0.4 rather than 0.5 because real traffic is
    mostly benign, and a model trained on a balanced set is over-eager on a
    realistic mix. class_weight="balanced" in the trainer handles the residual
    imbalance.
    """
    r = random.Random(seed)
    X, y, names = [], [], []

    for _ in range(n):
        if r.random() < malicious_fraction:
            cname, fn = _pick(r, MALICIOUS_CLASSES)
            label = LABEL_MALICIOUS
        else:
            cname, fn = _pick(r, BENIGN_CLASSES)
            label = LABEL_BENIGN

        row = _jitter(r, fn(r), noise)
        X.append([float(row[f]) for f in schema.FEATURE_NAMES])
        y.append(label)
        names.append(cname)

    return X, y, names
