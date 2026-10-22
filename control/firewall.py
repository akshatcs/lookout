"""Typed access to the pinned maps and the XDP program.

The format strings below mirror bpf/common.h by hand. If they drift, the
size check at the bottom fails on import instead of us reading garbage.

Addresses are packed as raw 4-byte strings ('4s'), which is already network
byte order. Packing them as integers ('I') would byte-swap them and break
prefix matching in the LPM tries.
"""

import ipaddress
import socket
import struct
import time

from .bpfmap import BPF_F_LOCK, BpfMap, BpfProg

PIN_DIR = "/sys/fs/bpf/adaptfw"
MAX_TRACKED = 32768
IDLE_TIMEOUT_S = 60     # srcstate entries idle this long get deleted

LPM_KEY = "<I4s"        # prefixlen, addr
ALLOW_VAL = "<QII"      # hits, flags, pad
BLOCK_VAL = "<QQII"     # expires_ns, hits, reason, pad
PORT_KEY = "<BxH"       # proto, pad, port (host order)
PORT_VAL = "<QII"       # hits, action, pad
SRC_KEY = "<4s"
SRC_STATE = "<I4x12Q"   # lock, pad, 12 u64 fields
CONFIG = "<QQIIII"      # rate_pps, burst_pkts, features, aggressiveness, policy, pad

SRC_STATE_FIELDS = (
    "lock", "tokens", "last_refill_ns", "last_seen_ns",
    "packets", "bytes", "dropped", "syn", "fin", "rst", "udp", "icmp",
    "port_bitmap",
)

ALLOW, DENY = 0, 1                      # enum fw_action
ACTIONS = {ALLOW: "allow", DENY: "deny"}

BLOCK_MANUAL, BLOCK_AUTO = 0, 1
BLOCK_REASONS = {BLOCK_MANUAL: "manual", BLOCK_AUTO: "auto"}

PROTOCOLS = {"icmp": 1, "tcp": 6, "udp": 17}

FEATURES = {            # name -> bit, same order as FEAT_* in common.h
    "allowlist": 1 << 0,
    "blocklist": 1 << 1,
    "proto": 1 << 2,
    "ratelimit": 1 << 3,
    "state": 1 << 4,
    "frags": 1 << 5,
    "ports": 1 << 6,
}

STAT_NAMES = [          # same order as enum stat_index
    "rx_packets", "rx_bytes",
    "pass_allowlist", "pass_rule", "pass_default", "pass_non_ipv4",
    "drop_blocklist", "drop_port_rule", "drop_default", "drop_proto",
    "drop_ratelimit", "drop_malformed", "drop_fragment",
    "state_full",
]

# Every packet that reaches the rate limiter ends up in one of these. The
# controller measures load as their sum: traffic that the allowlist passes
# or the blocklist, port rules or default policy drop has already been
# decided and isn't something a tighter rate limit would help with.
LIMITER_INPUT = ("pass_rule", "pass_default", "drop_ratelimit")


def parse_cidr(cidr):
    """'10.0.0.1' or '10.0.0.0/8' -> IPv4Network. Host bits are cleared,
    so '10.0.0.5/24' means 10.0.0.0/24."""
    try:
        return ipaddress.IPv4Network(cidr.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"not an IPv4 address or prefix: {cidr!r}") from e


def lpm_key(cidr):
    net = parse_cidr(cidr)
    return struct.pack(LPM_KEY, net.prefixlen, net.network_address.packed)


def unpack_cidr(key):
    plen, addr = struct.unpack(LPM_KEY, key)
    return f"{socket.inet_ntoa(addr)}/{plen}"


def parse_proto(name):
    """'tcp', 'udp', 'icmp' or a protocol number."""
    name = str(name).lower()
    if name in PROTOCOLS:
        return PROTOCOLS[name]
    if name.isdigit() and 0 <= int(name) <= 255:
        return int(name)
    raise ValueError(f"unknown protocol {name!r} (use tcp, udp, icmp or a number)")


def proto_name(num):
    return next((n for n, v in PROTOCOLS.items() if v == num), str(num))


def port_key(proto, port):
    proto = parse_proto(proto)
    port = int(port)
    limit = 255 if proto == PROTOCOLS["icmp"] else 65535
    if not 0 <= port <= limit:
        raise ValueError(f"port {port} out of range for {proto_name(proto)}")
    return struct.pack(PORT_KEY, proto, port)


def describe_features(bits):
    return " ".join(n for n, b in FEATURES.items() if bits & b) or "(none)"


def ktime_ns():
    # bpf_ktime_get_ns() is CLOCK_MONOTONIC. time.time() would put every
    # block deadline about 50 years in the future.
    return time.monotonic_ns()


class Firewall:
    def __init__(self, pin_dir=PIN_DIR):
        self.pin_dir = pin_dir
        self.allowlist = BpfMap(f"{pin_dir}/allowlist", 8, 16)
        self.blocklist = BpfMap(f"{pin_dir}/blocklist", 8, 24)
        self.portrules = BpfMap(f"{pin_dir}/portrules", 4, 16, percpu=True)
        self.srcstate = BpfMap(f"{pin_dir}/srcstate", 4, 104)
        self.stats = BpfMap(f"{pin_dir}/stats", 4, 8, percpu=True)
        self.config = BpfMap(f"{pin_dir}/config", 4, 32)
        self.maps = (self.allowlist, self.blocklist, self.portrules,
                     self.srcstate, self.stats, self.config)

    def close(self):
        for m in self.maps:
            m.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # allowlist

    def allow(self, cidr):
        self.allowlist.update(lpm_key(cidr), struct.pack(ALLOW_VAL, 0, 0, 0))

    def unallow(self, cidr):
        return self.allowlist.delete(lpm_key(cidr))

    def is_allowed(self, ip):
        # the trie does the prefix match, so a /32 lookup finds a covering /8
        return self.allowlist.lookup(lpm_key(ip)) is not None

    def list_allowed(self):
        for key, val in self.allowlist.items():
            yield {"cidr": unpack_cidr(key),
                   "hits": struct.unpack(ALLOW_VAL, val)[0]}

    # blocklist

    def block(self, cidr, duration_s=60, reason=BLOCK_MANUAL):
        """Block for duration_s seconds; 0 or less means permanent."""
        expires = ktime_ns() + int(duration_s * 1e9) if duration_s > 0 else 0
        self.blocklist.update(lpm_key(cidr),
                              struct.pack(BLOCK_VAL, expires, 0, reason, 0))

    def unblock(self, cidr):
        return self.blocklist.delete(lpm_key(cidr))

    def clear_blocks(self):
        keys = self.blocklist.keys()
        for k in keys:
            self.blocklist.delete(k)
        return len(keys)

    def list_blocked(self, include_expired=False):
        now = ktime_ns()
        for key, val in self.blocklist.items():
            expires, hits, reason, _ = struct.unpack(BLOCK_VAL, val)
            expired = expires != 0 and expires <= now
            if expired and not include_expired:
                continue
            yield {
                "cidr": unpack_cidr(key),
                "hits": hits,
                "reason": BLOCK_REASONS.get(reason, str(reason)),
                "remaining_s": None if expires == 0 else max(0, expires - now) / 1e9,
                "expired": expired,
            }

    def is_blocked(self, ip):
        raw = self.blocklist.lookup(lpm_key(ip))
        if raw is None:
            return False
        expires = struct.unpack(BLOCK_VAL, raw)[0]
        return expires == 0 or expires > ktime_ns()

    def remove_expired_blocks(self):
        # The kernel already ignores expired entries; this just frees slots.
        now = ktime_ns()
        doomed = [k for k, v in self.blocklist.items()
                  if 0 < struct.unpack(BLOCK_VAL, v)[0] <= now]
        for k in doomed:
            self.blocklist.delete(k)
        return len(doomed)

    # port rules

    def set_port_rule(self, proto, port, action):
        # a per-CPU map: every CPU gets its own copy of the rule
        self.portrules.update(port_key(proto, port),
                              struct.pack(PORT_VAL, 0, action, 0) * self.portrules.ncpu)

    def del_port_rule(self, proto, port):
        return self.portrules.delete(port_key(proto, port))

    def clear_port_rules(self):
        keys = self.portrules.keys()
        for k in keys:
            self.portrules.delete(k)
        return len(keys)

    def list_port_rules(self):
        for key, val in self.portrules.items():
            proto, port = struct.unpack(PORT_KEY, key)
            copies = list(struct.iter_unpack(PORT_VAL, val))
            hits, action = sum(c[0] for c in copies), copies[0][1]
            yield {"proto": proto_name(proto), "port": port,
                   "action": ACTIONS.get(action, str(action)), "hits": hits}

    # per-source state

    def read_states(self):
        """{ip: dict of src_state fields}. Read under the entry's lock."""
        out = {}
        for key, val in self.srcstate.items(BPF_F_LOCK):
            out[socket.inet_ntoa(key)] = dict(
                zip(SRC_STATE_FIELDS, struct.unpack(SRC_STATE, val)))
        return out

    def remove_idle_states(self, idle_s=IDLE_TIMEOUT_S):
        # srcstate is a plain hash (it holds a spin lock, so it can't be an
        # LRU), so nothing else ever removes stale entries.
        cutoff = ktime_ns() - int(idle_s * 1e9)
        doomed = [socket.inet_aton(ip) for ip, st in self.read_states().items()
                  if st["last_seen_ns"] < cutoff]
        for k in doomed:
            self.srcstate.delete(k)
        return len(doomed)

    def clear_states(self):
        keys = self.srcstate.keys()
        for k in keys:
            self.srcstate.delete(k)
        return len(keys)

    # stats

    def read_stats(self):
        out = {name: self.stats.sum_percpu(struct.pack("<I", i))
               for i, name in enumerate(STAT_NAMES)}
        out["drops_total"] = sum(v for k, v in out.items() if k.startswith("drop_"))
        out["passes_total"] = sum(v for k, v in out.items() if k.startswith("pass_"))
        return out

    def reset_stats(self):
        zero = bytes(self.stats.value_size)
        for i in range(len(STAT_NAMES)):
            self.stats.update(struct.pack("<I", i), zero)

    # config

    def read_config(self):
        rate, burst, feats, level, policy, _ = struct.unpack(
            CONFIG, self.config.lookup(struct.pack("<I", 0)))
        return {"rate_pps": rate, "burst_pkts": burst, "features": feats,
                "aggressiveness": level, "default_policy": policy}

    def update_config(self, **changes):
        cfg = self.read_config()
        unknown = set(changes) - set(cfg)
        if unknown:
            raise ValueError(f"unknown config field(s): {', '.join(sorted(unknown))}")
        cfg.update(changes)
        self.config.update(struct.pack("<I", 0), struct.pack(
            CONFIG, cfg["rate_pps"], cfg["burst_pkts"], cfg["features"],
            cfg["aggressiveness"], cfg["default_policy"], 0))
        return cfg

    # the program itself

    def prog_info(self):
        """id, tag, instruction counts and (if kernel.bpf_stats_enabled=1)
        the time spent in the program, straight from the kernel."""
        with BpfProg(f"{self.pin_dir}/xdp_firewall") as prog:
            return prog.info()


for _fmt, _size in ((LPM_KEY, 8), (ALLOW_VAL, 16), (BLOCK_VAL, 24),
                    (PORT_KEY, 4), (PORT_VAL, 16), (SRC_KEY, 4),
                    (SRC_STATE, 104), (CONFIG, 32)):
    assert struct.calcsize(_fmt) == _size, f"{_fmt} no longer matches common.h"
assert len(struct.unpack(SRC_STATE, bytes(104))) == len(SRC_STATE_FIELDS)
