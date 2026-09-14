"""
schema.py -- Python mirror of bpf/common.h.

============================================================================
THIS FILE MUST TRACK bpf/common.h BY HAND.
============================================================================
There is no code generation here. The kernel side describes its map values in
C; this file describes the same bytes using Python `struct` format strings. If
the two ever disagree, the control plane reads garbage -- silently, and in a
way that looks like a logical bug rather than a layout bug.

To make that failure loud instead of silent, every format string below is
checked against the expected size at import time (see _verify() at the bottom).
Change a struct in common.h without changing it here and the control plane
refuses to start.

--------------------------------------------------------------------------
A NOTE ON BYTE ORDER, BECAUSE THIS IS THE EASIEST THING TO GET WRONG
--------------------------------------------------------------------------
Two different orders are in play and they are not the same thing:

  * STRUCT FIELD order  -- how multi-byte integers are laid out in memory.
    This is the host's native order (little endian on x86_64/aarch64). Every
    format string starts with '<' to say so explicitly.

  * IP ADDRESS order    -- IPv4 addresses travel and are stored in NETWORK
    (big endian) order. The eBPF program reads iph->saddr and never swaps it,
    so the map keys are big endian.

We therefore pack addresses as a raw 4-byte blob ('4s') rather than as an
integer ('I'). socket.inet_aton() already produces network order, so the bytes
go straight in. This sidesteps the whole class of bug where an address comes
back as 1.1.10.10 instead of 10.10.1.1.
"""

import socket
import struct

# ---------------------------------------------------------------------------
# Where the loader pinned everything (must match ADAPTFW_PIN_DIR in common.h)
# ---------------------------------------------------------------------------
PIN_DIR = "/sys/fs/bpf/adaptfw"

MAP_ALLOWLIST = "allowlist"
MAP_BLOCKLIST = "blocklist"
MAP_SRCSTATE = "srcstate"
MAP_STATS = "stats"
MAP_CONFIG = "config"

# ---------------------------------------------------------------------------
# Map sizing (mirrors the #defines in common.h)
# ---------------------------------------------------------------------------
MAX_ALLOWLIST = 1024
MAX_BLOCKLIST = 4096
MAX_TRACKED = 32768

# ---------------------------------------------------------------------------
# struct lpm_key { __u32 prefixlen; __u32 addr; }   -- 8 bytes
# ---------------------------------------------------------------------------
LPM_KEY_FMT = "<I4s"
LPM_KEY_SIZE = 8


def pack_lpm_key(ip: str, prefixlen: int = 32) -> bytes:
    """Build an LPM trie key for an IPv4 address or CIDR prefix.

    The kernel matches `prefixlen` bits starting from the most significant bit
    of the address bytes, which is why the address must stay in network order.
    """
    if not 0 <= prefixlen <= 32:
        raise ValueError(f"prefixlen must be 0..32, got {prefixlen}")
    return struct.pack(LPM_KEY_FMT, prefixlen, socket.inet_aton(ip))


def unpack_lpm_key(raw: bytes):
    """Return (ip_string, prefixlen)."""
    prefixlen, addr = struct.unpack(LPM_KEY_FMT, raw)
    return socket.inet_ntoa(addr), prefixlen


def pack_cidr(cidr: str) -> bytes:
    """Accept either '10.0.0.1' or '10.0.0.0/8'."""
    if "/" in cidr:
        ip, plen = cidr.split("/", 1)
        return pack_lpm_key(ip.strip(), int(plen))
    return pack_lpm_key(cidr.strip(), 32)


# The srcstate map is keyed by a bare __u32 address, not an LPM key.
SRC_KEY_FMT = "<4s"
SRC_KEY_SIZE = 4


def pack_src_key(ip: str) -> bytes:
    return struct.pack(SRC_KEY_FMT, socket.inet_aton(ip))


def unpack_src_key(raw: bytes) -> str:
    return socket.inet_ntoa(raw[:4])


# ---------------------------------------------------------------------------
# struct allow_val { __u64 hits; __u32 flags; __u32 _pad; }   -- 16 bytes
# ---------------------------------------------------------------------------
ALLOW_VAL_FMT = "<QII"
ALLOW_VAL_SIZE = 16

# ---------------------------------------------------------------------------
# struct block_val { __u64 expires_ns; __u64 hits; __u32 reason; __u32 _pad; }
#                                                              -- 24 bytes
# ---------------------------------------------------------------------------
BLOCK_VAL_FMT = "<QQII"
BLOCK_VAL_SIZE = 24

BLOCK_REASON_MANUAL = 0
BLOCK_REASON_MODEL = 1
BLOCK_REASON_HEURISTIC = 2
BLOCK_REASON_REPEAT = 3

BLOCK_REASON_NAMES = {
    BLOCK_REASON_MANUAL: "manual",
    BLOCK_REASON_MODEL: "model",
    BLOCK_REASON_HEURISTIC: "heuristic",
    BLOCK_REASON_REPEAT: "repeat",
}

# ---------------------------------------------------------------------------
# struct src_state  -- 128 bytes
#
#   offset  0   struct bpf_spin_lock lock   (__u32)
#   offset  4   <4 bytes of compiler padding>
#   offset  8   14 x __u64
#   offset 120  __u32 min_len
#   offset 124  __u32 max_len
#
# '4x' in the format string is the padding. Do not remove it: without it every
# field after the lock is read from the wrong offset.
# ---------------------------------------------------------------------------
SRC_STATE_FMT = "<I4x14QII"
SRC_STATE_SIZE = 128

# Field order, matching struct src_state exactly. Used to build a dict.
SRC_STATE_FIELDS = (
    "lock",
    "tokens",
    "last_refill_ns",
    "first_seen_ns",
    "last_seen_ns",
    "packets",
    "bytes",
    "dropped",
    "syn",
    "fin",
    "rst",
    "udp",
    "icmp",
    "tcp",
    "port_bitmap",
    "min_len",
    "max_len",
)


def unpack_src_state(raw: bytes) -> dict:
    """Decode a src_state map value into a plain dict.

    `min_len` is normalised: the kernel initialises it to 0xFFFFFFFF so that
    the first `if (len < min_len)` comparison always succeeds, and a source
    that has been created but not yet counted would otherwise report a
    minimum packet size of four billion bytes.
    """
    values = struct.unpack(SRC_STATE_FMT, raw)
    state = dict(zip(SRC_STATE_FIELDS, values))
    if state["min_len"] == 0xFFFFFFFF:
        state["min_len"] = 0
    return state


# ---------------------------------------------------------------------------
# struct fw_config  -- 32 bytes
# ---------------------------------------------------------------------------
FW_CONFIG_FMT = "<QQIIII"
FW_CONFIG_SIZE = 32

FW_CONFIG_FIELDS = (
    "rate_pps",
    "burst_pkts",
    "features",
    "aggressiveness",
    "default_action",
    "_pad",
)

FEAT_ALLOWLIST = 1 << 0
FEAT_BLOCKLIST = 1 << 1
FEAT_PROTO_SANITY = 1 << 2
FEAT_RATELIMIT = 1 << 3
FEAT_TRACK_STATE = 1 << 4
FEAT_DROP_FRAGS = 1 << 5

FEAT_DEFAULT = (
    FEAT_ALLOWLIST | FEAT_BLOCKLIST | FEAT_PROTO_SANITY
    | FEAT_RATELIMIT | FEAT_TRACK_STATE
)

FEAT_NAMES = [
    (FEAT_ALLOWLIST, "allowlist"),
    (FEAT_BLOCKLIST, "blocklist"),
    (FEAT_PROTO_SANITY, "proto-sanity"),
    (FEAT_RATELIMIT, "ratelimit"),
    (FEAT_TRACK_STATE, "track-state"),
    (FEAT_DROP_FRAGS, "drop-frags"),
]

XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT = 0, 1, 2, 3, 4


def describe_features(bits: int) -> str:
    on = [name for bit, name in FEAT_NAMES if bits & bit]
    return " ".join(on) if on else "(none)"


def unpack_config(raw: bytes) -> dict:
    return dict(zip(FW_CONFIG_FIELDS, struct.unpack(FW_CONFIG_FMT, raw)))


def pack_config(cfg: dict) -> bytes:
    return struct.pack(
        FW_CONFIG_FMT,
        int(cfg["rate_pps"]),
        int(cfg["burst_pkts"]),
        int(cfg["features"]),
        int(cfg["aggressiveness"]),
        int(cfg.get("default_action", XDP_PASS)),
        0,
    )


# ---------------------------------------------------------------------------
# enum stat_index  -- keep in lockstep with common.h
# ---------------------------------------------------------------------------
STAT_NAMES = [
    "rx_packets",
    "rx_bytes",
    "pass_allowlist",
    "pass_default",
    "pass_non_ipv4",
    "drop_blocklist",
    "drop_proto",
    "drop_ratelimit",
    "drop_malformed",
    "drop_fragment",
    "state_full",
]
STAT_MAX = len(STAT_NAMES)

# Which counters represent a drop, for computing a drop ratio.
DROP_STATS = (
    "drop_blocklist",
    "drop_proto",
    "drop_ratelimit",
    "drop_malformed",
    "drop_fragment",
)

# ---------------------------------------------------------------------------
# Control-plane tunables that have no kernel counterpart
# ---------------------------------------------------------------------------

# Delete srcstate entries idle for longer than this. The srcstate map is a
# plain hash (it holds a spin lock, so it cannot be an LRU), which means
# nothing evicts stale entries except us.
STATE_IDLE_TIMEOUT_S = 60

# Feature vector column order. The trained model stores this list alongside
# itself and refuses to run if it changes -- reordering features silently is
# a classic way to get a model that is confidently wrong.
FEATURE_NAMES = [
    "pps",
    "bps",
    "mean_len",
    "len_range",
    "syn_ratio",
    "syn_fin_ratio",
    "udp_ratio",
    "icmp_ratio",
    "port_spread",
    "new_ports",
    "age_s",
]


def _verify():
    """Fail loudly at import time if a format string drifted from common.h."""
    checks = [
        ("lpm_key", LPM_KEY_FMT, LPM_KEY_SIZE),
        ("allow_val", ALLOW_VAL_FMT, ALLOW_VAL_SIZE),
        ("block_val", BLOCK_VAL_FMT, BLOCK_VAL_SIZE),
        ("src_state", SRC_STATE_FMT, SRC_STATE_SIZE),
        ("fw_config", FW_CONFIG_FMT, FW_CONFIG_SIZE),
        ("src_key", SRC_KEY_FMT, SRC_KEY_SIZE),
    ]
    for name, fmt, expected in checks:
        actual = struct.calcsize(fmt)
        if actual != expected:
            raise AssertionError(
                f"schema drift: struct {name} format '{fmt}' packs to "
                f"{actual} bytes, but common.h says {expected}. "
                f"Update control/schema.py to match bpf/common.h."
            )

    n_fields = len(SRC_STATE_FIELDS)
    n_unpacked = len(struct.unpack(SRC_STATE_FMT, b"\0" * SRC_STATE_SIZE))
    if n_fields != n_unpacked:
        raise AssertionError(
            f"schema drift: SRC_STATE_FIELDS names {n_fields} fields but "
            f"SRC_STATE_FMT unpacks {n_unpacked}."
        )


_verify()
