"""
firewall.py -- a typed, friendly view of the five pinned BPF maps.

bpfmap.py speaks raw bytes to the kernel. schema.py knows the byte layouts.
This module puts them together so the rest of the control plane can write

    fw.block("10.10.1.3", duration_s=60, reason=BLOCK_REASON_MODEL)

instead of packing structs by hand. Everything above this layer -- the policy
engine, the CLI, the collector -- goes through this class and never touches a
struct format string.
"""

import struct
import time

from . import schema
from .bpfmap import BPF_ANY, BPF_F_LOCK, BPF_NOEXIST, BpfError, BpfMap


class Firewall:
    """Open handles to every pinned map belonging to one loaded firewall."""

    def __init__(self, pin_dir=None):
        self.pin_dir = pin_dir or schema.PIN_DIR

        try:
            self.allowlist = BpfMap(
                schema.MAP_ALLOWLIST, schema.LPM_KEY_SIZE,
                schema.ALLOW_VAL_SIZE, pin_dir=self.pin_dir,
            )
            self.blocklist = BpfMap(
                schema.MAP_BLOCKLIST, schema.LPM_KEY_SIZE,
                schema.BLOCK_VAL_SIZE, pin_dir=self.pin_dir,
            )
            self.srcstate = BpfMap(
                schema.MAP_SRCSTATE, schema.SRC_KEY_SIZE,
                schema.SRC_STATE_SIZE, pin_dir=self.pin_dir,
            )
            self.stats = BpfMap(
                schema.MAP_STATS, 4, 8, pin_dir=self.pin_dir, percpu=True,
            )
            self.config = BpfMap(
                schema.MAP_CONFIG, 4, schema.FW_CONFIG_SIZE,
                pin_dir=self.pin_dir,
            )
        except BpfError as e:
            raise BpfError(
                e.errno,
                f"{e.strerror}\n\n"
                f"Could not open the pinned maps in {self.pin_dir}.\n"
                f"  * Is the firewall loaded?   sudo ./bin/fwload -i <iface>\n"
                f"  * Are you running as root?  sudo python3 -m control...\n"
            ) from None

    def close(self):
        for m in (self.allowlist, self.blocklist, self.srcstate,
                  self.stats, self.config):
            try:
                m.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # =====================================================================
    # Clock
    # =====================================================================

    @staticmethod
    def ktime_ns() -> int:
        """Read the same clock the eBPF program uses.

        bpf_ktime_get_ns() returns CLOCK_MONOTONIC. Python's
        time.monotonic_ns() reads the same clock source, so timestamps we
        write into the blocklist are directly comparable with the ones the
        kernel computes.

        Getting this wrong is a genuinely nasty bug: use time.time() here and
        every block we insert expires roughly fifty years in the future,
        because CLOCK_REALTIME counts from 1970 while CLOCK_MONOTONIC counts
        from boot. The firewall would appear to work perfectly and never
        unblock anything.
        """
        return time.monotonic_ns()

    # =====================================================================
    # Allowlist
    # =====================================================================

    def allow(self, cidr: str):
        """Add a prefix that must never be filtered."""
        key = schema.pack_cidr(cidr)
        val = struct.pack(schema.ALLOW_VAL_FMT, 0, 0, 0)
        self.allowlist.update(key, val, BPF_ANY)

    def unallow(self, cidr: str) -> bool:
        return self.allowlist.delete(schema.pack_cidr(cidr))

    def list_allowed(self):
        """Yield dicts describing each allowlist entry."""
        for key, val in self.allowlist.items():
            ip, plen = schema.unpack_lpm_key(key)
            hits, flags, _ = struct.unpack(schema.ALLOW_VAL_FMT, val)
            yield {"cidr": f"{ip}/{plen}", "hits": hits, "flags": flags}

    def is_allowed(self, ip: str) -> bool:
        """True if `ip` is covered by any allowlist prefix.

        The kernel does longest-prefix matching for us, so a /32 lookup finds
        a covering /8. This is the check the policy engine uses before ever
        blocking anything -- the outermost safety rail.
        """
        return self.allowlist.lookup(schema.pack_lpm_key(ip, 32)) is not None

    # =====================================================================
    # Blocklist
    # =====================================================================

    def block(self, cidr: str, duration_s: float = 60.0,
              reason: int = schema.BLOCK_REASON_MANUAL):
        """Drop traffic from `cidr` for `duration_s` seconds.

        duration_s <= 0 means permanent (expires_ns = 0).

        The expiry is stored as an absolute CLOCK_MONOTONIC deadline and the
        kernel checks it on every packet, so the block lifts on time even if
        this process is no longer running.
        """
        if duration_s and duration_s > 0:
            expires = self.ktime_ns() + int(duration_s * 1e9)
        else:
            expires = 0
        key = schema.pack_cidr(cidr)
        val = struct.pack(schema.BLOCK_VAL_FMT, expires, 0, reason, 0)
        self.blocklist.update(key, val, BPF_ANY)

    def unblock(self, cidr: str) -> bool:
        return self.blocklist.delete(schema.pack_cidr(cidr))

    def list_blocked(self, include_expired: bool = True):
        now = self.ktime_ns()
        for key, val in self.blocklist.items():
            ip, plen = schema.unpack_lpm_key(key)
            expires, hits, reason, _ = struct.unpack(schema.BLOCK_VAL_FMT, val)
            expired = expires != 0 and expires <= now
            if expired and not include_expired:
                continue
            remaining = None if expires == 0 else max(0.0, (expires - now) / 1e9)
            yield {
                "cidr": f"{ip}/{plen}",
                "hits": hits,
                "reason": schema.BLOCK_REASON_NAMES.get(reason, str(reason)),
                "reason_code": reason,
                "expires_ns": expires,
                "remaining_s": remaining,
                "expired": expired,
            }

    def is_blocked(self, ip: str) -> bool:
        raw = self.blocklist.lookup(schema.pack_lpm_key(ip, 32))
        if raw is None:
            return False
        expires, _, _, _ = struct.unpack(schema.BLOCK_VAL_FMT, raw)
        return expires == 0 or expires > self.ktime_ns()

    def gc_blocklist(self) -> int:
        """Delete entries whose deadline has passed. Returns how many.

        This only reclaims map slots; it is not what makes blocks expire. The
        kernel already stopped enforcing them the moment the deadline passed.
        """
        now = self.ktime_ns()
        doomed = []
        for key, val in self.blocklist.items():
            expires, _, _, _ = struct.unpack(schema.BLOCK_VAL_FMT, val)
            if expires != 0 and expires <= now:
                doomed.append(key)
        for key in doomed:
            self.blocklist.delete(key)
        return len(doomed)

    # =====================================================================
    # Per-source state
    # =====================================================================

    def read_states(self) -> dict:
        """Snapshot every tracked source. Returns {ip_string: state_dict}.

        BPF_F_LOCK is passed so the kernel holds each entry's spin lock while
        copying it out. Without it, a value could be copied mid-update and we
        would occasionally see a byte count that does not match its packet
        count.
        """
        out = {}
        for key, val in self.srcstate.items(flags=BPF_F_LOCK):
            ip = schema.unpack_src_key(key)
            out[ip] = schema.unpack_src_state(val)
        return out

    def gc_states(self, idle_timeout_s=None) -> int:
        """Delete sources idle for longer than the timeout. Returns how many.

        This is load-bearing, not housekeeping. The srcstate map holds a
        bpf_spin_lock, which the kernel only permits in HASH and ARRAY maps --
        not in LRU_HASH. So nothing evicts stale entries automatically and
        without this sweep a long source-spoofing flood fills the map
        permanently.
        """
        timeout = idle_timeout_s or schema.STATE_IDLE_TIMEOUT_S
        cutoff = self.ktime_ns() - int(timeout * 1e9)
        doomed = []
        for key, val in self.srcstate.items(flags=BPF_F_LOCK):
            st = schema.unpack_src_state(val)
            if st["last_seen_ns"] < cutoff:
                doomed.append(key)
        for key in doomed:
            self.srcstate.delete(key)
        return len(doomed)

    def forget(self, ip: str) -> bool:
        """Drop one source's state, resetting its bucket and counters."""
        return self.srcstate.delete(schema.pack_src_key(ip))

    def clear_states(self) -> int:
        keys = list(self.srcstate.keys())
        for k in keys:
            self.srcstate.delete(k)
        return len(keys)

    # =====================================================================
    # Statistics
    # =====================================================================

    def read_stats(self) -> dict:
        """Sum the per-CPU counters. Returns {stat_name: total}."""
        out = {}
        for idx, name in enumerate(schema.STAT_NAMES):
            out[name] = self.stats.sum_percpu_u64(struct.pack("<I", idx))
        out["drops_total"] = sum(out[n] for n in schema.DROP_STATS)
        out["passes_total"] = (
            out["pass_allowlist"] + out["pass_default"] + out["pass_non_ipv4"]
        )
        return out

    def reset_stats(self):
        """Zero every counter on every CPU."""
        zero = b"\0" * self.stats.buf_size
        for idx in range(len(schema.STAT_NAMES)):
            self.stats.update(struct.pack("<I", idx), zero, BPF_ANY)

    # =====================================================================
    # Configuration
    # =====================================================================

    def read_config(self) -> dict:
        raw = self.config.lookup(struct.pack("<I", 0))
        if raw is None:
            raise BpfError(2, "config map is empty -- was the firewall loaded?")
        return schema.unpack_config(raw)

    def write_config(self, cfg: dict):
        self.config.update(struct.pack("<I", 0), schema.pack_config(cfg),
                           BPF_ANY)

    def update_config(self, **changes):
        """Read-modify-write a subset of config fields. Returns the new config."""
        cfg = self.read_config()
        cfg.update(changes)
        self.write_config(cfg)
        return cfg


