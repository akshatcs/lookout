/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h -- Shared data layout for the Adaptive XDP/eBPF Firewall.
 *
 * ============================================================================
 * THIS FILE IS THE CONTRACT.
 * ============================================================================
 * Three separate programs have to agree, byte for byte, on what is stored in
 * the BPF maps:
 *
 *   1. bpf/firewall.bpf.c  -- the kernel data plane (writes most of it)
 *   2. src/loader.c        -- the C loader (writes the initial config)
 *   3. control/schema.py   -- the Python control plane (reads and writes)
 *
 * (1) and (2) include this header directly. (3) mirrors it by hand using
 * Python `struct` format strings. control/schema.py contains assertions that
 * check its formats produce the same sizes declared at the bottom of this
 * file, so if we change a struct here and forget to change schema.py, the
 * Python side refuses to start instead of silently reading garbage.
 *
 * RULES FOR EDITING:
 *   - Keep every struct explicitly padded to an 8-byte multiple. The BPF
 *     verifier requires map value sizes to be stable, and implicit tail
 *     padding is an easy way to get a mismatch between C and Python.
 *   - Put __u64 fields before __u32 fields so the compiler does not insert
 *     padding you did not plan for.
 *   - If we change ANY struct, run `make check-schema` and re-run the loader
 *     with `-u` (unload) first, because libbpf refuses to reuse an existing
 *     pinned map whose value size no longer matches.
 */

#ifndef __ADAPTFW_COMMON_H
#define __ADAPTFW_COMMON_H

/* ---------------------------------------------------------------------------
 * Map sizing
 * -------------------------------------------------------------------------*/

/* Number of CIDR prefixes we can allow-list. LPM tries are sparse, so this
 * costs nothing until entries are actually inserted. */
#define MAX_ALLOWLIST 1024

/* Number of CIDR prefixes the control plane may block at once. The control
 * plane also enforces its own, lower cap (see control/policy.py). */
#define MAX_BLOCKLIST 4096

/* Number of distinct source IPs we hold rate-limiter + behaviour state for.
 * This map is PREALLOCATED, so it costs MAX_TRACKED * sizeof(struct
 * src_state) = 32768 * 128 = 4 MiB of kernel memory, always. That is a
 * deliberate trade: preallocation means we never allocate on the packet path.
 *
 * Because the map is a plain hash (see the note on spin locks below) it can
 * fill up under a source-spoofing flood. When it does, the XDP program counts
 * the event in STAT_STATE_FULL and falls back to the configured default
 * verdict rather than failing. The control plane garbage-collects entries that
 * have been idle for STATE_IDLE_TIMEOUT seconds on every poll. */
#define MAX_TRACKED 32768

/* ---------------------------------------------------------------------------
 * Keys
 * -------------------------------------------------------------------------*/

/*
 * LPM trie key. The kernel's longest-prefix-match trie requires a key that
 * starts with a u32 prefix length, followed by the value to match, and it
 * matches bits starting from the MOST significant bit of the first byte.
 *
 * `addr` is therefore stored in NETWORK byte order (big endian), exactly as it
 * appears in the IP header. That is what makes 10.0.0.0/8 work: prefixlen 8
 * matches the first byte, which is 10.
 *
 * Do NOT byte-swap this field. The one place it is easy to get wrong is the
 * Python side -- schema.py uses socket.inet_aton(), which already returns
 * network order, and packs it as a raw 4-byte blob for exactly this reason.
 */
struct lpm_key {
	__u32 prefixlen; /* 0..32 */
	__u32 addr;      /* IPv4, NETWORK byte order */
}; /* 8 bytes */

/* ---------------------------------------------------------------------------
 * Values
 * -------------------------------------------------------------------------*/

/* Value stored in the allowlist trie. */
struct allow_val {
	__u64 hits;  /* packets that matched this prefix */
	__u32 flags; /* reserved for future per-rule behaviour; must be 0 */
	__u32 _pad;
}; /* 16 bytes */

/* Reason codes recorded when the control plane inserts a blocklist entry.
 * These are purely informational -- the kernel never branches on them -- but
 * they make `fwctl block list` readable and are worth showing in the demo. */
enum block_reason {
	BLOCK_REASON_MANUAL = 0,   /* a human ran `fwctl block add` */
	BLOCK_REASON_MODEL  = 1,   /* the Random Forest classified it malicious */
	BLOCK_REASON_HEURISTIC = 2,/* the static-threshold fallback fired */
	BLOCK_REASON_REPEAT = 3,   /* re-block of a known repeat offender */
};

/*
 * Value stored in the blocklist trie.
 *
 * `expires_ns` is an ABSOLUTE timestamp on the CLOCK_MONOTONIC scale returned
 * by bpf_ktime_get_ns(). The XDP program compares it against the current time
 * itself, so an entry stops being enforced at exactly the right moment even if
 * the userspace control plane has crashed, stalled, or been killed. Userspace
 * only ever deletes already-expired keys; it is a janitor, not the authority.
 *
 * A value of 0 means "never expires" (used for manual permanent blocks).
 */
struct block_val {
	__u64 expires_ns; /* bpf_ktime_get_ns() deadline, 0 = permanent */
	__u64 hits;       /* packets dropped by this entry */
	__u32 reason;     /* enum block_reason */
	__u32 _pad;
}; /* 24 bytes */

/*
 * Per-source-IP state. This single struct holds BOTH the token-bucket rate
 * limiter and the behavioural counters that feed the ML model.
 *
 * WHY ONE STRUCT AND NOT TWO MAPS:
 *   Merging them means one map lookup per packet instead of two, and it means
 *   the counters are updated inside the same critical section as the rate
 *   limiter, so they are exact rather than racy.
 *
 * WHY struct bpf_spin_lock:
 *   A token bucket is a read-modify-write of two fields (tokens and
 *   last_refill_ns). Without a lock, two CPUs handling packets from the same
 *   source race and lose updates, which lets traffic through above the
 *   configured rate. A BPF spin lock makes the critical section atomic.
 *
 *   The lock costs us one thing: the kernel only permits struct bpf_spin_lock
 *   inside BPF_MAP_TYPE_HASH and BPF_MAP_TYPE_ARRAY values -- NOT inside
 *   BPF_MAP_TYPE_LRU_HASH. So this map cannot self-evict, and we accept the
 *   map-full case described above under MAX_TRACKED instead. This trade is
 *   discussed at length in docs/ARCHITECTURE.md.
 *
 * RULES THE VERIFIER ENFORCES ON THE LOCK (see firewall.bpf.c):
 *   - The lock must be the first field, at offset 0.
 *   - No helper calls of any kind between bpf_spin_lock() and
 *     bpf_spin_unlock() -- that includes bpf_ktime_get_ns() and any map
 *     lookup. Read everything we need BEFORE taking the lock.
 *   - The program may not return while holding the lock.
 *   - Userspace must pass BPF_F_LOCK when reading this value, or it may
 *     observe a torn read. control/bpfmap.py does.
 */
struct src_state {
	struct bpf_spin_lock lock; /* MUST be at offset 0 */
	/* 4 bytes of padding here, inserted by the compiler to align the u64s */

	/* --- token bucket --- */
	__u64 tokens;          /* whole packets currently available */
	__u64 last_refill_ns;  /* when we last added tokens */

	/* --- lifetime --- */
	__u64 first_seen_ns;
	__u64 last_seen_ns;    /* used by the userspace GC sweep */

	/* --- behavioural counters (cumulative; userspace differentiates) --- */
	__u64 packets;
	__u64 bytes;
	__u64 dropped;         /* packets from this source we dropped */
	__u64 syn;             /* TCP segments with SYN set */
	__u64 fin;
	__u64 rst;
	__u64 udp;
	__u64 icmp;
	__u64 tcp;

	/*
	 * Destination-port spread, approximated as a 64-bit Bloom-ish bitmap:
	 *     port_bitmap |= 1ULL << (dport % 64)
	 *
	 * eBPF has no set type, and tracking real unique ports would need a
	 * per-source nested map. This is the cheap approximation: popcount() of
	 * the bitmap separates "talks to one service" (1-3 bits) from "sweeping
	 * the port range" (30+ bits), which is all the scan detector needs.
	 *
	 * It collides -- ports 80 and 144 set the same bit -- so it UNDERCOUNTS
	 * and can never produce a false scan alarm from a low-port-count source.
	 * Erring toward under-detection is the right direction for a firewall.
	 * This limitation is stated in docs/ML_MODEL.md; say it out loud in the
	 * viva, it is the kind of thing examiners probe.
	 */
	__u64 port_bitmap;

	/* --- packet size envelope --- */
	__u32 min_len; /* initialised to 0xFFFFFFFF; userspace normalises */
	__u32 max_len;
}; /* 128 bytes */

/* ---------------------------------------------------------------------------
 * Runtime configuration (single-entry array map)
 * -------------------------------------------------------------------------*/

/* Bits for struct fw_config.features. Turning a stage off makes the XDP
 * program skip it entirely, which is how the benchmark isolates the cost of
 * each stage (see docs/EVALUATION.md). */
#define FEAT_ALLOWLIST   (1U << 0)
#define FEAT_BLOCKLIST   (1U << 1)
#define FEAT_PROTO_SANITY (1U << 2)
#define FEAT_RATELIMIT   (1U << 3)
#define FEAT_TRACK_STATE (1U << 4) /* maintain src_state at all */
#define FEAT_DROP_FRAGS  (1U << 5) /* drop non-first IP fragments */

#define FEAT_DEFAULT (FEAT_ALLOWLIST | FEAT_BLOCKLIST | FEAT_PROTO_SANITY | \
		      FEAT_RATELIMIT | FEAT_TRACK_STATE)

/*
 * The one and only knob the control plane turns.
 *
 * Note what is NOT here: there is no "aggressiveness multiplier" for the
 * kernel to apply. Userspace computes the final rate_pps and burst_pkts and
 * writes concrete numbers. `aggressiveness` is carried along purely so the
 * status display and the demo can show which tier is active. Keeping policy
 * arithmetic out of the kernel keeps the XDP program short and the verifier
 * happy.
 */
struct fw_config {
	__u64 rate_pps;       /* per-source token refill rate; 0 disables */
	__u64 burst_pkts;     /* bucket capacity (max burst tolerated) */
	__u32 features;       /* FEAT_* bitmask */
	__u32 aggressiveness; /* 0..3, informational only */
	__u32 default_action; /* XDP_PASS (2) or XDP_DROP (1) for unmatched */
	__u32 _pad;
}; /* 32 bytes */

/* ---------------------------------------------------------------------------
 * Global statistics (per-CPU array map)
 * -------------------------------------------------------------------------*/

/*
 * Indices into the `stats` map. It is a BPF_MAP_TYPE_PERCPU_ARRAY: each CPU
 * gets its own copy of every counter, so the packet path never contends on a
 * cache line. Userspace sums across CPUs when it reads.
 *
 * Keep this enum in sync with STAT_NAMES in control/schema.py.
 */
enum stat_index {
	STAT_RX_PACKETS = 0,   /* every packet the program saw */
	STAT_RX_BYTES,
	STAT_PASS_ALLOWLIST,   /* short-circuited by an allowlist hit */
	STAT_PASS_DEFAULT,     /* passed after running every check */
	STAT_PASS_NON_IPV4,    /* ARP, IPv6, etc: not our business, passed */
	STAT_DROP_BLOCKLIST,
	STAT_DROP_PROTO,       /* failed a protocol sanity check */
	STAT_DROP_RATELIMIT,   /* token bucket empty */
	STAT_DROP_MALFORMED,   /* truncated / nonsensical headers */
	STAT_DROP_FRAGMENT,
	STAT_STATE_FULL,       /* src_state map was full; see MAX_TRACKED */
	STAT_MAX
};

/* ---------------------------------------------------------------------------
 * Size assertions
 * -------------------------------------------------------------------------*/

/* Fire at compile time if padding ever changes a struct size out from under
 * the Python side. `(void)sizeof(char[1 - 2*!!(cond)])` is the classic
 * pre-C11 static assert: the array size goes negative when cond is true. */
#define ADAPTFW_ASSERT_SIZE(type, want) \
	((void)sizeof(char[1 - 2 * !!(sizeof(type) != (want))]))

static __always_inline void adaptfw_check_sizes(void)
{
	ADAPTFW_ASSERT_SIZE(struct lpm_key, 8);
	ADAPTFW_ASSERT_SIZE(struct allow_val, 16);
	ADAPTFW_ASSERT_SIZE(struct block_val, 24);
	ADAPTFW_ASSERT_SIZE(struct src_state, 128);
	ADAPTFW_ASSERT_SIZE(struct fw_config, 32);
}

/* Mirrored by control/schema.py -- update both together. */
#define SIZEOF_LPM_KEY    8
#define SIZEOF_ALLOW_VAL  16
#define SIZEOF_BLOCK_VAL  24
#define SIZEOF_SRC_STATE  128
#define SIZEOF_FW_CONFIG  32

/* Where the loader pins everything. */
#define ADAPTFW_PIN_DIR "/sys/fs/bpf/adaptfw"

#endif /* __ADAPTFW_COMMON_H */
