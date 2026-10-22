/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h - map layouts shared by the XDP program, the loader and the
 * Python control plane.
 *
 * firewall.bpf.c and loader.c include this file. control/firewall.py mirrors
 * it with struct format strings and checks the sizes when it is imported, so
 * if you change a struct here, change it there too and run `make reload`
 * (libbpf will not reuse a pinned map whose value size has changed).
 */

#ifndef ADAPTFW_COMMON_H
#define ADAPTFW_COMMON_H

#define ADAPTFW_PIN_DIR "/sys/fs/bpf/adaptfw"

/* Map capacities. The LPM tries only use memory for entries that exist.
 * srcstate is preallocated (32768 * 104 bytes, about 3.3 MiB) so the packet
 * path never allocates. The controller adds at most 32 blocks/s for 60 s =
 * 1920 automatic blocks alive at once, well under MAX_BLOCKLIST. */
#define MAX_ALLOWLIST  1024
#define MAX_BLOCKLIST  4096
#define MAX_PORT_RULES 1024
#define MAX_TRACKED    32768

/* Verdict of a port rule, and the default policy for packets that match no
 * port rule. */
enum fw_action {
	ACTION_ALLOW = 0,
	ACTION_DENY  = 1,
};

/* Key for both LPM tries. The trie matches bits from the most significant
 * end, so addr stays in network byte order exactly as it is in the IP
 * header. Lookups always use prefixlen 32. */
struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct allow_val {
	__u64 hits;
	__u32 flags;    /* unused, always 0 */
	__u32 _pad;
};

/* Who added a blocklist entry. Only userspace looks at this. */
enum block_reason {
	BLOCK_MANUAL = 0,   /* fwctl block add */
	BLOCK_AUTO   = 1,   /* the controller */
};

/* expires_ns is an absolute bpf_ktime_get_ns() (CLOCK_MONOTONIC) deadline,
 * checked by the XDP program on every packet, so a block lifts on time even
 * if the controller is not running. 0 means permanent. */
struct block_val {
	__u64 expires_ns;
	__u64 hits;
	__u32 reason;
	__u32 _pad;
};

/* Port rules match the IP protocol and the destination port (TCP, UDP) or
 * the ICMP type. Other protocols are looked up with port 0. port is in host
 * byte order. _pad must be zero: it is part of the hash key. */
struct port_key {
	__u8  proto;
	__u8  _pad;
	__u16 port;
};

struct port_val {        /* one copy per CPU, see portrules */
	__u64 hits;
	__u32 action;           /* ACTION_ALLOW or ACTION_DENY */
	__u32 _pad;
};

/*
 * Per-source state: the token bucket plus the counters the controller reads.
 * Keeping both in one value means one lookup per packet, and the counters are
 * updated under the same lock as the bucket.
 *
 * The lock is needed because the bucket update is a read-modify-write of two
 * fields and several CPUs can handle packets from the same source at once.
 * The kernel only allows bpf_spin_lock in HASH and ARRAY values, not
 * LRU_HASH, so this map cannot evict on its own; the controller deletes
 * entries that have been idle for 60 s instead.
 */
struct src_state {
	struct bpf_spin_lock lock;  /* must be first; 4 bytes of padding follow */

	__u64 tokens;
	__u64 last_refill_ns;
	__u64 last_seen_ns;

	/* cumulative; the controller works with per-second differences */
	__u64 packets;
	__u64 bytes;
	__u64 dropped;
	__u64 syn;
	__u64 fin;
	__u64 rst;
	__u64 udp;
	__u64 icmp;

	/* bit (dport % 64) set for every destination port seen. Ports 80 and
	 * 144 share a bit, so the popcount under-counts, which is the safe
	 * direction for a scan detector. */
	__u64 port_bitmap;
};

/* Stages of the pipeline. Clearing a bit makes the program skip that stage. */
#define FEAT_ALLOWLIST    (1U << 0)
#define FEAT_BLOCKLIST    (1U << 1)
#define FEAT_PROTO_SANITY (1U << 2)
#define FEAT_RATELIMIT    (1U << 3)
#define FEAT_TRACK_STATE  (1U << 4)
#define FEAT_DROP_FRAGS   (1U << 5)   /* off by default */
#define FEAT_PORT_RULES   (1U << 6)

#define FEAT_DEFAULT (FEAT_ALLOWLIST | FEAT_BLOCKLIST | FEAT_PROTO_SANITY | \
		      FEAT_RATELIMIT | FEAT_TRACK_STATE | FEAT_PORT_RULES)

/* Runtime settings. The controller writes rate_pps and burst_pkts to adapt;
 * tier logic stays in Python. aggressiveness is only for display. */
struct fw_config {
	__u64 rate_pps;         /* per-source refill rate, 0 = no rate limit */
	__u64 burst_pkts;       /* bucket size */
	__u32 features;         /* FEAT_* */
	__u32 aggressiveness;   /* 0..3 */
	__u32 default_policy;   /* ACTION_ALLOW or ACTION_DENY, for unmatched ports */
	__u32 _pad;
};

/* Indices into the per-CPU stats array. Keep in sync with STAT_NAMES in
 * control/firewall.py. Every packet bumps RX_* and exactly one PASS_* or
 * DROP_* counter, so passes + drops == rx_packets. */
enum stat_index {
	STAT_RX_PACKETS = 0,
	STAT_RX_BYTES,
	STAT_PASS_ALLOWLIST,    /* trusted source */
	STAT_PASS_RULE,         /* an allow port rule matched */
	STAT_PASS_DEFAULT,      /* no rule matched, default policy is allow */
	STAT_PASS_NON_IPV4,     /* ARP, IPv6, ... */
	STAT_DROP_BLOCKLIST,
	STAT_DROP_PORT_RULE,    /* a deny port rule matched */
	STAT_DROP_DEFAULT,      /* no rule matched, default policy is deny */
	STAT_DROP_PROTO,        /* impossible TCP flags */
	STAT_DROP_RATELIMIT,
	STAT_DROP_MALFORMED,
	STAT_DROP_FRAGMENT,
	STAT_STATE_FULL,        /* srcstate had no room; not a verdict */
	STAT_MAX
};

_Static_assert(sizeof(struct lpm_key) == 8, "lpm_key size");
_Static_assert(sizeof(struct allow_val) == 16, "allow_val size");
_Static_assert(sizeof(struct block_val) == 24, "block_val size");
_Static_assert(sizeof(struct port_key) == 4, "port_key size");
_Static_assert(sizeof(struct port_val) == 16, "port_val size");
_Static_assert(sizeof(struct src_state) == 104, "src_state size");
_Static_assert(sizeof(struct fw_config) == 32, "fw_config size");

#endif
