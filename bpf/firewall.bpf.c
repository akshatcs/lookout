// SPDX-License-Identifier: GPL-2.0
/*
 * firewall.bpf.c -- XDP data plane for the Adaptive XDP/eBPF Firewall.
 *
 * ============================================================================
 * WHAT THIS PROGRAM IS
 * ============================================================================
 * This is an eBPF program attached at the XDP hook: the earliest point in the
 * Linux receive path, inside the NIC driver, BEFORE the kernel allocates an
 * sk_buff for the packet. That is the whole performance argument of the
 * project. A packet dropped here costs a few hundred cycles. The same packet
 * dropped by nftables has already had an sk_buff allocated and been walked
 * through several layers of the networking stack first.
 *
 * We get exactly one function, one shot at each packet, and we return one of:
 *   XDP_PASS     -- hand it to the normal networking stack
 *   XDP_DROP     -- free it immediately, the stack never sees it
 *   XDP_TX/REDIRECT -- bounce it back out (we don't use these)
 *
 * ============================================================================
 * THE THREE RULES THE VERIFIER ENFORCES (and where they show up below)
 * ============================================================================
 * 1. EVERY packet byte we read must be preceded by a bounds check against
 *    ctx->data_end that the verifier can follow. "I already checked 20 bytes
 *    ago" is not good enough if control flow got complicated in between. This
 *    is why the parsing below looks repetitive -- each header re-checks.
 *
 * 2. No unbounded loops. There are no loops in this program at all.
 *
 * 3. Inside a bpf_spin_lock critical section: no helper calls whatsoever
 *    (not even bpf_ktime_get_ns), no map lookups, and no returning. Look at
 *    how `now`, `rate`, `burst` are all read into locals BEFORE the lock is
 *    taken. That is the explicit way of doing things correctly.
 *
 * ============================================================================
 * PACKET PIPELINE
 * ============================================================================
 *   parse ethernet (+ optional VLAN tag)
 *     -> not IPv4?  PASS (we are an IPv4 firewall; ARP must survive)
 *   parse IPv4 header (variable length, so IHL is validated carefully)
 *     -> non-first fragment? count, and drop only if configured to
 *   parse TCP / UDP / ICMP to extract dest port and TCP flags
 *   allowlist lookup  -> HIT: pass immediately, cheapest possible path
 *   blocklist lookup  -> HIT and not expired: drop
 *   protocol sanity   -> impossible flag combinations: drop
 *   per-source state  -> update counters + run the token bucket
 *   return verdict
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

/*
 * NOTE ON HEADERS -- read this before you add an #include.
 *
 * <linux/if_vlan.h> and <linux/icmp.h> both pull in <linux/if.h>, which pulls
 * in glibc's <sys/socket.h>, which under `clang -target bpf` tries to include
 * the 32-bit stubs header and fails with:
 *
 *     fatal error: 'gnu/stubs-32.h' file not found
 *
 * This will hit the first time we try to include almost any other kernel
 * networking header. The options are (a) install gcc-multilib, (b) generate
 * vmlinux.h with bpftool and use CO-RE, or (c) declare the two tiny structs
 * we actually need ourselves. We take (c): it keeps the build dependency-free
 * and these two structs are four lines of wire format that have not changed
 * since the 1990s.
 */

/* 802.1Q VLAN tag, as it sits between the MAC addresses and the ethertype. */
struct vlan_hdr {
	__be16 h_vlan_TCI;                 /* priority + VLAN id */
	__be16 h_vlan_encapsulated_proto;  /* the real ethertype */
};

/* First 4 bytes of an ICMP header. We only ever bounds-check it, but having
 * the struct keeps the parsing code uniform with TCP and UDP. */
struct icmphdr_min {
	__u8  type;
	__u8  code;
	__be16 checksum;
};

#define NSEC_PER_SEC 1000000000ULL

/* TCP flag bits. We read byte 13 of the TCP header directly rather than using
 * the bitfields in struct tcphdr, because the bitfield layout in <linux/tcp.h>
 * depends on __LITTLE_ENDIAN_BITFIELD being correctly defined for the target,
 * and a raw byte read is both portable and faster.
 *
 * TCP header byte 13 layout (RFC 793 + RFC 3168):
 *   bit 0 FIN, 1 SYN, 2 RST, 3 PSH, 4 ACK, 5 URG, 6 ECE, 7 CWR
 */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* ===========================================================================
 * MAPS
 * ===========================================================================
 * Every map below is pinned to /sys/fs/bpf/adaptfw/<name> by src/loader.c.
 * Pinning is what lets a completely separate process (the Python control
 * plane) reopen the same map by path. It is also what keeps the maps -- and
 * therefore the firewall policy -- alive after the loader process exits.
 */

/* Sources that are never filtered, no matter what the model says.
 * LPM_TRIE so one entry can cover a whole subnet (10.0.0.0/8).
 * LPM tries REQUIRE BPF_F_NO_PREALLOC; the kernel rejects them otherwise. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct allow_val);
	__uint(max_entries, MAX_ALLOWLIST);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist SEC(".maps");

/* Sources currently being dropped. Written by the control plane (model
 * verdicts + manual `fwctl block add`), enforced here. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct block_val);
	__uint(max_entries, MAX_BLOCKLIST);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

/* Per-source token bucket + behaviour counters. See the long comment on
 * struct src_state in common.h for why this is a plain HASH and not an LRU. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);          /* source IPv4, network byte order */
	__type(value, struct src_state);
	__uint(max_entries, MAX_TRACKED);
} srcstate SEC(".maps");

/* Global counters. PERCPU so incrementing never bounces a cache line between
 * cores -- at multi-Mpps that difference is measurable. Userspace sums. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* Single-entry array holding the live policy. The control plane writes here
 * once per second; we read it once per packet. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fw_config);
	__uint(max_entries, 1);
} config SEC(".maps");

/* ===========================================================================
 * HELPERS
 * ===========================================================================*/

/* Add to a per-CPU counter. No atomics needed: by definition this CPU is the
 * only writer of its own copy, and XDP runs with preemption disabled. */
static __always_inline void stat_add(__u32 idx, __u64 n)
{
	__u64 *v;

	if (idx >= STAT_MAX)
		return; /* keeps the verifier happy about the array bound */

	v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += n;
}

static __always_inline void stat_inc(__u32 idx)
{
	stat_add(idx, 1);
}

/*
 * Reject TCP flag combinations that cannot occur in a legitimate conversation.
 * Every one of these is produced by common scanning and flood tools and by
 * nothing else.
 *
 * Returns 1 if sane, 0 if the packet should be dropped.
 *
 * NOTE ON SCOPE: this is deliberately *stateless*. It is not a connection
 * tracker and it will not catch a flood of perfectly well-formed SYNs -- that
 * is the rate limiter's job, and beyond that the model's. All this does is
 * discard the traffic that is provably garbage, for almost zero cost.
 */
static __always_inline int tcp_flags_sane(__u8 f)
{
	/* NULL scan: no flags at all. */
	if (f == 0)
		return 0;
	/* SYN+FIN: open and close simultaneously. Nonsense. */
	if ((f & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN))
		return 0;
	/* SYN+RST: request and refuse simultaneously. */
	if ((f & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
		return 0;
	/* FIN+RST: graceful and abortive close at once. */
	if ((f & (TCP_FIN | TCP_RST)) == (TCP_FIN | TCP_RST))
		return 0;
	/* Xmas scan: FIN+PSH+URG lit up "like a christmas tree". */
	if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG))
		return 0;
	return 1;
}

/* ===========================================================================
 * THE PROGRAM
 * ===========================================================================*/

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
	/* ctx->data and ctx->data_end are __u32 in the context struct but are
	 * really pointers. This double cast is the standard XDP idiom; the
	 * verifier recognises it and starts tracking them as packet pointers. */
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	__u32 pkt_len = (__u32)(data_end - data);
	__u32 zero = 0;

	/* Read the clock ONCE, up front. bpf_ktime_get_ns() is a helper call,
	 * so it is illegal inside the spin lock later, and calling it twice
	 * would be wasted cycles on the hot path. */
	__u64 now = bpf_ktime_get_ns();

	struct fw_config *cfg;
	__u64 rate, burst;
	__u32 feat;

	struct ethhdr *eth;
	struct iphdr *iph;
	void *nh;          /* "next header" cursor */
	void *l4;
	__u16 h_proto;
	__u32 ihl_bytes;
	__u32 saddr;
	__u8 proto;
	__u16 dport = 0;
	__u8 tcp_flags = 0;

	int verdict = XDP_PASS;
	__u32 reason = STAT_PASS_DEFAULT;
	struct src_state *st;

	stat_inc(STAT_RX_PACKETS);
	stat_add(STAT_RX_BYTES, pkt_len);

	/* ---- configuration -------------------------------------------------
	 * Fail OPEN. If the config map is somehow unreadable we pass traffic
	 * rather than black-holing the machine. For a firewall protecting a
	 * service, availability of the control path failing should not take the
	 * service down with it. */
	cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg)
		return XDP_PASS;
	/* NOTE: this is the ONLY return path that increments no verdict
	 * counter, so it is the one case where
	 *     passes_total + drops_total != rx_packets
	 * in userspace. It requires the single-entry config array to be
	 * unreadable, which cannot happen once the loader has run. Every other
	 * path below increments exactly one STAT_PASS_* or STAT_DROP_*. */

	/* Copy out everything we need before we ever take the spin lock. */
	rate = cfg->rate_pps;
	burst = cfg->burst_pkts;
	feat = cfg->features;

	/* ---- Ethernet ------------------------------------------------------*/
	eth = data;
	/* (eth + 1) is "one struct ethhdr past the start", i.e. the first byte
	 * we are NOT allowed to touch. If that is past data_end, the frame is
	 * truncated. This same pattern repeats for every header. */
	if ((void *)(eth + 1) > data_end) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	h_proto = eth->h_proto; /* network byte order */
	nh = (void *)(eth + 1);

	/* One level of VLAN tagging. Nested QinQ is out of scope -- a second
	 * tag falls through to the "not IPv4" branch and is passed. */
	if (h_proto == bpf_htons(ETH_P_8021Q) ||
	    h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = nh;

		if ((void *)(vh + 1) > data_end) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
		h_proto = vh->h_vlan_encapsulated_proto;
		nh = (void *)(vh + 1);
	}

	/* Anything that is not IPv4 -- ARP, IPv6, LLDP -- is passed untouched.
	 * Dropping ARP here would break the network in a way that is confusing
	 * to debug, so this early exit matters. */
	if (h_proto != bpf_htons(ETH_P_IP)) {
		stat_inc(STAT_PASS_NON_IPV4);
		return XDP_PASS;
	}

	/* ---- IPv4 ----------------------------------------------------------*/
	iph = nh;
	if ((void *)(iph + 1) > data_end) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	if (iph->version != 4) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	/* IHL is a 4-bit field counting 32-bit words, so the header is 20..60
	 * bytes. We clamp explicitly even though the field cannot exceed 15:
	 * the verifier needs to see a concrete upper bound before it will let
	 * us do pointer arithmetic with a value derived from packet data. */
	ihl_bytes = iph->ihl * 4;
	if (ihl_bytes < sizeof(struct iphdr) || ihl_bytes > 60) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	l4 = (void *)iph + ihl_bytes;
	if (l4 > data_end) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	/* Total length must at least cover the header it claims to have. */
	if (bpf_ntohs(iph->tot_len) < ihl_bytes) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	/* A TTL of zero should have been discarded by the previous hop. */
	if (iph->ttl == 0) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	saddr = iph->saddr; /* keep in network byte order throughout */
	proto = iph->protocol;

	/* Non-first fragments carry no L4 header, so we cannot inspect ports or
	 * flags on them. Fragment-based evasion is a real technique, but
	 * dropping all fragments breaks legitimate large UDP (DNSSEC, some
	 * VPNs), so this is opt-in via FEAT_DROP_FRAGS. */
	if (bpf_ntohs(iph->frag_off) & 0x1FFF) {
		/* Count the DROP counter only when we actually drop. Userspace
		 * sums every drop_* counter into a drop ratio, and that ratio
		 * feeds the aggressiveness controller -- so counting a passed
		 * packet here would inflate the ratio and could tighten the
		 * global rate limit in response to traffic we let through. */
		if (feat & FEAT_DROP_FRAGS) {
			stat_inc(STAT_DROP_FRAGMENT);
			return XDP_DROP;
		}
		stat_inc(STAT_PASS_DEFAULT);
		return XDP_PASS;
	}

	/* ---- L4: extract dest port and TCP flags ---------------------------*/
	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = l4;

		if ((void *)(th + 1) > data_end) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
		dport = bpf_ntohs(th->dest);
		/* Byte 13 holds the flag bits; see the #defines at the top. */
		tcp_flags = *((__u8 *)th + 13);

		/* Data offset is in 32-bit words and can never be below 5
		 * (a 20-byte header with no options). */
		if (th->doff < 5) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uh = l4;

		if ((void *)(uh + 1) > data_end) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
		dport = bpf_ntohs(uh->dest);

		/* The UDP length field includes its own 8-byte header, so any
		 * value below 8 is impossible. Classic malformed-packet DoS. */
		if (bpf_ntohs(uh->len) < sizeof(struct udphdr)) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
	} else if (proto == IPPROTO_ICMP) {
		struct icmphdr_min *ih = l4;

		if ((void *)(ih + 1) > data_end) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
		dport = 0; /* ICMP has no ports */
	}

	/* ---- Stage 1: allowlist -------------------------------------------
	 * Checked first and short-circuits everything. Two reasons:
	 *   (a) correctness -- an allowlisted host must be unblockable, even by
	 *       a misbehaving model. This is the outermost safety rail.
	 *   (b) performance -- known-good traffic takes the shortest path
	 *       through the program, one map lookup and out.
	 *
	 * Note we do NOT maintain src_state for allowlisted sources. They are
	 * exempt from the rate limiter and invisible to the model by design. */
	if (feat & FEAT_ALLOWLIST) {
		struct lpm_key lk = {
			.prefixlen = 32, /* lookups always specify a full address */
			.addr = saddr,
		};
		struct allow_val *av = bpf_map_lookup_elem(&allowlist, &lk);

		if (av) {
			/* Shared across CPUs, so this one needs to be atomic. */
			__sync_fetch_and_add(&av->hits, 1);
			stat_inc(STAT_PASS_ALLOWLIST);
			return XDP_PASS;
		}
	}

	/* ---- Stage 2: blocklist -------------------------------------------
	 * The expiry check happens HERE, in the kernel, against the kernel's
	 * own clock. That is what makes a block time-limited even if the
	 * control plane dies: nothing in userspace has to run for the entry to
	 * stop being enforced. Userspace only reclaims the map slot later. */
	if (feat & FEAT_BLOCKLIST) {
		struct lpm_key lk = {
			.prefixlen = 32,
			.addr = saddr,
		};
		struct block_val *bv = bpf_map_lookup_elem(&blocklist, &lk);

		if (bv && (bv->expires_ns == 0 || bv->expires_ns > now)) {
			__sync_fetch_and_add(&bv->hits, 1);
			verdict = XDP_DROP;
			reason = STAT_DROP_BLOCKLIST;
			goto update_state;
		}
	}

	/* ---- Stage 3: protocol sanity -------------------------------------*/
	if ((feat & FEAT_PROTO_SANITY) && proto == IPPROTO_TCP) {
		if (!tcp_flags_sane(tcp_flags)) {
			verdict = XDP_DROP;
			reason = STAT_DROP_PROTO;
			goto update_state;
		}
	}

update_state:
	/* ---- Stage 4: per-source state + token bucket ----------------------
	 * We arrive here on BOTH the pass and drop paths. Updating counters for
	 * traffic we are already dropping is deliberate: it is what lets the
	 * live display show an attacker still hammering the box after being
	 * blocked, which is one of the better moments in the demo.
	 */
	if (!(feat & FEAT_TRACK_STATE)) {
		stat_inc(reason);
		return verdict;
	}

	st = bpf_map_lookup_elem(&srcstate, &saddr);
	if (!st) {
		/* First packet from this source: create its state.
		 *
		 * `init` lives on the BPF stack. It contains a bpf_spin_lock
		 * field, but the verifier's restrictions on spin locks apply to
		 * map-value pointers, not stack memory, so zero-initialising it
		 * here is fine. The kernel ignores the lock bytes we hand it
		 * and initialises the real lock itself. */
		struct src_state init = {};

		init.first_seen_ns = now;
		init.last_seen_ns = now;
		init.last_refill_ns = now;
		init.tokens = burst;      /* start with a full bucket */
		init.min_len = 0xFFFFFFFF; /* so the first min() works */

		/* BPF_NOEXIST: if another CPU raced us and inserted first, this
		 * fails harmlessly and the re-lookup below finds their entry. */
		if (bpf_map_update_elem(&srcstate, &saddr, &init, BPF_NOEXIST)) {
			/* Map is full. Count it and fall through with whatever
			 * verdict we already had -- we simply cannot rate limit
			 * a source we have no room to track. */
			stat_inc(STAT_STATE_FULL);
			stat_inc(reason);
			return verdict;
		}

		st = bpf_map_lookup_elem(&srcstate, &saddr);
		if (!st) {
			stat_inc(STAT_STATE_FULL);
			stat_inc(reason);
			return verdict;
		}
	}

	/* ===== CRITICAL SECTION =============================================
	 * From bpf_spin_lock() to bpf_spin_unlock() there are NO helper calls,
	 * NO map lookups, and NO returns. Only arithmetic on `st` and on locals
	 * we read earlier. The verifier rejects the program outright otherwise.
	 * ===================================================================*/
	bpf_spin_lock(&st->lock);

	st->packets += 1;
	st->bytes += pkt_len;
	st->last_seen_ns = now;

	if (pkt_len < st->min_len)
		st->min_len = pkt_len;
	if (pkt_len > st->max_len)
		st->max_len = pkt_len;

	if (proto == IPPROTO_TCP) {
		st->tcp += 1;
		if (tcp_flags & TCP_SYN)
			st->syn += 1;
		if (tcp_flags & TCP_FIN)
			st->fin += 1;
		if (tcp_flags & TCP_RST)
			st->rst += 1;
	} else if (proto == IPPROTO_UDP) {
		st->udp += 1;
	} else if (proto == IPPROTO_ICMP) {
		st->icmp += 1;
	}

	if (dport)
		st->port_bitmap |= (1ULL << (dport & 63));

	/* Token bucket. Only applied to traffic that would otherwise pass --
	 * there is no point spending tokens on a packet already being dropped.
	 *
	 * The bucket refills continuously rather than in discrete ticks:
	 *     new_tokens = elapsed_ns * rate_pps / 1e9
	 * `elapsed` is clamped to one second so that a source which has been
	 * idle for an hour does not arrive with a billion tokens, and so the
	 * multiplication cannot overflow (1e9 * 1e6 = 1e15, comfortably inside
	 * a u64).
	 *
	 * last_refill_ns is only advanced when we actually add a token. If we
	 * advanced it every packet, a source sending faster than the refill
	 * rate would see `add` round down to zero every time and never refill
	 * at all -- a subtle bug that turns the limiter into a hard cap at
	 * `burst` packets total. */
	if (verdict == XDP_PASS && (feat & FEAT_RATELIMIT) && rate > 0) {
		__u64 elapsed = now - st->last_refill_ns;
		__u64 add;

		if (elapsed > NSEC_PER_SEC)
			elapsed = NSEC_PER_SEC;

		add = (elapsed * rate) / NSEC_PER_SEC;
		if (add > 0) {
			st->tokens += add;
			if (st->tokens > burst)
				st->tokens = burst;
			st->last_refill_ns = now;
		}

		if (st->tokens > 0) {
			st->tokens -= 1;
		} else {
			verdict = XDP_DROP;
			reason = STAT_DROP_RATELIMIT;
		}
	}

	if (verdict == XDP_DROP)
		st->dropped += 1;

	bpf_spin_unlock(&st->lock);
	/* ===== END CRITICAL SECTION ========================================*/

	stat_inc(reason);
	return verdict;
}

/* The license string is mandatory. Many BPF helpers are marked GPL-only and
 * the verifier refuses to link them into a non-GPL program. */
char LICENSE[] SEC("license") = "GPL";
