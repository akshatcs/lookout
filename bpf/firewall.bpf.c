// SPDX-License-Identifier: GPL-2.0
/*
 * firewall.bpf.c - the XDP data plane.
 *
 * Runs in the driver receive path, before the kernel allocates an sk_buff,
 * once per packet. Pipeline:
 *
 *   parse eth [+ vlan] -> ipv4
 *   source on the allowlist         -> PASS
 *   source on the blocklist         -> DROP (until the entry expires)
 *   parse tcp/udp/icmp
 *   impossible TCP flags            -> DROP
 *   port rule for proto/port        -> DROP if deny, continue if allow
 *   no port rule                    -> default policy (allow or deny)
 *   per-source token bucket empty   -> DROP
 *   otherwise                       -> PASS
 *
 * Two verifier rules shape this file. Every packet read needs a bounds check
 * the verifier can see, so each header is checked against data_end again
 * even when it looks redundant. And nothing that calls a helper (including
 * the clock) may run while the spin lock is held, so everything we need is
 * read into locals before taking it.
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

/* Declared here instead of including <linux/if_vlan.h> and <linux/icmp.h>:
 * those pull in glibc's sys/socket.h, which fails under -target bpf with
 * "gnu/stubs-32.h not found". */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct icmphdr_min {
	__u8  type;
	__u8  code;
	__be16 checksum;
};

#define NSEC_PER_SEC 1000000000ULL

/* Byte 13 of the TCP header. Reading the byte directly avoids depending on
 * the bitfield layout in struct tcphdr. */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* All maps are pinned under ADAPTFW_PIN_DIR by the loader, which is how the
 * Python tools find them and why they outlive the loader process. */

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct allow_val);
	__uint(max_entries, MAX_ALLOWLIST);
	__uint(map_flags, BPF_F_NO_PREALLOC);   /* required for LPM tries */
} allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct block_val);
	__uint(max_entries, MAX_BLOCKLIST);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

/* Per-CPU so the hit counter of a busy rule isn't one cache line that every
 * core fights over. Userspace writes the same action into every CPU's copy
 * and sums the hits. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct port_key);
	__type(value, struct port_val);
	__uint(max_entries, MAX_PORT_RULES);
} portrules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);                     /* saddr, network order */
	__type(value, struct src_state);
	__uint(max_entries, MAX_TRACKED);
} srcstate SEC(".maps");

/* Per-CPU so the hot counters never share a cache line between cores. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fw_config);
	__uint(max_entries, 1);
} config SEC(".maps");

/* No atomics needed: each CPU only touches its own copy. */
static __always_inline void stat_add(__u32 idx, __u64 n)
{
	__u64 *v;

	if (idx >= STAT_MAX)
		return;

	v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += n;
}

static __always_inline void stat_inc(__u32 idx)
{
	stat_add(idx, 1);
}

/* Flag combinations no real TCP stack sends. Stateless and cheap; it does
 * not stop a flood of valid SYNs, the rate limiter does that. */
static __always_inline int tcp_flags_sane(__u8 f)
{
	if (f == 0)                                     /* null scan */
		return 0;
	if ((f & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN))
		return 0;
	if ((f & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST))
		return 0;
	if ((f & (TCP_FIN | TCP_RST)) == (TCP_FIN | TCP_RST))
		return 0;
	if ((f & (TCP_FIN | TCP_PSH | TCP_URG)) == (TCP_FIN | TCP_PSH | TCP_URG))
		return 0;                               /* xmas scan */
	return 1;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	__u32 pkt_len = (__u32)(data_end - data);
	__u32 zero = 0;

	/* Read the clock once, up front: it is a helper call, so it cannot be
	 * called later inside the lock. */
	__u64 now = bpf_ktime_get_ns();

	struct fw_config *cfg;
	__u64 rate, burst;
	__u32 feat, policy;

	struct ethhdr *eth;
	struct iphdr *iph;
	void *nh;
	void *l4;
	__u16 h_proto;
	__u32 ihl_bytes;
	__u32 saddr;
	__u8 proto;
	__u16 dport = 0;        /* TCP/UDP destination port, for the scan bitmap */
	__u16 rule_port = 0;    /* what port rules match: dport, or the ICMP type */
	__u8 tcp_flags = 0;
	int is_frag;

	int verdict = XDP_PASS;
	__u32 reason = STAT_PASS_DEFAULT;
	struct src_state *st;

	stat_inc(STAT_RX_PACKETS);
	stat_add(STAT_RX_BYTES, pkt_len);

	/* Fail open if the config is missing. Can't happen once the loader has
	 * run; it is also the only path that skips the verdict counters. */
	cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg)
		return XDP_PASS;

	rate = cfg->rate_pps;
	burst = cfg->burst_pkts;
	feat = cfg->features;
	policy = cfg->default_policy;

	/* Ethernet. (eth + 1) is the first byte past the header. */
	eth = data;
	if ((void *)(eth + 1) > data_end) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	h_proto = eth->h_proto;
	nh = (void *)(eth + 1);

	/* One VLAN tag. A second tag shows up as non-IPv4 and is passed. */
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

	/* ARP, IPv6 etc. are passed untouched. Dropping ARP breaks the link. */
	if (h_proto != bpf_htons(ETH_P_IP)) {
		stat_inc(STAT_PASS_NON_IPV4);
		return XDP_PASS;
	}

	iph = nh;
	if ((void *)(iph + 1) > data_end) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	if (iph->version != 4) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	/* ihl can't exceed 15, but the verifier wants an explicit upper bound
	 * before we use it for pointer arithmetic. */
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

	if (bpf_ntohs(iph->tot_len) < ihl_bytes) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	if (iph->ttl == 0) {
		stat_inc(STAT_DROP_MALFORMED);
		return XDP_DROP;
	}

	saddr = iph->saddr;     /* left in network byte order */
	proto = iph->protocol;

	/* Source lists come first, straight after the IP header: they only
	 * need the source address. The allowlist is checked before anything
	 * else so an allowlisted host can't be blocked by anything, including
	 * a bad decision in the controller. No per-source state is kept for
	 * it. */
	if (feat & FEAT_ALLOWLIST) {
		struct lpm_key lk = {
			.prefixlen = 32,
			.addr = saddr,
		};
		struct allow_val *av = bpf_map_lookup_elem(&allowlist, &lk);

		if (av) {
			__sync_fetch_and_add(&av->hits, 1);   /* shared between CPUs */
			stat_inc(STAT_PASS_ALLOWLIST);
			return XDP_PASS;
		}
	}

	/* The expiry check lives here so blocks lift on time without any
	 * userspace help. A blocked source is dropped right here, before its
	 * L4 header is even parsed: it has been dealt with, so it costs one
	 * trie lookup and nothing else. */
	if (feat & FEAT_BLOCKLIST) {
		struct lpm_key lk = {
			.prefixlen = 32,
			.addr = saddr,
		};
		struct block_val *bv = bpf_map_lookup_elem(&blocklist, &lk);

		if (bv && (bv->expires_ns == 0 || bv->expires_ns > now)) {
			__sync_fetch_and_add(&bv->hits, 1);
			stat_inc(STAT_DROP_BLOCKLIST);
			return XDP_DROP;
		}
	}

	/* A non-first fragment has no L4 header, so there is nothing to parse
	 * and no port to match. */
	is_frag = bpf_ntohs(iph->frag_off) & 0x1FFF;

	if (is_frag) {
		/* nothing to parse */
	} else if (proto == IPPROTO_TCP) {
		struct tcphdr *th = l4;

		if ((void *)(th + 1) > data_end) {
			stat_inc(STAT_DROP_MALFORMED);
			return XDP_DROP;
		}
		dport = bpf_ntohs(th->dest);
		rule_port = dport;
		tcp_flags = *((__u8 *)th + 13);

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
		rule_port = dport;

		/* The length includes the 8-byte header, so < 8 is bogus. */
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
		rule_port = ih->type;   /* e.g. 8 = echo request */
	}

	/* Fragments can't match a port rule, so under a default-deny policy
	 * they are dropped like any other unmatched packet. With the default
	 * allow policy they pass, because dropping them breaks large UDP
	 * (DNSSEC, some VPNs); FEAT_DROP_FRAGS drops them anyway. */
	if (is_frag) {
		if (feat & FEAT_DROP_FRAGS) {
			verdict = XDP_DROP;
			reason = STAT_DROP_FRAGMENT;
		} else if ((feat & FEAT_PORT_RULES) && policy == ACTION_DENY) {
			verdict = XDP_DROP;
			reason = STAT_DROP_DEFAULT;
		}
		goto update_state;
	}

	if ((feat & FEAT_PROTO_SANITY) && proto == IPPROTO_TCP) {
		if (!tcp_flags_sane(tcp_flags)) {
			verdict = XDP_DROP;
			reason = STAT_DROP_PROTO;
			goto update_state;
		}
	}

	/* Port rules, then the default policy for anything without a rule. */
	if (feat & FEAT_PORT_RULES) {
		struct port_key pk = {
			.proto = proto,
			._pad = 0,
			.port = rule_port,
		};
		struct port_val *pv = bpf_map_lookup_elem(&portrules, &pk);

		if (pv) {
			pv->hits += 1;              /* this CPU's own copy */
			if (pv->action == ACTION_DENY) {
				verdict = XDP_DROP;
				reason = STAT_DROP_PORT_RULE;
				goto update_state;
			}
			reason = STAT_PASS_RULE;
		} else if (policy == ACTION_DENY) {
			verdict = XDP_DROP;
			reason = STAT_DROP_DEFAULT;
			goto update_state;
		}
	}

update_state:
	if (!(feat & FEAT_TRACK_STATE)) {
		stat_inc(reason);
		return verdict;
	}

	st = bpf_map_lookup_elem(&srcstate, &saddr);
	if (!st) {
		/* New source. The kernel initialises the real lock itself; the
		 * zeroed lock bytes on the stack are ignored. */
		struct src_state init = {};

		init.last_seen_ns = now;
		init.last_refill_ns = now;
		init.tokens = burst;            /* start with a full bucket */

		/* NOEXIST: if another CPU inserted it first, this fails and the
		 * lookup below finds their entry. If the map is full we can't
		 * track or rate limit this source; keep the verdict we have. */
		if (bpf_map_update_elem(&srcstate, &saddr, &init, BPF_NOEXIST)) {
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

	/* No helper calls, map lookups or returns until the unlock. */
	bpf_spin_lock(&st->lock);

	st->packets += 1;
	st->bytes += pkt_len;
	st->last_seen_ns = now;

	if (proto == IPPROTO_TCP) {
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

	/*
	 * Token bucket, only for packets that would otherwise pass. Refill is
	 * continuous: elapsed * rate / 1e9 tokens, with elapsed capped at 1 s so
	 * an idle source can't bank a huge allowance (and the multiply can't
	 * overflow).
	 *
	 * last_refill_ns only moves when at least one token was added, and only
	 * by the time those whole tokens took to earn. If it jumped to `now`,
	 * the fraction of a token earned since would be thrown away on every
	 * refill, and a source sending just above the rate would be held well
	 * below it. If it moved on every packet, add would always be 0.
	 */
	if (verdict == XDP_PASS && (feat & FEAT_RATELIMIT) && rate > 0) {
		__u64 elapsed = 0;
		__u64 add;

		/* `now` was read before the lock. Another CPU handling the same
		 * source may have taken the lock in between with a later clock
		 * reading, so now can be behind last_refill_ns. Unsigned
		 * subtraction would wrap that to a huge value and grant a full
		 * second of tokens; treat it as no time passed instead. */
		if (now > st->last_refill_ns)
			elapsed = now - st->last_refill_ns;

		if (elapsed >= NSEC_PER_SEC) {
			/* idle for a second or more: refill up to one second's worth
			 * and start counting from now */
			add = rate;
			st->last_refill_ns = now;
		} else {
			add = (elapsed * rate) / NSEC_PER_SEC;
			if (add > 0)
				st->last_refill_ns += (add * NSEC_PER_SEC) / rate;
		}
		st->tokens += add;
		if (st->tokens > burst)
			st->tokens = burst;

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

	stat_inc(reason);
	return verdict;
}

/* Several helpers we use are GPL-only. */
char LICENSE[] SEC("license") = "GPL";
