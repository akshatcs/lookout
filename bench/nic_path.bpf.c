// SPDX-License-Identifier: GPL-2.0
/*
 * nic_path.bpf.c - two tiny XDP programs used only by the benchmark.
 *
 * Built twice by run_experiment.sh:
 *
 *   -DTARGET_IFINDEX=<veth-cl>  "redirect": loaded on gen1 in the client
 *       namespace. It forwards every frame hping3 sends into veth-cl as a
 *       raw XDP frame, so veth-fw receives packets the way a network card
 *       does: as a buffer with no sk_buff yet. Without this, veth hands the
 *       sender's sk_buff across, and XDP has to copy it into a buffer of its
 *       own first (veth_convert_skb_to_xdp_buff in drivers/net/veth.c),
 *       which no real card makes it do.
 *
 *       Adding -DSPREAD=<n> also rewrites each packet's source address to
 *       a random one of 198.18.0.1 ... 198.18.0.0+n (the range RFC 2544
 *       reserves for benchmarks), fixing the IP, TCP and UDP checksums, so
 *       one hping3 at full speed looks like n different senders.
 *
 *   without it                  "empty": drops every IPv4 packet and does
 *       nothing else (ARP passes, so the testbed keeps working). Loaded on
 *       veth-fw it measures the cost of delivering a frame and running any
 *       XDP program at all; whatever a firewall costs on top of that is the
 *       firewall's own work.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifdef TARGET_IFINDEX
#ifdef SPREAD
/* A checksum after one 32-bit field changes from `from` to `to` (RFC 1624).
 * One's-complement sums don't depend on byte order, so the raw words do. */
static __always_inline __u16 csum_fix(__u16 check, __u32 from, __u32 to)
{
	__u32 sum = (__u16)~check;

	sum += (__u16)~(from >> 16) + (__u16)~(from & 0xffff);
	sum += (to >> 16) + (to & 0xffff);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}
#endif

SEC("xdp")
int xdp_redirect_to_nic(struct xdp_md *ctx)
{
#ifdef SPREAD
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP) &&
	    ip->ihl == 5) {
		__u32 from = ip->saddr;
		__u32 to = bpf_htonl(0xc6120000 + 1 + bpf_get_prandom_u32() % SPREAD);
		struct tcphdr *tcp = (void *)(ip + 1);
		struct udphdr *udp = (void *)(ip + 1);

		ip->saddr = to;
		ip->check = csum_fix(ip->check, from, to);
		/* TCP and UDP checksums cover the source address too */
		if (ip->protocol == IPPROTO_TCP && (void *)(tcp + 1) <= data_end)
			tcp->check = csum_fix(tcp->check, from, to);
		else if (ip->protocol == IPPROTO_UDP && (void *)(udp + 1) <= data_end &&
			 udp->check)
			udp->check = csum_fix(udp->check, from, to) ?: 0xffff;
	}
#endif
	return bpf_redirect(TARGET_IFINDEX, 0);
}
#else
SEC("xdp")
int xdp_empty_drop(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	return XDP_DROP;
}
#endif

char LICENSE[] SEC("license") = "GPL";
