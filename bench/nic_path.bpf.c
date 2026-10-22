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
 *   without it                  "empty": drops every IPv4 packet and does
 *       nothing else (ARP passes, so the testbed keeps working). Loaded on
 *       veth-fw it measures the cost of delivering a frame and running any
 *       XDP program at all; whatever a firewall costs on top of that is the
 *       firewall's own work.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifdef TARGET_IFINDEX
SEC("xdp")
int xdp_redirect_to_nic(struct xdp_md *ctx)
{
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
