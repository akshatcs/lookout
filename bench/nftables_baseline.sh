#!/usr/bin/env bash
# =============================================================================
# nftables_baseline.sh -- the conventional Linux firewall we compare against.
#
# For the comparison to mean anything, this ruleset must enforce the SAME
# POLICY as the XDP program: allowlist first, then blocklist, then a
# per-source rate limit. Any difference in measured cost then comes from WHERE
# the work happens, not from what work is done.
#
# The essential difference being measured:
#
#   nftables runs at the netfilter prerouting hook. By the time a packet gets
#   there the kernel has already allocated an sk_buff and walked part of the
#   receive path. That allocation is the cost XDP avoids.
#
#   We attach at priority -300 (raw/conntrack-defeating, the earliest
#   netfilter hook available) to give nftables the best possible showing.
#
# Usage:
#   sudo ./bench/nftables_baseline.sh apply [iface]
#   sudo ./bench/nftables_baseline.sh status
#   sudo ./bench/nftables_baseline.sh remove
# =============================================================================
set -euo pipefail

TABLE="fwbench"
IFACE="${2:-veth-fw}"
RATE="${RATE:-20000}"       # match the XDP default: per-source packets/second
BURST="${BURST:-40000}"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (sudo $0)" >&2
    exit 1
fi

command -v nft >/dev/null || { echo "error: nftables not installed (sudo apt install nftables)" >&2; exit 1; }

case "${1:-}" in
apply)
    nft delete table inet $TABLE 2>/dev/null || true

    # NOTE: the heredoc delimiter below is deliberately UNQUOTED so that
    # $TABLE, $IFACE, $RATE and $BURST expand. The consequence is that
    # BACKTICKS INSIDE THIS BLOCK ARE COMMAND SUBSTITUTION -- writing `meter`
    # in a comment makes bash try to run `meter` and print "command not found".
    # Use 'single quotes' in comments here, never backticks.
    nft -f - <<NFT
table inet $TABLE {
    # Named sets mirror the LPM tries in the XDP program. 'flags interval'
    # gives nftables prefix matching, the closest equivalent to an LPM trie.
    set allowset {
        type ipv4_addr
        flags interval
    }

    set blockset {
        type ipv4_addr
        flags interval
    }

    chain prerouting {
        # -300 is the earliest netfilter hook. Giving the baseline its best
        # possible position is what makes the comparison fair.
        type filter hook prerouting priority -300; policy accept;

        iifname != "$IFACE" accept

        ip saddr @allowset counter accept
        ip saddr @blockset counter drop

        # Per-source token bucket. 'meter' keys a dynamic set on the source
        # address, which is nftables' equivalent of our per-source BPF hash.
        # The 'counter' is essential for the benchmark: without it we cannot
        # tell whether nftables actually dropped anything, and a baseline that
        # silently passed all traffic would look artificially cheap.
        meter flood { ip saddr limit rate over ${RATE}/second burst ${BURST} packets } counter drop

        # Protocol sanity, matching tcp_flags_sane() in firewall.bpf.c.
        tcp flags & (fin|syn) == (fin|syn) counter drop
        tcp flags & (syn|rst) == (syn|rst) counter drop
        tcp flags & (fin|rst) == (fin|rst) counter drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg) counter drop
    }
}
NFT
    echo "nftables baseline applied on $IFACE (rate ${RATE}/s, burst ${BURST})"
    echo "IMPORTANT: unload the XDP firewall before benchmarking this, or you"
    echo "           are measuring both stacks at once:"
    echo "           sudo ./bin/fwload -i $IFACE -u"
    ;;
remove)
    nft delete table inet $TABLE 2>/dev/null && echo "removed table $TABLE" \
        || echo "table $TABLE was not present"
    ;;
status)
    nft list table inet $TABLE 2>/dev/null || echo "table $TABLE not present"
    ;;
drops)
    # Total packets dropped by every counter on a drop rule. Used by
    # run_experiment.sh so the nftables baseline is measured the same way the
    # XDP firewall is.
    # Sum the packet count of every counter attached to a drop rule.
    #
    # The awk anchors on the "counter packets" PAIR, not on "packets" alone.
    # nft renders the meter rule as:
    #     add @flood { ... burst 40000 packets } counter packets N bytes M drop
    # so "packets" appears twice, and matching the first occurrence grabs the
    # burst clause and yields 0 -- silently losing the count from the rule that
    # does most of the dropping.
    nft -a list table inet $TABLE 2>/dev/null \
      | awk '/drop/ {for(i=1;i<NF;i++) if($i=="counter" && $(i+1)=="packets") {s+=$(i+2); break}} END {print s+0}'
    ;;
zero)
    # `reset counters` only clears NAMED counter objects. Our counters are
    # anonymous rule counters, so `reset rules` is the correct command. The
    # wrong one is valid syntax that matches nothing, which is why it failed
    # silently and let counts accumulate across benchmark repeats.
    nft reset rules table inet $TABLE >/dev/null 2>&1 || true
    # Older nft without `reset rules`: rebuild the table instead.
    if ! nft -a list table inet $TABLE 2>/dev/null | grep -q 'packets 0 bytes 0'; then
        :  # best effort; run_experiment also tolerates a non-zero baseline
    fi
    ;;
*)
    echo "usage: $0 {apply|remove|status} [iface]" >&2
    exit 1
    ;;
esac

