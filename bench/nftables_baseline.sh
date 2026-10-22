#!/usr/bin/env bash
# The firewall's policy written for nftables, for the benchmark.
#
#   sudo ./bench/nftables_baseline.sh apply [iface]
#   sudo ./bench/nftables_baseline.sh block <ip>
#   sudo ./bench/nftables_baseline.sh drops       # packets dropped so far
#   sudo ./bench/nftables_baseline.sh status | remove
#
# Same rules in the same order as the XDP program: allowlist, blocklist,
# TCP flag checks, deny tcp/23, per-source rate limit.
#
# HOOK=prerouting (default) filters at inet prerouting priority -300, where
# iptables/nftables firewalls normally run. HOOK=ingress uses the netdev
# ingress hook instead, the earliest point netfilter can see a packet.
set -euo pipefail

IFACE=${2:-veth-fw}
HOOK=${HOOK:-prerouting}

case $HOOK in
    prerouting) TABLE="inet fwbench"
                HEAD="type filter hook prerouting priority -300; policy accept;
        iifname != \"$IFACE\" accept" ;;
    ingress)    TABLE="netdev fwbench"
                HEAD="type filter hook ingress device \"$IFACE\" priority -500; policy accept;" ;;
    *) echo "HOOK must be prerouting or ingress" >&2; exit 1 ;;
esac

[[ $EUID -eq 0 ]] || { echo "needs root" >&2; exit 1; }

case ${1:-} in
apply)
    nft delete table inet fwbench 2>/dev/null || true
    nft delete table netdev fwbench 2>/dev/null || true
    # The heredoc is unquoted so the variables expand, which also means
    # backticks in here would run as commands. Don't use them.
    nft -f - <<EOF
table $TABLE {
    set allowset { type ipv4_addr; flags interval; }
    set blockset { type ipv4_addr; flags interval; }

    chain filter {
        $HEAD

        ip saddr @allowset counter accept
        ip saddr @blockset counter drop

        tcp flags & (fin|syn) == (fin|syn) counter drop
        tcp flags & (syn|rst) == (syn|rst) counter drop
        tcp flags & (fin|rst) == (fin|rst) counter drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg) counter drop

        tcp dport 23 counter drop

        meter flood { ip saddr limit rate over 20000/second burst 40000 packets } counter drop
    }
}
EOF
    echo "nftables policy applied at $HOOK on $IFACE"
    ;;
block)
    nft add element $TABLE blockset "{ $2 }"
    ;;
drops)
    # Sum the counters on drop rules. Anchor on "counter packets": the meter
    # rule also contains "burst N packets" earlier on the same line.
    nft list table $TABLE 2>/dev/null | awk '/drop/ {
        for (i = 1; i < NF; i++)
            if ($i == "counter" && $(i+1) == "packets") { s += $(i+2); break }
    } END { print s + 0 }'
    ;;
status)
    nft list table $TABLE 2>/dev/null || echo "table $TABLE not present"
    ;;
remove)
    { nft delete table inet fwbench || nft delete table netdev fwbench; } 2>/dev/null \
        && echo "removed table fwbench" || true
    ;;
*)
    sed -n '2,14p' "$0"; exit 1 ;;
esac
