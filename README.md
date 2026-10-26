# Adaptive XDP/eBPF Firewall

A packet-filtering firewall that runs as an eBPF program at the XDP hook, in
the network driver's receive path, with a userspace control plane that
adapts the rate limits and applies firewall to sources based on the traffic
it sees.

```
                       NIC / veth receive path
                                |
   ===== KERNEL ================|=======================================
        +-----------------------v-------------------------------+
        |  XDP program (C, eBPF), once per packet               |
        |  parse -> allowlist -> blocklist -> TCP flag checks   |
        |  -> port rules / default policy -> per-source limit   |
        +-------------------------------------------------------+
                    |                          ^
                    v    BPF maps (pinned)     |
        +-------------------------------------------------------+
        |  allowlist  blocklist  portrules  srcstate  stats  config |
        +-------------------------------------------------------+
                    |                          ^
   ===== USERSPACE =|==========================|========================
                    v                          |
        +-------------------------------------------------------+
        |  fwctl: rules by hand    controller: adapts once a second |
        +-------------------------------------------------------+
```

**The kernel enforces and userspace decides.** They only share maps, so
userspace is never on the packet path, and stopping it leaves the firewall
running with the last rules and deadlines it wrote.

## What it does

**Data plane (C, eBPF, `bpf/firewall.bpf.c`)**
- Parses Ethernet, one VLAN tag, IPv4, TCP, UDP and ICMP, with every read
  bounds-checked for the verifier
- Source allowlist and blocklist as CIDR prefixes (LPM tries). Blocks can
  expire, and the kernel checks the deadline itself.
- Port rules: allow or deny by protocol and destination port (or ICMP type),
  and a default policy of allow or deny for everything without a rule
- Drops TCP flag combinations no real stack sends (null, SYN+FIN, SYN+RST,
  FIN+RST, xmas)
- Per-source token-bucket rate limiting, made safe across CPUs with
  `bpf_spin_lock`
- Per-source traffic counters for the controller, and per-CPU global counters
  where passes + drops always equals packets received

**Control plane (Python, no dependencies, `control/`)**
- Talks to the kernel through the raw `bpf(2)` syscall: no BCC, no libbpf
  binding
- `fwctl`: manage rules and lists, inspect counters, self-test
- `controller`: the adaptive part, two rule-based mechanisms:
  - **Load tiers:** when the traffic reaching the rate limiter rises, it
    tightens everyone's per-source limit within a second, then relaxes one
    step per 5 calm seconds
  - **Auto-blocking:** each second a source matches a rule (port scan,
    flood, unanswered SYNs, ICMP flood) earns it a strike, and each clean
    second takes one away. At two strikes it is blocked for 60 s, then
    300 s, then 900 s if it comes back
  - Guard rails: allowlisted hosts are never blocked, at most 32 new blocks
    a second, and a dry-run mode

## Quick start

Copy the zip to the VM and build:

```bash
scp -P 2222 adaptive-xdp-firewall.zip devuser@127.0.0.1:~/
ssh devuser@127.0.0.1 -p 2222
unzip adaptive-xdp-firewall.zip && cd adaptive-xdp-firewall
./scripts/install_deps.sh            # once
make
make test                            # unit tests, no root
sudo make e2e                        # builds the testbed, loads, checks multiple behaviours
sudo ./scripts/demo.sh               # the guided demo

sudo ./scripts/block_ip.sh 8.8.8.8     # if asked to block an address
sudo ./bench/setup_netns.sh && sudo ./bench/run_experiment.sh   # runs for ~20 min
python3 bench/plot.py results/run-*
sudo ./bench/collateral.sh && sudo ./bench/detection.sh            # the evaluation, ~2 h
python3 bench/eval_report.py results/collateral-*                  # and results/detection-*
```


## Using it

```bash
sudo ./bench/setup_netns.sh                             # the test network
sudo ./bin/fwload -i veth-fw                            # load and attach

sudo python3 -m control.fwctl port deny tcp 23          # block telnet
sudo python3 -m control.fwctl port allow tcp 22 80 443  # allow services...
sudo python3 -m control.fwctl port allow icmp 8         # ...and ping
sudo python3 -m control.fwctl policy deny               # drop everything else
sudo python3 -m control.fwctl port                      # rules with hit counts

sudo python3 -m control.fwctl block add 203.0.113.7      # one address, 60 s
sudo python3 -m control.fwctl block add 203.0.113.0/24 --duration 0   # a prefix, for good
sudo python3 -m control.fwctl block list                # with drop counts
sudo python3 -m control.fwctl allow add 10.10.1.2       # never filtered
sudo python3 -m control.fwctl status                    # settings and counters

sudo python3 -m control.controller                      # the adaptive loop
```

The policy is stateless, like iptables without conntrack: with
`policy deny`, replies to connections this machine opens itself need rules
too. That's fine for a server that only accepts connections.

```bash
sudo ./scripts/block_ip.sh 8.8.8.8
```

The testbed is a closed network, so the script sends five packets with that
source address from the client side, blocks it, and sends five more.
tcpdump on `veth-fw` counts 5 and then 0: the packets are dropped before the
network stack sees them. It works for prefixes too (`203.0.113.0/24`).

## Which interface does what

```
 netns: fwtest                              root namespace
 veth-cl  10.10.1.2 ... .7   ============>  veth-fw  10.10.1.1
 the clients                     wire       XDP ATTACHED HERE
```

`veth-cl` sends and `veth-fw` filters. Your SSH session uses a different
interface and is never touched.

## Project layout

```
bpf/common.h              map layouts shared by kernel, loader and Python
bpf/firewall.bpf.c        the XDP program
src/loader.c              verify, pin, attach, exit
control/bpfmap.py         bpf(2) syscall wrapper
control/firewall.py       typed access to the maps and the program
control/fwctl.py          manual CLI
control/detect.py         per-second behaviour and the detection rules
control/policy.py         load tiers and the auto-blocker
control/controller.py     the adaptive loop
scripts/demo.sh           guided, self-checking demo
scripts/block_ip.sh       block any address and show it on the testbed
scripts/install_deps.sh   dependencies for Ubuntu 22.04 / 24.04
tests/test_policy.py      unit tests (no root)
tests/e2e.sh              end-to-end test with real packets
bench/setup_netns.sh      the veth testbed
bench/gen_traffic.sh      normal and misbehaving traffic
bench/nftables_baseline.sh  the same policy in nftables, for comparison
bench/run_experiment.sh   benchmark: none vs nftables vs XDP
bench/nic_path.sh         delivers traffic like a network card, from one or many sources
bench/nic_path.bpf.c      the XDP program behind it
bench/plot.py             summary, consistency checks and the CPU chart
bench/collateral.sh       evaluation: a normal user's experience during attacks
bench/detection.sh        evaluation: attacks caught, normal clients wrongly blocked
bench/clients.py          realistic clients and servers for the evaluation
bench/eval_report.py      summaries and the latency chart for the evaluation
```

## Common commands

| Purpose | Command |
|---|---|
| Build | `make` |
| Check C/Python layouts agree | `make check-schema` |
| Rebuild after editing `common.h` | `make reload` |
| Status | `sudo python3 -m control.fwctl status` |
| Port rules | `sudo python3 -m control.fwctl port [allow\|deny\|del] PROTO PORT...` |
| Default policy | `sudo python3 -m control.fwctl policy allow\|deny` |
| Live per-source view | `sudo python3 -m control.fwctl top --watch` |
| Clean slate | `sudo python3 -m control.fwctl reset --all` |
| Controller, watch only | `sudo python3 -m control.controller --dry-run` |
| Benchmark | `sudo ./bench/run_experiment.sh` then `python3 bench/plot.py results/run-*` |
| Evaluation | `sudo ./bench/collateral.sh`, `sudo ./bench/detection.sh`, then `python3 bench/eval_report.py results/<dir>` |

## Requirements

- Linux 5.10+ (5.15+ preferred), tested on Ubuntu 24.04
- clang, libbpf-dev, libelf-dev (installed by `scripts/install_deps.sh`)
- root, to load BPF programs and open the pinned maps
- Python 3.8+ with nothing extra; matplotlib only for the chart


## Demo walkthrough

A quick walkthrough via a terminal on the VM.

## Setup

```bash
cd ~/adaptive-xdp-firewall
sudo ./bench/setup_netns.sh                       # test network: clients 10.10.1.2/.3/.4 -> firewall 10.10.1.1
sudo ./bin/fwload -i veth-fw                       # load the XDP firewall
sudo python3 -m control.fwctl reset --all          # start with no rules
sudo python3 -m http.server 8080 --bind 10.10.1.1 >/dev/null 2>&1 &   # a web server to protect
```

Paste these two helpers. `t SRC PORT` connects from a client address to a port on the firewall host. `p SRC` pings from a client.

```bash
t() { local c; c=$(sudo ip netns exec fwtest curl -s -m 2 -o /dev/null -w '%{http_code}' --interface $1 http://10.10.1.1:$2/)
      case $? in 0) echo "HTTP $c";; 7) echo "refused";; 28) echo "no answer (dropped)";; *) echo "error";; esac; }
p() { sudo ip netns exec fwtest ping -c 2 -W 1 -I $1 10.10.1.1 | grep -o "[0-9]* received"; }
FW="sudo python3 -m control.fwctl"
```

There are three possible answers:

| Answer | Meaning |
|---|---|
| `HTTP 200` | Allowed, and the web server replied. |
| `refused` | The packet got through the firewall, but nothing is listening on that port. |
| `no answer (dropped)` | The firewall dropped the packet. |

## 1. Before any rules

```bash
t 10.10.1.2 8080      # HTTP 200
t 10.10.1.3 8080      # HTTP 200
t 10.10.1.2 23        # refused   (port 23 reachable, just nothing listening)
p 10.10.1.3           # 2 received
```

## 2. Block an IP

```bash
$FW block add 10.10.1.3 --duration 60    # blocked 10.10.1.3/32 for 60s
t 10.10.1.3 8080      # no answer (dropped)
p 10.10.1.3           # 0 received
t 10.10.1.2 8080      # HTTP 200   <- other clients unaffected
$FW block list
```
```
prefix                 remaining          hits  reason
10.10.1.3/32                 56s             4  manual
```
`hits` counts the packets XDP dropped for that entry. To unblock:
```bash
$FW block del 10.10.1.3                  # unblocked 10.10.1.3
t 10.10.1.3 8080      # HTTP 200
```
Use `--duration 0` for a permanent block. If you leave the block in place, it lifts by itself when the time runs out.

## 3. Block a whole range, but allow one IP

```bash
$FW block add 10.10.1.0/24 --duration 60
t 10.10.1.2 8080      # no answer (dropped)
$FW allow add 10.10.1.2                  # allowed 10.10.1.2/32
t 10.10.1.2 8080      # HTTP 200   <- allowlist wins over the block
t 10.10.1.4 8080      # no answer (dropped)   <- rest of the /24 still blocked
$FW block add 10.10.1.2
# refused 10.10.1.2: it is allowlisted. Remove it from the allowlist first.
```
Undo with `$FW allow del 10.10.1.2` and `$FW block del 10.10.1.0/24`.

## 4. Block a port

```bash
$FW port deny tcp 8080                    # deny tcp/8080
t 10.10.1.2 8080      # no answer (dropped)
t 10.10.1.2 23        # refused   <- other ports unaffected
$FW port
```
```
rule          action            hits
tcp/8080      deny                 2
anything else allow     (default policy)
```
```bash
$FW port del tcp 8080                     # removed tcp/8080
t 10.10.1.2 8080      # HTTP 200
```

## 5. Allow only certain ports, drop everything else

```bash
$FW port allow tcp 8080
$FW port allow icmp 8                     # ping (ICMP type 8)
$FW policy deny                           # default: drop anything without an allow rule
t 10.10.1.2 8080      # HTTP 200
t 10.10.1.2 22        # no answer (dropped)
t 10.10.1.2 23        # no answer (dropped)
p 10.10.1.2           # 2 received
$FW port
```
```
rule          action            hits
icmp/8        allow                2
tcp/8080      allow                6
anything else deny      (default policy)
```
Undo with `$FW policy allow` and `$FW port flush`.

## Seeing why packets were dropped

```bash
$FW stats | grep -E "pass_|drop_"
```
This shows a counter per reason: `drop_blocklist` (blocked IP), `drop_port_rule` (deny rule), `drop_default` (default-deny policy), `pass_allowlist`, `pass_rule`, and so on. For independent proof that a packet never reached the network stack, watch the interface with `sudo tcpdump -ni veth-fw port 8080` while you test: dropped packets don't appear.

You can't send real internet traffic into this closed test network, so to block an address (say 8.8.8.8), use `sudo ./scripts/block_ip.sh 8.8.8.8`. It sends packets with that source address, then shows tcpdump seeing 5 before the block and 0 after.

Also, we use token bucket for rate limiting. We have defaults, with the burst set to two seconds' worth of the rate, which is a common rule of thumb. We can change them with `sudo python3 -m control.fwctl config set --rate 1000 --burst 2000`. The adaptive controller changes both together. As load rises it tightens each source's limit through four levels: 20,000/40,000, then 5,000/10,000, then 1,000/2,000, then 200/400. The burst stays at twice the rate at every level.

## Clean up

```bash
$FW reset --all
kill %1                                   # stops the web server
```


## Known limitations

- **IPv4 only.** IPv6 passes unfiltered.
- **Stateless.** No connection tracking: with a default-deny policy, replies
  to outgoing connections need their own rules, and a flood of ACKs looks
  like the return half of a download.
- **Single ports.** Port rules match one port each, not ranges.
- **`srcstate` can fill up** under heavy source spoofing. A map that holds a
  `bpf_spin_lock` can't be an `LRU_HASH`; idle entries are removed after
  60 s.
- **Fixed thresholds.** The tier and detection thresholds were tuned on the
  veth testbed and would need recalibrating for a real network.
- **The testbed is veth.** It runs native XDP, but traffic pushed straight
  into a veth pair arrives as an `sk_buff` that XDP must copy. The benchmark
  therefore delivers raw frames, as a network card does
  (`bench/nic_path.bpf.c`). See the report, Sections 7.4 and 8.1.

## References

- Høiland-Jørgensen et al. 2018. The eXpress Data Path: fast programmable packet processing in the operating system kernel. CoNEXT '18, 54–66. <https://doi.org/10.1145/3281411.3281443>
- The Linux Kernel Documentation: BPF <https://docs.kernel.org/bpf/> and BPF maps <https://docs.kernel.org/bpf/maps.html>
- eBPF Documentation <https://docs.ebpf.io/>
- Cilium BPF and XDP Reference Guide <https://docs.cilium.io/en/stable/network/ebpf/intro/>
- libbpf API Documentation <https://libbpf.readthedocs.io/>
- nftables wiki <https://wiki.nftables.org/>

