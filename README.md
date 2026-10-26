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

**The kernel enforces and userspace decides.** They only share maps (ebpf maps), so
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
sudo ./scripts/block_ip.sh 10.10.1.3
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

A quick walkthrough via a terminal.

## 0. Set up (once, before the demo)

```bash
cd ~/adaptive-xdp-firewall
sudo ./bench/setup_netns.sh                     # test network: clients 10.10.1.2–.4 -> firewall host 10.10.1.1
sudo ./bin/fwload -i veth-fw                    # load the XDP firewall
sudo python3 -m control.fwctl reset --all       # start with no rules
python3 -m http.server 8080 --bind 10.10.1.1 >/dev/null 2>&1 &   # a small web server to protect
```

Two shortcuts make the demo commands easy to read (paste them once):

```bash
p()   { sudo ip netns exec fwtest ping -c 3 -W 1 -I "$1" 10.10.1.1 | grep -E "received|100% packet loss"; }
web() { sudo ip netns exec fwtest curl -s -m 2 -o /dev/null -w "HTTP %{http_code}\n" --interface "$1" http://10.10.1.1:"$2"/ || echo "no answer"; }
```

- `p ADDR` pings the firewall host from that client address.
- `web ADDR PORT` fetches the web page from that client address. You'll see `HTTP 200` if it works, and `HTTP 000` or `no answer` if it's blocked.

## Part A: Block an IP address

**1. Before:** both clients can reach the host.
```bash
p 10.10.1.3          # 3 received
p 10.10.1.2          # 3 received
```

**2. Block one address:**
```bash
sudo python3 -m control.fwctl block add 10.10.1.3        # blocked for 60 s by default
```

**3. After:** only that address is cut off.
```bash
p 10.10.1.3          # 0 received (100% packet loss)
p 10.10.1.2          # 3 received: other clients are unaffected
```

**4. Show the firewall counted it:**
```bash
sudo python3 -m control.fwctl block list                 # shows the entry, time left, and packets dropped
```

**5. Unblock:**
```bash
sudo python3 -m control.fwctl block del 10.10.1.3
p 10.10.1.3          # 3 received again
```

Optional variations:
```bash
sudo python3 -m control.fwctl block add 10.10.1.3 --duration 10   # lifts by itself after 10 s
sudo python3 -m control.fwctl block add 10.10.1.0/24 --duration 0 # a whole subnet, until removed
```

The block is a kernel map entry. The XDP program checks it for every packet in the network driver, and drops matching packets before Linux builds anything for them. The expiry is checked by the kernel too, so the block lifts on time even if no userspace program is running.

### Proof that blocked packets never reach the stack

This one command shows it with tcpdump as a witness:
```bash
sudo ./scripts/block_ip.sh 8.8.8.8
```
It sends 5 packets with that source address, blocks it, and sends 5 more. tcpdump on the protected interface sees **5, then 0**: the packets are dropped before the network stack sees them. Remove it afterwards with `sudo python3 -m control.fwctl block del 8.8.8.8/32`.

## Part B: Block a port

**1. Before:** the web server on port 8080 answers.
```bash
web 10.10.1.2 8080   # HTTP 200
```

**2. Deny the port:**
```bash
sudo python3 -m control.fwctl port deny tcp 8080
```

**3. After:** nothing reaches the web server, from any client.
```bash
web 10.10.1.2 8080   # HTTP 000 / no answer
p 10.10.1.2          # ping still works: only that port is blocked
```

**4. Show the rule and its hit counter:**
```bash
sudo python3 -m control.fwctl port                       # lists rules with how many packets each one dropped
```

**5. Remove the rule:**
```bash
sudo python3 -m control.fwctl port del tcp 8080
web 10.10.1.2 8080   # HTTP 200 again
```

### Optional: allow-only mode (default deny)

This turns it into a "deny everything except what I allow" firewall:
```bash
sudo python3 -m control.fwctl port allow tcp 8080        # allow the web server
sudo python3 -m control.fwctl port allow icmp 8          # allow ping
sudo python3 -m control.fwctl policy deny                # drop everything else

web 10.10.1.2 8080   # HTTP 200: allowed by rule
p 10.10.1.2          # 3 received: allowed by rule
sudo python3 -m control.fwctl port                       # rules, plus "anything else: deny"

sudo python3 -m control.fwctl policy allow               # back to normal
```

## Overall status

```bash
sudo python3 -m control.fwctl status    # settings, rules, lists and every counter
```

## Clean up after the demo

```bash
kill %1 2>/dev/null                              # stop the web server
sudo python3 -m control.fwctl reset --all        # remove all rules
sudo ./bin/fwload -i veth-fw -u                  # unload the firewall (optional)
```

- If a `p` or `web` result creates an issue, run `sudo python3 -m control.fwctl reset --all` and start that part again.
- For the full guided demo, including the adaptive controller, use `sudo ./scripts/demo.sh`. It pauses at each step and checks each result.

You can't send real internet traffic into this closed test network, so to block an address, use `sudo ./scripts/block_ip.sh <ip address>`. It sends packets with that source address, then shows tcpdump seeing 5 before the block and 0 after.

Also, we use token bucket for rate limiting. We have defaults, with the burst set to two seconds' worth of the rate, which is a common rule of thumb. We can change them with `sudo python3 -m control.fwctl config set --rate 1000 --burst 2000`. The adaptive controller changes both together. As load rises it tightens each source's limit through four levels: 20,000/40,000, then 5,000/10,000, then 1,000/2,000, then 200/400. The burst stays at twice the rate at every level.

## Benchmarking

```bash
cd ~/project/adaptive-xdp-firewall
make                                   # build if you haven't
sudo ./bench/setup_netns.sh            # the test network
```

Performance benchmark: CPU per packet
```bash
sudo ./bench/run_experiment.sh
python3 bench/plot.py results/run-*
```

On a VM with 2 vCPUs, run sudo ./bench/run_experiment.sh --senders 1 instead, so the senders don’t saturate both CPUs.

A normal user experience
```bash
sudo ./bench/collateral.sh
python3 bench/eval_report.py results/collateral-*
```

Detection accuracy
```bash
sudo ./bench/detection.sh
python3 bench/eval_report.py results/detection-*
```

Each run creates its own folder under results. If you’ve run a benchmark more than once, results/run-* matches several folders. Give the exact folder name instead, for example python3 bench/plot.py results/run-20261026-153500.

Note: If your VM runs VirtualBox on top of Hyper-V, which breaks CPU-time accounting. Here's what it means for the benchmarks:

Benchmark 1: plot.py checks for the problem. If it reports CPU busy is lower than the senders alone must use, the CPU figures from that run aren’t valid. The packet counts still are. Benchmarks 2 and 3: they rely on accurate timing and CPU figures. On a VM, rates and timings will come out lower or slower than on a normal machine because the virtual machine manager might context switch the virtual machine on the host operating system.

The results in a test virtual environments are kept in lookout-results.zip file. To regenerate their summaries and charts on the VM, run:

```bash
unzip lookout-results.zip
python3 bench/plot.py        lookout-results/benchmark
python3 bench/eval_report.py lookout-results/collateral
python3 bench/eval_report.py lookout-results/detection
```


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
- Securing Linux with a faster and scalable iptables <https://dl.acm.org/doi/10.1145/3371927.3371929>
- Performance Implications of Packet Filtering with Linux eBPF <https://ieeexplore.ieee.org/document/8493077>
- Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications <https://dl.acm.org/doi/10.1145/3371038>

