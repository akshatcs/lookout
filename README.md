# Adaptive XDP/eBPF Firewall

A kernel-level firewall that filters packets in the NIC driver's receive path
using XDP and eBPF - before Linux allocates an `sk_buff` - with a userspace
control plane that adapts enforcement based on observed traffic behaviour.

```
                       NIC / veth receive path
                                |
   ===== KERNEL ================|=====================================
        +-----------------------v------------------------+
        |  XDP program (C, eBPF)                          |
        |  parse -> allowlist -> blocklist -> flag sanity |
        |        -> per-source token bucket -> counters   |
        +------------------------------------------------+
                    |                          ^
                    v    BPF maps (pinned)     |
        +------------------------------------------------+
        |  allowlist  blocklist  srcstate  stats  config  |
        +------------------------------------------------+
                    |                          ^
   ===== USERSPACE =|==========================|==========
                    v                          |
        +------------------------------------------------+
        |  control plane (Python, 1 Hz)                   |
        |  features -> Random Forest -> policy engine     |
        +------------------------------------------------+
```

**The kernel enforces and the userspace decides.** They communicate only through maps, which means the control plane is never on the packet path - and terminating it leaves the firewall running with its last policy intact.

---

## What it does

**Data plane (C, eBPF)**
- IPv4 / VLAN / TCP / UDP / ICMP parsing with full verifier-checked bounds
- CIDR allowlist and blocklist using LPM tries, with kernel-side block expiry
- Stateless TCP flag sanity checks (null, SYN+FIN, SYN+RST, FIN+RST, Xmas)
- Per-source token-bucket rate limiting, made race-free with `bpf_spin_lock`
- Per-source behavioural counters and per-CPU global statistics

**Control plane (Python)**
- Reaches the kernel through the raw `bpf(2)` syscall - no BCC, no libbpf binding
- Safety rails: allowlist immunity, hysteresis, escalating block durations,
  insertion rate cap, dry-run mode
- A second, non-ML adaptive loop that scales rate limits by observed load
- Loads the eBPF program to the Kernel
---

## Quick start

```bash
# Quick start - Get into the VM and copy the project.
scp -P 2222 adaptive-xdp-firewall.tar.gz devuser@127.0.0.1:~/      # Upload local file to remote server
scp -P 2222 devuser@127.0.0.1:~/adaptive-xdp-firewall-v1.tar.gz .  # Download remote file to local directory
ssh devuser@127.0.0.1 -p 2222
tar xzf adaptive-xdp-firewall.tar.gz && cd adaptive-xdp-firewall
./scripts/install_deps.sh && make && make model
sudo ./bench/setup_netns.sh
sudo ./bin/fwload -i veth-fw
sudo python3 -m control.fwctl selftest

./scripts/install_deps.sh        # clang, libbpf, hping3, ...
make                             # build the eBPF object and the loader
make model                       # train the Random Forest
make test                        # offline pipeline test, no root needed
 
sudo ./bench/setup_netns.sh      # create the veth testbed
sudo ./bin/fwload -i veth-fw     # load and attach
sudo python3 -m control.fwctl selftest   # verify the plumbing
```
 
Then, in two terminals:
 
```bash
# terminal 1 - watch it decide (without enforcing)
sudo python3 -m control.controller --iface veth-fw --dry-run
 
# terminal 2 - send it an attack
sudo ./bench/gen_traffic.sh syn_flood 30 10.10.1.3
```
 
Tear down:
 
```bash
sudo ./bin/fwload -i veth-fw -u
sudo ./bench/teardown_netns.sh
```
 
---

## Which interface does what
 
```
 netns: fwtest                             root namespace
 veth-cl  10.10.1.2/.3/.4   ============>  veth-fw  10.10.1.1
 GENERATES packets              Wire       XDP ATTACHED HERE
```
 
`veth-cl` sends, `veth-fw` filters. The XDP program runs on the **ingress** of
`veth-fw`, so it inspects packets arriving there - exactly the ones `veth-cl`
sent. Allow and block lists match on **source address**.
 
Your SSH session runs over a different interface (`enp0s3` or similar) and is
never touched by the testbed.
 
## Blocking an arbitrary address on the spot

If you want to block Google DNS or a particular website during a
demonstration, the testbed is a closed network and nothing from the internet
arrives on `veth-fw`. This can be achieved with two options.
 
```bash
# Option A -- forge the source address in the testbed (safe, 30 seconds)
sudo ip netns exec fwtest hping3 -c 5 -S -a 8.8.8.8 10.10.1.1   # gets through
sudo python3 -m control.fwctl block add 8.8.8.8 --duration 120
sudo ip netns exec fwtest hping3 -c 5 -S -a 8.8.8.8 10.10.1.1   # dropped
sudo python3 -m control.fwctl block list                         # hit counter
 
# Option B -- attach to the VM's real NIC so DNS genuinely stops
# (allowlist your SSH client first; see DEMO.md for the full procedure)
```
 
## Layout
 
```
bpf/
  common.h              shared struct definitions -- THE CONTRACT
  firewall.bpf.c        the XDP program
src/
  loader.c              libbpf loader: load, pin, attach, exit
control/
  schema.py             Python mirror of common.h, self-verifying
  bpfmap.py             raw bpf(2) syscall wrapper via ctypes
  firewall.py           typed access to the five pinned maps
  features.py           cumulative counters -> per-second features
  model.py              Random Forest + threshold baseline
  policy.py             safety rails and the load-based adaptive loop
  controller.py         the 1 Hz control loop (run this)
  fwctl.py              manual CLI (run this)
  collect.py            capture labelled training data
  synth.py              synthetic training data generator
bench/
  setup_netns.sh        create the veth testbed
  nftables_baseline.sh  equivalent policy for the comparison
  run_experiment.sh     automated benchmark sweep
  latency.py            UDP ping-pong with percentiles
  gen_traffic.sh        named traffic classes for demos and training
  plot.py               charts and summary tables
  demo_tmux.sh          four-pane layout for recording
tests/
  test_pipeline.py      offline test of features -> model -> policy
docs/                   the documents listed above
```
 
---
 
## Common commands
 
| Purpose | Command |
|---|---|
| Build | `make` |
| Verify C/Python struct agreement | `make check-schema` |
| Rebuild and reload after editing `common.h` | `make reload` |
| Status | `sudo python3 -m control.fwctl status` |
| Live per-source view | `sudo python3 -m control.fwctl top --watch` |
| Block by hand | `sudo python3 -m control.fwctl block add IP --duration 60` |
| Allowlist | `sudo python3 -m control.fwctl allow add IP` |
| Control plane, safe | `sudo python3 -m control.controller --dry-run` |
| Control plane, live | `sudo python3 -m control.controller` |
| Without the model | `sudo python3 -m control.controller --no-ml` |
| Benchmark | `sudo ./bench/run_experiment.sh` |
 
---
 
## Requirements
 
- Linux kernel **5.10+** (5.15+ preferred), Ubuntu 22.04 or 24.04
- clang 10+, libbpf-dev, libelf-dev
- Root, for loading BPF programs and reading pinned maps
- scikit-learn *(optional — `--no-ml` falls back to the threshold detector)*
---
 
## Scope and known limitations
 
- **IPv4 only.** IPv6 is passed unfiltered.
- **No connection state.** An ACK flood is close to indistinguishable from the
  reverse direction of a legitimate download using per-source aggregates alone.
  The fix is SYN cookies or connection tracking.
- **`srcstate` can fill** under source spoofing, because a map holding a
  `bpf_spin_lock` cannot be an `LRU_HASH`. A correct rate limiter with bounded
  capacity was chosen over an incorrect one with unbounded capacity.
- **Port spread is approximate** - a 64-bit hashed bitmap, so it under-counts.
- **One-second resolution.** Bursts shorter than a window are averaged out.
- **Benchmarks run on veth**, which supports native XDP but has no DMA or
  hardware queues. Relative comparisons between systems are valid; absolute
  packet rates do not transfer to real NICs.
---
 
## References

- Toke Høiland-Jørgensen, Jesper Dangaard Brouer, Daniel Borkmann, John Fastabend, Tom Herbert, David Ahern, and David Miller. 2018. The eXpress data path: fast programmable packet processing in the operating system kernel. In Proceedings of the 14th International Conference on Emerging Networking Experiments and Technologies (CoNEXT '18). Association for Computing Machinery, New York, NY, USA, 54–66. - <https://doi.org/10.1145/3281411.3281443>
- The Linux Kernel Documentation (BPF Documentation) - <https://docs.kernel.org/bpf/>
- The Linux Kernel Documentation (BPF Maps) - <https://docs.kernel.org/bpf/maps.html>
- eBPF Documentation - <https://docs.ebpf.io/>
- Cilium BPF and XDP Reference Guide - <https://docs.cilium.io/en/stable/network/ebpf/intro/>
- libbpf API Documentation - <https://libbpf.readthedocs.io/>
- Netfilter Project - nftables - <https://wiki.nftables.org/wiki-nftables/index.php/Main_Page>
