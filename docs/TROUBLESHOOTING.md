# TROUBLESHOOTING.md

Problems are grouped by the stage at which they appear.

---

## Build

### `fatal error: 'gnu/stubs-32.h' file not found`

A header you included pulls in glibc's `<sys/socket.h>`, which breaks under
`clang -target bpf`. The usual culprits are `<linux/if_vlan.h>` and
`<linux/icmp.h>` (both reach it via `<linux/if.h>`).

Fix: declare the small struct you need yourself, as
`bpf/firewall.bpf.c` does for `vlan_hdr` and `icmphdr_min`. Or
`sudo apt install gcc-multilib`.

### `bpf/bpf_helpers.h: No such file or directory`

```bash
sudo apt install libbpf-dev
```

### `cannot find -lbpf`

```bash
sudo apt install libbpf-dev libelf-dev zlib1g-dev
```

### `error: unknown argument: '-target bpf'`

clang is too old or absent. `sudo apt install clang llvm` (need clang 10+).

---

## Loading

### `error: loading BPF object: Invalid argument`

The verifier rejected the program. Get the actual reason:

```bash
sudo ./bin/fwload -i veth-fw -v 2>&1 | tail -60
```

The last few lines before the rejection point at the offending instruction.
Common causes in this codebase if you have been editing:

- **Reading packet data without a bounds check the verifier can follow.** Every
  dereference needs a preceding `if (ptr + size > data_end)` that the verifier
  can connect to *that* dereference.
- **A helper call inside the spin lock.** Nothing between `bpf_spin_lock()` and
  `bpf_spin_unlock()` may call a helper — including `bpf_ktime_get_ns()` and
  any map lookup.
- **Returning while holding the lock.**

### `map_check_btf` / `Invalid argument` mentioning BTF

The object was built without BTF. Ensure `-g` is in `BPF_CFLAGS` — it is
required for the spin lock in `struct src_state`, not just for debugging.

### `map 'srcstate' ... value_size mismatch` or `Invalid argument` after editing common.h

libbpf is trying to reuse the existing pinned map, which has the old layout.

```bash
sudo ./bin/fwload -i veth-fw -u
make && sudo ./bin/fwload -i veth-fw
# or simply: make reload
```

### `error: attaching to veth-fw: Device or resource busy`

Another XDP program is attached.

```bash
sudo ip link set dev veth-fw xdp off
sudo ./bin/fwload -i veth-fw
```

### `note: native XDP attach failed; falling back to generic`

The driver has no native XDP support. Common for emulated `e1000` NICs in
VirtualBox/VMware.

- On **veth** (the testbed), native should work. If it does not, check that
  both ends are `up` and that offloads are off — `setup_netns.sh` does both.
- On the **VM's real NIC**, switch the adapter type to `virtio-net` in your
  hypervisor, or accept generic mode.

Generic mode is functionally identical but much slower, because it runs
*after* `sk_buff` allocation.

### `/sys/fs/bpf does not exist`

```bash
sudo mount -t bpf bpf /sys/fs/bpf
echo 'bpffs /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab
```

### Map creation fails with `Operation not permitted` on an older kernel

Kernels before 5.11 charge BPF memory to `RLIMIT_MEMLOCK`. The loader raises
it automatically; if it still fails, run `ulimit -l unlimited` first.

---

## Runtime

### `bpf OBJ_GET on /sys/fs/bpf/adaptfw/... failed: No such file or directory`

The firewall is not loaded. `sudo ./bin/fwload -i veth-fw`

### `... failed: Operation not permitted`

Not root. Every control-plane command needs `sudo`.

### Counters stay at zero while traffic is flowing

1. **Wrong interface.** XDP only sees traffic arriving *on the interface it is
   attached to*. Confirm with `ip link show veth-fw | grep xdp`.
2. **Traffic is not actually arriving.** `sudo tcpdump -ni veth-fw -c 5`.
3. **You are testing from the wrong side.** Traffic must come *from* the
   namespace *to* `veth-fw`. Prefix generator commands with
   `sudo ip netns exec fwtest`.

### Packet counts far lower than what you sent

GRO/GSO is aggregating frames before XDP sees them. Re-run
`sudo ./bench/setup_netns.sh`, which disables offloads, or by hand:

```bash
sudo ethtool -K veth-fw gro off gso off tso off
sudo ip netns exec fwtest ethtool -K veth-cl gro off gso off tso off
```

### `srcstate map full` warnings

Expected under heavy source spoofing — see ARCHITECTURE.md §3. Either raise
`MAX_TRACKED` in `bpf/common.h` (then `make reload`) or lower
`STATE_IDLE_TIMEOUT_S` in `control/schema.py` so the sweep reclaims faster.

### A block never expires

Almost always a clock mismatch. The kernel uses `CLOCK_MONOTONIC`
(`bpf_ktime_get_ns`), so userspace must use `time.monotonic_ns()`. Using
`time.time()` puts the deadline about fifty years in the future.

`sudo python3 -m control.fwctl selftest` checks for exactly this: it inserts a
5-second block and asserts the remaining time is about 5 seconds.

### The controller blocks something it should not

```bash
sudo python3 -m control.fwctl allow add <ip>      # permanent immunity
sudo python3 -m control.controller --dry-run       # diagnose without enforcing
sudo python3 -m control.controller --confidence 0.9  # demand more certainty
```

Raise `CONSECUTIVE_WINDOWS_TO_BLOCK` in `control/policy.py` for more
hysteresis.

### `feature mismatch between the trained model and the current code`

You changed `schema.FEATURE_NAMES` after training. Retrain:

```bash
python3 -m control.train --synthetic
```

---

## Measurement

### hping3 gives far fewer pps than expected

`hping3 --flood` is single-threaded and tops out around 50–150 k pps in a VM.
That is usually enough to show the effect. For higher rates use kernel
pktgen, or run several hping3 instances with different spoofed sources:

```bash
for ip in 10.10.1.2 10.10.1.3 10.10.1.4; do
  sudo ip netns exec fwtest hping3 --flood -S -a $ip -p 80 10.10.1.1 &
done
```

### CPU shows one core at 100% and the rest idle

Expected. veth has a single receive queue, so all softirq processing lands on
one core. Report per-core figures, not just the average, and explain why.

### Results vary a lot between runs

A VM on a Windows host is descheduled by the host scheduler. Mitigate by:
closing other Windows applications, using `--repeat 5` and reporting the
median, pinning the VM to specific host cores if your hypervisor allows, and
disabling dynamic CPU frequency scaling in the guest.

---

## Full reset

When something is wedged and you want a clean slate:

```bash
sudo ./bin/fwload -i veth-fw -u          # detach and unpin
sudo ./bench/teardown_netns.sh           # remove the testbed
sudo ./bench/nftables_baseline.sh remove # remove nft rules
sudo rm -rf /sys/fs/bpf/adaptfw          # force-clear pins
make clean && make
sudo ./bench/setup_netns.sh
sudo ./bin/fwload -i veth-fw
sudo python3 -m control.fwctl selftest
```
