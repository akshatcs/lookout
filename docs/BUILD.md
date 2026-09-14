# BUILD.md — setup on an Ubuntu Server VM

Assumes a fresh Ubuntu Server 24.04 VM on a Windows host, reached
with `ssh devuser@127.0.0.1 -p 2222`.

---

## 1. Requirements

| | Minimum | Recommended |
|---|---|---|
| Kernel | 5.10 | 5.15+ (`uname -r`) |
| vCPUs | 2 | 4 - per-CPU counters and CPU measurement are more meaningful |
| RAM | 2 GB | 4 GB - the `srcstate` map alone preallocates 4 MiB |
| Disk | 4 GB | 8 GB |

Check your kernel:

```bash
uname -r          # need 5.10 or newer
zgrep -E "CONFIG_BPF_SYSCALL|CONFIG_XDP_SOCKETS" /proc/config.gz 2>/dev/null || \
  grep -E "CONFIG_BPF_SYSCALL|CONFIG_XDP_SOCKETS" /boot/config-$(uname -r)
```

Both should say `=y`. Every stock Ubuntu kernel since 20.04 has them.

---

## 2. Install dependencies

```bash
cd ~/adaptive-xdp-firewall
./scripts/install_deps.sh
```

It installs clang/LLVM, libbpf-dev, bpftool, hping3, iperf3, nftables,
sysstat, tmux, and scikit-learn, then mounts bpffs and verifies everything.

Make bpffs permanent so it survives reboot:

```bash
echo 'bpffs /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab
```

---

## 3. Build

```bash
make
```

```
  CLANG-BPF  bpf/firewall.bpf.o
             37200 bytes
  CC         bin/fwload
```

Two artefacts:

- `bpf/firewall.bpf.o` — the eBPF program, compiled for the `bpf` pseudo-target
- `bin/fwload` — the userspace loader, linked against libbpf

Verify the C and Python struct definitions still agree:

```bash
make check-schema
```

```
checking C struct sizes...
8 16 24 128 32
checking Python mirrors...
schema.py OK
```

Those numbers are `lpm_key`, `allow_val`, `block_val`, `src_state`,
`fw_config`. **Run this after every edit to `bpf/common.h`.**

---

## 4. Train the model (optional)

```bash
make model
```

Writes `models/rf_model.joblib` (~200 KB) and `models/metrics.json`, and
prints the full comparison against the threshold baseline.

Without scikit-learn the firewall still works — run the controller with
`--no-ml`.

---

## 5. Run the offline test

```bash
make test
```

No root required. Verifies features → model → policy, and asserts allowlist
immunity, hysteresis, and that benign traffic is left alone.

---

## 6. Bring up the testbed and load

```bash
sudo ./bench/setup_netns.sh
sudo ./bin/fwload -i veth-fw
sudo python3 -m control.fwctl selftest
```

`selftest` must end with **self-test passed**.

---

## 7. About the build flags

Three flags in the Makefile are not optional:

**`-target bpf`** — compile to BPF bytecode rather than x86.

**`-g`** — emits BTF type information. This is *required*, not a debugging
convenience: the kernel needs BTF to permit a `bpf_spin_lock` inside a map
value. Without it the load fails with a `map_check_btf` error.

**`-I/usr/include/$(uname -m)-linux-gnu`** — the kernel's `asm/` headers live
in an architecture-specific directory. Without this, `<linux/ip.h>` cannot
resolve `<asm/types.h>`.

### The `gnu/stubs-32.h` error

If you add an `#include` and hit:

```
fatal error: 'gnu/stubs-32.h' file not found
```

you have included a header that pulls in `<linux/if.h>` → glibc's
`<sys/socket.h>`, which misbehaves under `-target bpf`. `<linux/if_vlan.h>`
and `<linux/icmp.h>` both do this.

Options: install `gcc-multilib`, generate `vmlinux.h` with bpftool and use
CO-RE, or declare the struct you need yourself. **We chose the third** — see
the header note at the top of `bpf/firewall.bpf.c`, which declares `vlan_hdr`
and `icmphdr_min` locally.

---

## 8. Clean rebuild

```bash
make clean && make
```

If you changed `bpf/common.h`, **unload first**. libbpf reuses pinned maps by
path, and refuses to reuse one whose value size changed:

```bash
make reload      # unload, rebuild, load
```

---

## 9. Optional: a persistent systemd unit

For a longer demo you may want the firewall to load at boot.

`/etc/systemd/system/adaptfw.service`:

```ini
[Unit]
Description=Adaptive XDP/eBPF firewall
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/devuser/adaptive-xdp-firewall
ExecStart=/home/devuser/adaptive-xdp-firewall/bin/fwload -i veth-fw
ExecStop=/home/devuser/adaptive-xdp-firewall/bin/fwload -i veth-fw -u

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now adaptfw
```

Optional, but it demonstrates the point that the data plane and control plane have independent lifecycles.
