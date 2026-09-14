"""
Userspace control plane for the Adaptive XDP/eBPF firewall.

Module map (read them in this order to understand the system):

    schema.py      byte layouts mirroring bpf/common.h -- the contract
    bpfmap.py      raw bpf(2) syscall wrapper; talks bytes to the kernel
    firewall.py    typed access to the five pinned maps
    features.py    cumulative counters -> per-second behavioural features
    model.py       Random Forest detector + the threshold baseline
    policy.py      verdicts -> map writes, under safety rails
    controller.py  the 1 Hz adaptive loop (run this)
    fwctl.py       manual CLI (run this)
    collect.py     capture labelled training data
    train.py       fit and evaluate the model
"""

__version__ = "1.0.0"
