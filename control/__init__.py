"""Userspace side of the XDP firewall.

    bpfmap.py      bpf(2) syscall wrapper for pinned maps
    firewall.py    map layouts and typed access to the five maps
    detect.py      per-second behaviour of each source, and the attack rules
    policy.py      load-driven rate tiers and the auto-blocker
    controller.py  the 1 Hz adaptive loop (run this)
    fwctl.py       manual command-line control (run this)
"""
