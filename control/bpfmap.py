"""
bpfmap.py -- talk to pinned BPF maps from Python using the raw bpf() syscall.

============================================================================
WHY ctypes AND NOT A LIBRARY
============================================================================
There are two usual ways to reach BPF maps from Python: BCC (which drags in a
runtime LLVM toolchain and compiles C at import time) or a ctypes binding to
libbpf.so (which then depends on which libbpf the linux distro shipped).

We do neither. Every operation we need -- open a pinned map, look up, update,
delete, iterate -- is a single `bpf(2)` syscall, and calling a syscall through
ctypes is about eighty lines of code with no dependencies at all.

The practical payoff is that this file works identically on Ubuntu 22.04 and
24.04 and inside any container, and the educational payoff is that we can see
exactly what the kernel interface looks like: one syscall number, one command
enum, one union of argument structs.

============================================================================
HOW bpf(2) WORKS
============================================================================
    int bpf(int cmd, union bpf_attr *attr, unsigned int size);

`attr` is a big union defined in <linux/bpf.h>. Each command uses a different
member of it. We only define the two members we need.

Forward/backward compatibility is handled by `size`: the kernel zero-fills
anything past the size we pass, and rejects the call if we pass a longer
struct whose tail is not zero. So passing the historical (smaller) size of a
member is always safe, even on a newer kernel that has grown extra fields.

Everything here requires root (or CAP_BPF + CAP_NET_ADMIN), because
/sys/fs/bpf is root-owned and map access is privileged.
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import struct

# ---------------------------------------------------------------------------
# Syscall plumbing
# ---------------------------------------------------------------------------

_NR_BPF_BY_ARCH = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
    "i686": 357,
    "ppc64le": 361,
    "s390x": 351,
    "riscv64": 280,
}

_MACHINE = platform.machine()
if _MACHINE not in _NR_BPF_BY_ARCH:
    raise RuntimeError(
        f"unknown architecture '{_MACHINE}': add its bpf() syscall number to "
        f"_NR_BPF_BY_ARCH in control/bpfmap.py "
        f"(look it up in the kernel's syscall table)"
    )
NR_BPF = _NR_BPF_BY_ARCH[_MACHINE]

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
# Deliberately no argtypes: syscall() is variadic, and leaving argtypes unset
# lets ctypes pass each argument in its natural form.

# bpf() command numbers from <linux/bpf.h>, enum bpf_cmd.
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_OBJ_GET = 7

# Update flags.
BPF_ANY = 0      # create or overwrite
BPF_NOEXIST = 1  # create only; fail if the key exists
BPF_EXIST = 2    # overwrite only; fail if the key does not exist
BPF_F_LOCK = 4   # take the value's bpf_spin_lock during the operation


class _AttrObj(ctypes.Structure):
    """union bpf_attr member used by BPF_OBJ_GET / BPF_OBJ_PIN."""

    _fields_ = [
        ("pathname", ctypes.c_uint64),  # __aligned_u64 pointer to a C string
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class _AttrElem(ctypes.Structure):
    """union bpf_attr member used by every BPF_MAP_*_ELEM command.

    Layout from <linux/bpf.h>:
        __u32 map_fd;          (plus 4 bytes of alignment padding)
        __aligned_u64 key;
        union { __aligned_u64 value; __aligned_u64 next_key; };
        __u64 flags;
    """

    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),  # doubles as next_key
        ("flags", ctypes.c_uint64),
    ]


def _bpf(cmd, attr):
    """Invoke bpf(2). Returns the syscall result; -1 on error with errno set."""
    ctypes.set_errno(0)
    return _libc.syscall(
        ctypes.c_long(NR_BPF),
        ctypes.c_long(cmd),
        ctypes.byref(attr),
        ctypes.c_ulong(ctypes.sizeof(attr)),
    )


def _addr_of(buf):
    """Address of a ctypes buffer as an integer, or 0 for None (== NULL)."""
    if buf is None:
        return 0
    return ctypes.cast(buf, ctypes.c_void_p).value


class BpfError(OSError):
    """A bpf(2) call failed. Carries the real errno so callers can branch."""


def _fail(op, path_or_fd):
    err = ctypes.get_errno()
    msg = os.strerror(err)
    hint = ""
    if err == errno.EPERM or err == errno.EACCES:
        hint = " (are you root? try sudo)"
    elif err == errno.ENOENT:
        hint = " (is the firewall loaded? run: sudo ./bin/fwload -i <iface>)"
    raise BpfError(err, f"bpf {op} on {path_or_fd} failed: {msg}{hint}")


def obj_get(path: str) -> int:
    """Open a pinned BPF object by path and return a file descriptor."""
    cpath = ctypes.create_string_buffer(path.encode())
    attr = _AttrObj(pathname=_addr_of(cpath), bpf_fd=0, file_flags=0)
    fd = _bpf(BPF_OBJ_GET, attr)
    if fd < 0:
        _fail("OBJ_GET", path)
    return int(fd)


def num_possible_cpus() -> int:
    """Number of CPU slots the kernel allocates per-CPU map values for.

    This is `possible` CPUs, not `online` ones -- a per-CPU map value is sized
    for every slot the kernel could ever bring online, so reading one with the
    online count gives us a short buffer and an EFAULT.
    """
    try:
        with open("/sys/devices/system/cpu/possible") as f:
            spec = f.read().strip()
    except OSError:
        return os.cpu_count() or 1

    total = 0
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            total += int(hi) - int(lo) + 1
        else:
            total += 1
    return max(total, 1)


class BpfMap:
    """A pinned BPF map, opened by path.

    Values and keys are handled as raw `bytes`; encoding and decoding lives in
    schema.py. That separation is intentional -- this class knows about the
    kernel interface, schema.py knows about our data, and neither needs to
    know about the other.
    """

    def __init__(self, name, key_size, value_size, pin_dir=None, percpu=False):
        from . import schema  # local import keeps this module dependency-free

        pin_dir = pin_dir or schema.PIN_DIR
        self.path = os.path.join(pin_dir, name)
        self.name = name
        self.key_size = key_size
        self.value_size = value_size
        self.percpu = percpu

        # A per-CPU map value is an array of per-CPU slots, each rounded up to
        # 8 bytes. Reading it with a buffer sized for one CPU returns EFAULT,
        # which is an unhelpful error to debug from scratch.
        if percpu:
            self.ncpu = num_possible_cpus()
            self.buf_size = ((value_size + 7) // 8 * 8) * self.ncpu
        else:
            self.ncpu = 1
            self.buf_size = value_size

        self.fd = obj_get(self.path)

    def close(self):
        if getattr(self, "fd", None) is not None and self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- single element operations -----------------------------------------

    def lookup(self, key: bytes, flags: int = 0):
        """Return the raw value bytes, or None if the key is absent.

        For maps whose value contains a bpf_spin_lock, pass flags=BPF_F_LOCK
        so the kernel takes the lock while copying. Without it we can observe
        a half-updated value -- rare, but it shows up as a nonsensical packet
        count exactly once every few thousand reads, which is a miserable bug
        to chase.
        """
        assert len(key) == self.key_size, (
            f"{self.name}: key is {len(key)} bytes, map wants {self.key_size}"
        )
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        vbuf = ctypes.create_string_buffer(self.buf_size)
        attr = _AttrElem(
            map_fd=self.fd,
            key=_addr_of(kbuf),
            value=_addr_of(vbuf),
            flags=flags,
        )
        if _bpf(BPF_MAP_LOOKUP_ELEM, attr) < 0:
            if ctypes.get_errno() == errno.ENOENT:
                return None
            _fail("MAP_LOOKUP_ELEM", self.path)
        return vbuf.raw[: self.buf_size]

    def update(self, key: bytes, value: bytes, flags: int = BPF_ANY):
        assert len(key) == self.key_size, (
            f"{self.name}: key is {len(key)} bytes, map wants {self.key_size}"
        )
        assert len(value) == self.buf_size, (
            f"{self.name}: value is {len(value)} bytes, map wants "
            f"{self.buf_size}"
        )
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        vbuf = ctypes.create_string_buffer(value, self.buf_size)
        attr = _AttrElem(
            map_fd=self.fd,
            key=_addr_of(kbuf),
            value=_addr_of(vbuf),
            flags=flags,
        )
        if _bpf(BPF_MAP_UPDATE_ELEM, attr) < 0:
            err = ctypes.get_errno()
            if err == errno.E2BIG:
                raise BpfError(
                    err,
                    f"{self.name} is full -- no room for another entry. "
                    f"Raise max_entries in bpf/common.h, or let the control "
                    f"plane's garbage collector catch up.",
                )
            _fail("MAP_UPDATE_ELEM", self.path)

    def delete(self, key: bytes) -> bool:
        """Remove a key. Returns False if it was not there."""
        kbuf = ctypes.create_string_buffer(key, self.key_size)
        attr = _AttrElem(map_fd=self.fd, key=_addr_of(kbuf), value=0, flags=0)
        if _bpf(BPF_MAP_DELETE_ELEM, attr) < 0:
            if ctypes.get_errno() == errno.ENOENT:
                return False
            _fail("MAP_DELETE_ELEM", self.path)
        return True

    # -- iteration ---------------------------------------------------------

    def keys(self):
        """Yield every key currently in the map, as raw bytes.

        Iteration walks the map with BPF_MAP_GET_NEXT_KEY, starting from a
        NULL key to mean "give me the first one". The kernel gives no ordering
        guarantee and the map can change underneath us.

        IMPORTANT: never delete while iterating. Deleting the key we are
        standing on can make the kernel restart the walk from the beginning,
        which turns a cleanup pass into an infinite loop. Every caller in this
        project collects keys into a list first, then deletes. See
        `items()` and the GC sweep in controller.py.
        """
        cur = None
        nbuf = ctypes.create_string_buffer(self.key_size)
        # Hard bound: a corrupt walk cannot hang the control plane forever.
        limit = 4 * 1024 * 1024

        for _ in range(limit):
            attr = _AttrElem(
                map_fd=self.fd,
                key=_addr_of(cur),
                value=_addr_of(nbuf),  # `value` doubles as next_key
                flags=0,
            )
            if _bpf(BPF_MAP_GET_NEXT_KEY, attr) < 0:
                if ctypes.get_errno() == errno.ENOENT:
                    return  # walked off the end: we are done
                _fail("MAP_GET_NEXT_KEY", self.path)

            key = nbuf.raw[: self.key_size]
            yield key
            cur = ctypes.create_string_buffer(key, self.key_size)

        raise BpfError(
            errno.ERANGE,
            f"{self.name}: iteration exceeded {limit} keys; aborting",
        )

    def items(self, flags: int = 0):
        """Yield (key, value) pairs. Snapshots keys first, so it is safe to
        delete entries as we consume the results."""
        for key in list(self.keys()):
            val = self.lookup(key, flags=flags)
            if val is not None:  # may have been evicted between the two calls
                yield key, val

    def count(self) -> int:
        return sum(1 for _ in self.keys())

    # -- per-CPU helpers ---------------------------------------------------

    def sum_percpu_u64(self, key: bytes) -> int:
        """Sum a per-CPU __u64 counter across every CPU slot."""
        raw = self.lookup(key)
        if raw is None:
            return 0
        return sum(struct.unpack_from("<Q", raw, i * 8) [0]
                   for i in range(self.ncpu))
