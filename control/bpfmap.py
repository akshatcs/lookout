"""Minimal access to pinned BPF maps and programs through the bpf(2) syscall.

Every operation we need (open a pinned object, lookup, update, delete, walk
the keys, read many entries at once, read a program's info) is a single
syscall, so calling it through ctypes avoids depending on BCC or on whichever
libbpf version the distro ships. Needs root.

Keys and values are raw bytes here; firewall.py knows the layouts.
"""

import ctypes
import errno
import os
import platform
import struct

NR_BPF = {
    "x86_64": 321, "aarch64": 280, "riscv64": 280,
    "armv7l": 386, "i686": 357, "ppc64le": 361, "s390x": 351,
}[platform.machine()]

# enum bpf_cmd
MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM, MAP_DELETE_ELEM, MAP_GET_NEXT_KEY = 1, 2, 3, 4
OBJ_GET = 7
OBJ_GET_INFO_BY_FD = 15
MAP_LOOKUP_BATCH = 24
ENOTSUPP = 524      # kernel-internal errno some map types return for batch ops

BPF_ANY = 0
BPF_F_LOCK = 4      # copy the value while holding its bpf_spin_lock

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


class _ObjAttr(ctypes.Structure):
    # the BPF_OBJ_GET member of union bpf_attr
    _fields_ = [("pathname", ctypes.c_uint64),
                ("bpf_fd", ctypes.c_uint32),
                ("file_flags", ctypes.c_uint32)]


class _ElemAttr(ctypes.Structure):
    # the BPF_MAP_*_ELEM member; `value` doubles as next_key
    _fields_ = [("map_fd", ctypes.c_uint32),
                ("_pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64),
                ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class _BatchAttr(ctypes.Structure):
    # the BPF_MAP_*_BATCH member
    _fields_ = [("in_batch", ctypes.c_uint64),
                ("out_batch", ctypes.c_uint64),
                ("keys", ctypes.c_uint64),
                ("values", ctypes.c_uint64),
                ("count", ctypes.c_uint32),
                ("map_fd", ctypes.c_uint32),
                ("elem_flags", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class _InfoAttr(ctypes.Structure):
    # the BPF_OBJ_GET_INFO_BY_FD member
    _fields_ = [("bpf_fd", ctypes.c_uint32),
                ("info_len", ctypes.c_uint32),
                ("info", ctypes.c_uint64)]


class BpfError(OSError):
    pass


def _bpf(cmd, attr):
    # The kernel zero-fills anything past the size we pass, so these short
    # versions of bpf_attr work on newer kernels too.
    return _libc.syscall(ctypes.c_long(NR_BPF), ctypes.c_long(cmd),
                         ctypes.byref(attr), ctypes.c_ulong(ctypes.sizeof(attr)))


def _addr(buf):
    return ctypes.addressof(buf) if buf is not None else 0


def _raise(op, what):
    err = ctypes.get_errno()
    hint = ""
    if err in (errno.EPERM, errno.EACCES):
        hint = " (run with sudo)"
    elif err == errno.ENOENT:
        hint = " (is the firewall loaded? sudo ./bin/fwload -i veth-fw)"
    raise BpfError(err, f"{op} {what}: {os.strerror(err)}{hint}")


def possible_cpus():
    """Per-CPU map values have one slot per *possible* CPU, which can be
    more than the online count. Sizing the buffer by online CPUs gives
    EFAULT."""
    try:
        with open("/sys/devices/system/cpu/possible") as f:
            spec = f.read().strip()
    except OSError:
        return os.cpu_count() or 1
    n = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        n += int(hi or lo) - int(lo) + 1
    return n


def _open_pinned(path):
    cpath = ctypes.create_string_buffer(path.encode())
    ctypes.set_errno(0)
    fd = _bpf(OBJ_GET, _ObjAttr(pathname=_addr(cpath)))
    if fd < 0:
        _raise("open", path)
    return fd


class _Pinned:
    fd = -1

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class BpfProg(_Pinned):
    """A pinned program. Only used to read struct bpf_prog_info."""

    # Offsets into struct bpf_prog_info (include/uapi/linux/bpf.h). They
    # have been stable since the fields were added; older kernels fill a
    # shorter struct and leave the rest zero.
    INFO_SIZE = 232

    def __init__(self, path):
        self.path = path
        self.fd = _open_pinned(path)

    def info(self):
        buf = ctypes.create_string_buffer(self.INFO_SIZE)
        attr = _InfoAttr(bpf_fd=self.fd, info_len=self.INFO_SIZE, info=_addr(buf))
        ctypes.set_errno(0)
        if _bpf(OBJ_GET_INFO_BY_FD, attr) < 0:
            _raise("read info of", self.path)
        raw = buf.raw
        u32 = lambda off: struct.unpack_from("<I", raw, off)[0]
        u64 = lambda off: struct.unpack_from("<Q", raw, off)[0]
        return {
            "id": u32(4),
            "tag": raw[8:16].hex(),
            "jited_bytes": u32(16),     # native machine code
            "xlated_bytes": u32(20),    # BPF bytecode after the verifier
            "name": raw[64:80].split(b"\0")[0].decode(),
            "run_time_ns": u64(192),    # 0 unless kernel.bpf_stats_enabled=1
            "run_cnt": u64(200),
        }


class BpfMap(_Pinned):
    def __init__(self, path, key_size, value_size, percpu=False):
        self.path = path
        self.key_size = key_size
        if percpu:
            self.ncpu = possible_cpus()
            self.value_size = ((value_size + 7) // 8 * 8) * self.ncpu
        else:
            self.ncpu = 1
            self.value_size = value_size
        self.fd = _open_pinned(path)

    def _elem(self, cmd, key, value=None, flags=0):
        kbuf = ctypes.create_string_buffer(key, self.key_size) if key else None
        attr = _ElemAttr(map_fd=self.fd, key=_addr(kbuf),
                         value=_addr(value), flags=flags)
        ctypes.set_errno(0)
        return _bpf(cmd, attr)

    def lookup(self, key, flags=0):
        """Value bytes for key, or None. Pass BPF_F_LOCK for values that
        hold a spin lock, otherwise a read can catch a half-done update."""
        vbuf = ctypes.create_string_buffer(self.value_size)
        if self._elem(MAP_LOOKUP_ELEM, key, vbuf, flags) < 0:
            if ctypes.get_errno() == errno.ENOENT:
                return None
            _raise("lookup in", self.path)
        return vbuf.raw

    def update(self, key, value, flags=BPF_ANY):
        assert len(value) == self.value_size, (self.path, len(value))
        vbuf = ctypes.create_string_buffer(value, self.value_size)
        if self._elem(MAP_UPDATE_ELEM, key, vbuf, flags) < 0:
            if ctypes.get_errno() == errno.E2BIG:
                raise BpfError(errno.E2BIG, f"{self.path} is full")
            _raise("update in", self.path)

    def delete(self, key):
        """True if the key existed."""
        if self._elem(MAP_DELETE_ELEM, key) < 0:
            if ctypes.get_errno() == errno.ENOENT:
                return False
            _raise("delete in", self.path)
        return True

    def keys(self):
        """All keys, as a list.

        Returned as a list rather than yielded so callers can delete while
        looping: deleting the key the kernel walk is standing on can restart
        the walk from the beginning.
        """
        out, cur = [], None
        nxt = ctypes.create_string_buffer(self.key_size)
        while True:
            if self._elem(MAP_GET_NEXT_KEY, cur, nxt) < 0:
                if ctypes.get_errno() == errno.ENOENT:
                    return out
                _raise("walk", self.path)
            cur = nxt.raw
            out.append(cur)
            if len(out) > 1 << 20:
                raise BpfError(errno.ERANGE, f"{self.path}: runaway key walk")

    def items(self, flags=0):
        """All (key, value) pairs. Read in batches of thousands per syscall
        where the kernel supports it (5.6+); a key-by-key walk costs two
        syscalls per entry, a third of a second for a full srcstate map."""
        batch = self._batch(flags)
        if batch is not None:
            return batch
        out = []
        for key in self.keys():
            val = self.lookup(key, flags)
            if val is not None:     # it may have gone since keys() ran
                out.append((key, val))
        return out

    def _batch(self, flags, chunk=4096):
        """Every entry via BPF_MAP_LOOKUP_BATCH, or None if not supported."""
        ks, vs = self.key_size, self.value_size
        keys = ctypes.create_string_buffer(ks * chunk)
        vals = ctypes.create_string_buffer(vs * chunk)
        token_in, token_out = ctypes.create_string_buffer(8), ctypes.create_string_buffer(8)
        out, first = [], True
        while True:
            attr = _BatchAttr(in_batch=0 if first else _addr(token_in),
                              out_batch=_addr(token_out), keys=_addr(keys),
                              values=_addr(vals), count=chunk, map_fd=self.fd,
                              elem_flags=flags)
            ctypes.set_errno(0)
            rc = _bpf(MAP_LOOKUP_BATCH, attr)
            err = ctypes.get_errno()
            if attr.count:
                kraw, vraw = keys.raw, vals.raw
                out += [(kraw[i * ks:(i + 1) * ks], vraw[i * vs:(i + 1) * vs])
                        for i in range(attr.count)]
            if rc < 0:
                if err == errno.ENOENT:         # that was the last batch
                    return out
                if first and err in (errno.EINVAL, ENOTSUPP):
                    return None
                ctypes.set_errno(err)
                _raise("batch read of", self.path)
            ctypes.memmove(token_in, token_out, 8)
            first = False

    def sum_percpu(self, key):
        """Sum a per-CPU u64 across all CPU slots."""
        raw = self.lookup(key)
        if raw is None:
            return 0
        return sum(struct.unpack_from("<Q", raw, i * 8)[0]
                   for i in range(self.ncpu))


