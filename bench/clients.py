#!/usr/bin/env python3
"""Realistic clients and servers for the evaluation (bench/collateral.sh and
bench/detection.sh). Clients run in the fwtest namespace, servers on the
firewall host.

    clients.py serve DIR [PORT...]        web server on 8080 serving DIR, and a
                                          sink that reads and discards on PORTs
    clients.py probe SECONDS OUT.csv      10 requests/s; logs every one
    clients.py browse SECONDS             a page load (20 requests) every 2 s
    clients.py download SECONDS           fetches a large file over and over
    clients.py upload SECONDS             streams data to the sink on 9000
    clients.py nat SECONDS USERS          USERS people behind one address,
                                          each loading a page every 2 s
    clients.py udp SECONDS PPS            small UDP datagrams to port 53
    clients.py services SECONDS           one short connection a second, each
                                          to a different port (9001...)
    clients.py watch SECONDS OUT.csv      the firewall's rate-limit tier and
                                          blocklist, four times a second

Every client sends from 10.10.1.2 to 10.10.1.1, bound to veth-cl: the
namespace routes 10.10.1.1 through gen0 while the NIC-like path is up
(bench/nic_path.sh), and these clients must use the normal path.
"""

import csv
import http.client
import http.server
import random
import socket
import socketserver
import sys
import threading
import time

SERVER, CLIENT, WEB = "10.10.1.1", "10.10.1.2", 8080
TIMEOUT = 3.0           # a lost SYN is retried after 1 s, then 3 s


def sock(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"veth-cl")
    s.bind((CLIENT, 0))
    return s


def connect(port):
    s = sock()
    s.settimeout(TIMEOUT)
    try:
        s.connect((SERVER, port))
    except OSError:
        s.close()
        raise
    return s


class Conn(http.client.HTTPConnection):
    def connect(self):
        self.sock = connect(WEB)


def get(path="/"):
    """One HTTP request on a new connection. Returns latency in ms."""
    t = time.monotonic()
    c = Conn(SERVER, WEB, timeout=TIMEOUT)
    try:
        c.request("GET", path)
        r = c.getresponse()
        r.read()
        if r.status != 200:
            raise OSError(f"HTTP {r.status}")
    finally:
        c.close()
    return (time.monotonic() - t) * 1000


def every(interval, seconds, fn):
    """Call fn(i) on its own thread every interval seconds, on a fixed
    schedule, so one slow call doesn't delay the next."""
    start, threads, i = time.monotonic(), [], 0
    while (due := start + i * interval) < start + seconds:
        time.sleep(max(0.0, due - time.monotonic()))
        t = threading.Thread(target=fn, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        i += 1
    for t in threads:
        t.join(TIMEOUT + 1)


def quietly(fn, *args):
    try:
        fn(*args)
    except OSError:
        pass


def probe(seconds, out):
    """Logs each request's scheduled wall-clock time, whether it succeeded
    and how long it took, so it lines up with the attack and the watcher."""
    rows, t0 = [], time.time()

    def one(i):
        try:
            rows.append((f"{t0 + i / 10:.2f}", 1, round(get(), 2)))
        except OSError:
            rows.append((f"{t0 + i / 10:.2f}", 0, ""))
    every(0.1, seconds, one)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "ok", "latency_ms"])
        w.writerows(sorted(rows))


def browse(seconds):
    every(2, seconds, lambda i: [threading.Thread(target=quietly, args=(get,)).start()
                                 for _ in range(20)])


def download(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        quietly(get, "/big.bin")


def upload(seconds):
    end, chunk = time.monotonic() + seconds, b"x" * 65536
    with connect(9000) as s:
        s.settimeout(None)
        while time.monotonic() < end:
            s.sendall(chunk)


def nat(seconds, users):
    def user(_):
        time.sleep(random.uniform(0, 2))
        every(2, seconds, lambda i: quietly(get))
    for u in range(users):
        threading.Thread(target=user, args=(u,), daemon=True).start()
    time.sleep(seconds + 2)


def udp(seconds, pps):
    s = sock(socket.SOCK_DGRAM)
    query = b"\x12\x34\x01\x00\x00\x01" + b"\x00" * 6 + b"\x07example\x03com\x00\x00\x01\x00\x01"
    start, n = time.monotonic(), 0
    while (now := time.monotonic()) < start + seconds:
        due = int((now - start) * pps)          # catch up in small batches
        while n < due:
            s.sendto(query, (SERVER, 53))
            n += 1
        time.sleep(0.001)


def services(seconds):
    def one(i):
        with connect(9001 + i % 30) as s:
            s.sendall(b"hello\n")
    every(1, seconds, lambda i: quietly(one, i))


def watch(seconds, out):
    sys.path.insert(0, __file__.rsplit("/", 2)[0] or ".")
    from control.firewall import Firewall
    fw, end = Firewall(), time.time() + seconds
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "tier", "blocked"])
        while time.time() < end:
            w.writerow([f"{time.time():.2f}", fw.read_config()["aggressiveness"],
                        " ".join(b["cidr"] for b in fw.list_blocked())])
            f.flush()
            time.sleep(0.25)


def serve(directory, ports):
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=directory, **k)

        def log_message(self, *a):
            pass

    class Sink(socketserver.BaseRequestHandler):
        def handle(self):
            while self.request.recv(65536):
                pass

    http.server.ThreadingHTTPServer.request_queue_size = 1024
    servers = [http.server.ThreadingHTTPServer((SERVER, WEB), Quiet)]
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    servers += [socketserver.ThreadingTCPServer((SERVER, p), Sink) for p in ports]
    for s in servers:
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    threading.Event().wait()


def main(argv):
    cmd, args = argv[0], argv[1:]
    if cmd == "serve":
        serve(args[0], [int(p) for p in args[1:]])
        return
    seconds = float(args[0])
    {"probe": lambda: probe(seconds, args[1]),
     "browse": lambda: browse(seconds),
     "download": lambda: download(seconds),
     "upload": lambda: upload(seconds),
     "nat": lambda: nat(seconds, int(args[1])),
     "udp": lambda: udp(seconds, int(args[1])),
     "services": lambda: services(seconds),
     "watch": lambda: watch(seconds, args[1])}[cmd]()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(sys.argv[1:])
