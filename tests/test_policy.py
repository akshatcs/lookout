"""Offline tests for the decision logic. No root or kernel needed.

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from control.detect import Window, classify               # noqa: E402
from control.firewall import (lpm_key, port_key, unpack_cidr,  # noqa: E402
                              PORT_KEY)
from control.policy import Aggressiveness, Blocker        # noqa: E402

SEC = 10**9


def state(packets=0, bytes=0, syn=0, fin=0, rst=0, icmp=0, dropped=0, ports=0):
    return {"packets": packets, "bytes": bytes, "syn": syn, "fin": fin,
            "rst": rst, "icmp": icmp, "dropped": dropped, "port_bitmap": ports}


class FakeFirewall:
    def __init__(self, allowed=()):
        self.allowed = set(allowed)
        self.blocks = {}

    def is_allowed(self, ip):
        return ip in self.allowed

    def block(self, ip, duration, reason=0):
        self.blocks[ip] = duration


class TestWindow(unittest.TestCase):
    def test_first_call_is_baseline(self):
        self.assertEqual(Window().update({"a": state(10, 640)}, 0), {})

    def test_rates_come_from_differences(self):
        w = Window()
        w.update({"a": state(100, 6400, syn=100)}, 0)
        row = w.update({"a": state(1100, 70400, syn=1100)}, 2 * SEC)["a"]
        self.assertAlmostEqual(row["pps"], 500)
        self.assertAlmostEqual(row["mean_len"], 64)
        self.assertAlmostEqual(row["syn_ratio"], 1.0)
        self.assertAlmostEqual(row["syn_fin_ratio"], 1000)

    def test_idle_sources_are_skipped(self):
        w = Window()
        w.update({"a": state(5, 300)}, 0)
        self.assertEqual(w.update({"a": state(5, 300)}, SEC), {})

    def test_recreated_entry_counts_from_zero(self):
        w = Window()
        w.update({"a": state(1000, 64000)}, 0)
        row = w.update({"a": state(10, 640)}, SEC)["a"]
        self.assertEqual(row["pps"], 10)


class TestClassify(unittest.TestCase):
    def row(self, **kw):
        r = dict(pps=50, mean_len=500, syn_ratio=0.01, syn_fin_ratio=1,
                 icmp_ratio=0, port_spread=1, drop_ratio=0)
        r.update(kw)
        return r

    def test_normal_traffic(self):
        self.assertIsNone(classify(self.row()))

    def test_bulk_download_is_not_a_flood(self):
        self.assertIsNone(classify(self.row(pps=50000, mean_len=1400)))

    def test_floods_and_scans(self):
        self.assertEqual(classify(self.row(pps=50000, mean_len=60)), "volumetric flood")
        self.assertEqual(classify(self.row(pps=200, mean_len=54, syn_ratio=1,
                                           syn_fin_ratio=200)), "syn flood")
        self.assertEqual(classify(self.row(port_spread=40, mean_len=60)), "port scan")
        self.assertEqual(classify(self.row(pps=3000, mean_len=98, icmp_ratio=1)),
                         "icmp flood")

    def test_syn_scan_is_named_a_scan(self):
        self.assertEqual(classify(self.row(pps=500, mean_len=54, syn_ratio=1,
                                           syn_fin_ratio=500, port_spread=60)),
                         "port scan")

    def test_busy_server_with_closing_connections(self):
        # high SYN share, but every connection is closed again
        self.assertIsNone(classify(self.row(syn_ratio=0.4, syn_fin_ratio=1.2)))


class TestBlocker(unittest.TestCase):
    def test_needs_two_windows_in_a_row(self):
        fw = FakeFirewall()
        b = Blocker(fw)
        b.update({"x": "syn flood"})
        self.assertEqual(fw.blocks, {})
        b.update({"x": "syn flood"})
        self.assertEqual(fw.blocks, {"x": 60})

    def test_a_clean_window_resets_the_count(self):
        fw = FakeFirewall()
        b = Blocker(fw)
        for verdict in ("syn flood", None, "syn flood"):
            b.update({"x": verdict})
        self.assertEqual(fw.blocks, {})

    def test_allowlisted_source_is_never_blocked(self):
        fw = FakeFirewall(allowed={"x"})
        b = Blocker(fw)
        for _ in range(5):
            b.update({"x": "volumetric flood"})
        self.assertEqual(fw.blocks, {})

    def test_repeat_offenders_get_longer_blocks(self):
        fw = FakeFirewall()
        b = Blocker(fw)
        durations = []
        for _ in range(3):
            b.update({"x": "f"})
            b.update({"x": "f"})
            durations.append(fw.blocks["x"])
            b.until.clear()             # pretend the block expired
        self.assertEqual(durations, [60, 300, 900])

    def test_new_blocks_per_window_are_capped(self):
        fw = FakeFirewall()
        b = Blocker(fw)
        flagged = {f"10.0.{i // 256}.{i % 256}": "f" for i in range(100)}
        b.update(flagged)
        b.update(flagged)
        self.assertEqual(len(fw.blocks), Blocker.MAX_PER_WINDOW)

    def test_dry_run_writes_nothing(self):
        fw = FakeFirewall()
        b = Blocker(fw, dry_run=True)
        b.update({"x": "f"})
        b.update({"x": "f"})
        self.assertEqual(fw.blocks, {})
        self.assertIn("WOULD BLOCK x", b.log[-1][1])


class TestAggressiveness(unittest.TestCase):
    def test_escalates_at_once_and_can_skip_tiers(self):
        a = Aggressiveness()
        self.assertTrue(a.update(300000, 0))
        self.assertEqual(a.level, 3)
        self.assertEqual(a.limits, (200, 400))

    def test_high_drop_ratio_alone_escalates(self):
        a = Aggressiveness()
        a.update(1000, 0.9)
        self.assertEqual(a.level, 2)

    def test_relaxes_slowly_one_tier_at_a_time(self):
        a = Aggressiveness()
        a.update(300000, 0)
        for _ in range(4):
            a.update(0, 0)
        self.assertEqual(a.level, 3)    # four calm seconds is not enough
        a.update(0, 0)
        self.assertEqual(a.level, 2)    # fifth one drops a single tier


class TestKeys(unittest.TestCase):
    def test_cidr_round_trip_keeps_network_byte_order(self):
        self.assertEqual(unpack_cidr(lpm_key("10.10.1.3")), "10.10.1.3/32")
        self.assertEqual(unpack_cidr(lpm_key("8.8.8.0/24")), "8.8.8.0/24")
        self.assertEqual(lpm_key("10.0.0.0/8")[4:], bytes([10, 0, 0, 0]))

    def test_host_bits_are_cleared(self):
        self.assertEqual(unpack_cidr(lpm_key("10.0.0.5/24")), "10.0.0.0/24")

    def test_bad_addresses_are_rejected(self):
        for bad in ("10.1", "300.1.1.1", "10.0.0.0/33", "fe80::1", ""):
            with self.assertRaises(ValueError):
                lpm_key(bad)

    def test_port_keys(self):
        import struct
        self.assertEqual(struct.unpack(PORT_KEY, port_key("tcp", 23)), (6, 23))
        self.assertEqual(struct.unpack(PORT_KEY, port_key("UDP", 53)), (17, 53))
        self.assertEqual(struct.unpack(PORT_KEY, port_key("icmp", 8)), (1, 8))
        self.assertEqual(struct.unpack(PORT_KEY, port_key("47", 0)), (47, 0))
        self.assertEqual(port_key("tcp", 23)[1], 0)     # pad byte is zero

    def test_bad_port_rules_are_rejected(self):
        for proto, port in (("tcp", 70000), ("icmp", 300), ("sctpx", 1), ("tcp", -1)):
            with self.assertRaises(ValueError):
                port_key(proto, port)


if __name__ == "__main__":
    unittest.main()
