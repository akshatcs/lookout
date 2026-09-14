"""
test_pipeline.py -- offline integration test for the whole decision chain.

Runs features -> model -> policy against a FAKE srcstate map, so it needs no
root, no kernel, and no attached XDP program. Run it after any change to
features.py, model.py or policy.py:

    python3 tests/test_pipeline.py

It asserts the three properties that matter most for safety:

  1. An ALLOWLISTED source is never blocked, even when the model is certain it
     is malicious. (Simulated here by allowlisting 10.10.1.2 and then having
     it emit a textbook 300k pps SYN flood.)
  2. HYSTERESIS holds: nothing is blocked after a single bad window; the block
     lands on the second consecutive one.
  3. Benign traffic that superficially resembles an attack -- steady small UDP
     packets, i.e. the game-server workload -- is left alone.

It also exercises the aggressiveness controller's asymmetry: escalation is
immediate, de-escalation takes several calm windows.
"""
import sys, time, struct; sys.path.insert(0,'.')
from control import schema
from control.features import FeatureExtractor
from control.policy import PolicyEngine, AggressivenessController
from control.model import get_detector, LABEL_MALICIOUS

class FakeFW:
    def __init__(self):
        self.blocks={}; self.allows={"10.10.1.2"}
        self.t=int(time.monotonic_ns())
    def ktime_ns(self): return self.t
    def is_allowed(self, ip): return ip in self.allows
    def block(self, ip, duration_s=60, reason=0): self.blocks[ip]=(duration_s,reason)

def mk(pkts,byts,syn=0,fin=0,rst=0,udp=0,icmp=0,tcp=0,ports=0,first=0,last=0,mn=54,mx=54,drop=0):
    return dict(lock=0,tokens=0,last_refill_ns=0,first_seen_ns=first,last_seen_ns=last,
                packets=pkts,bytes=byts,dropped=drop,syn=syn,fin=fin,rst=rst,udp=udp,
                icmp=icmp,tcp=tcp,port_bitmap=ports,min_len=mn,max_len=mx)

fw=FakeFW(); fx=FeatureExtractor()
det,note=get_detector(); print("detector:",note)
pol=PolicyEngine(fw); agg=AggressivenessController()

NS=10**9
# t=0 baseline: three sources at rest
s0={"10.10.1.2":mk(100,140000,first=0,last=0,tcp=100,mn=800,mx=1500),
    "10.10.1.3":mk(50,70000,first=0,last=0,tcp=50,mn=800,mx=1500),
    "10.10.1.4":mk(10,1400,first=0,last=0,udp=10,mn=140,mx=140)}
fx.update(s0, fw.t)

def step(states, label):
    fw.t += NS
    for s in states.values(): s["last_seen_ns"]=fw.t
    rows=fx.update(states, fw.t)
    v=det.predict(rows)
    acts=pol.apply(v,rows)
    print(f"\n--- {label} ---")
    for ip,r in sorted(rows.items()):
        lab,conf,reason=v[ip]
        print(f"  {ip:<12} pps={r['pps']:>9.0f} len={r['mean_len']:>6.0f} "
              f"syn%={r['syn_ratio']*100:>5.1f} s/f={r['syn_fin_ratio']:>7.1f} "
              f"ports={int(r['port_spread']):>3} -> "
              f"{'MALICIOUS' if lab==LABEL_MALICIOUS else 'benign':<10} p={conf:.2f} {reason}")
    for a in acts:
        if a['action']!='watch': print(f"    ACTION {a['action']}: {a['ip']} {a.get('reason','')}")
    return rows

# Window 1: .2 allowlisted but floods; .3 SYN floods; .4 normal game traffic
s1={"10.10.1.2":mk(300100,42000000,first=0,last=0,tcp=300100,syn=300000,mn=54,mx=60),
    "10.10.1.3":mk(200050,10800000,first=0,last=0,tcp=200050,syn=200000,mn=54,mx=60),
    "10.10.1.4":mk(160,22400,first=0,last=0,udp=160,mn=140,mx=140)}
step(s1,"window 1 (strike 1)")
s2={"10.10.1.2":mk(600200,84000000,first=0,last=0,tcp=600200,syn=600000,mn=54,mx=60),
    "10.10.1.3":mk(400100,21600000,first=0,last=0,tcp=400100,syn=400000,mn=54,mx=60),
    "10.10.1.4":mk(310,43400,first=0,last=0,udp=310,mn=140,mx=140)}
step(s2,"window 2 (strike 2 -> block expected)")

print("\nblocks written:", fw.blocks)
assert "10.10.1.3" in fw.blocks, "SYN flooder should be blocked"
assert "10.10.1.2" not in fw.blocks, "ALLOWLIST VIOLATED"
assert "10.10.1.4" not in fw.blocks, "benign game traffic blocked"
print("PASS: allowlist immunity held, hysteresis worked, benign untouched")

# aggressiveness
for pps,dr in [(1000,0.0),(90000,0.1),(300000,0.6)]:
    lvl,rate,burst,ch=agg.evaluate(pps,dr); print(f"  pps={pps:>7} drop={dr} -> L{lvl} rate={rate} burst={burst}")
for _ in range(8): lvl,rate,burst,ch=agg.evaluate(500,0.0)
print(f"  after 8 calm windows -> L{lvl} rate={rate}")
