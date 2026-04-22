"""Additional hard stress tests."""
import os, queue, re, threading, time, tempfile, sys, random

class _Fake:
    def __getattr__(self, _): return _Fake()
    def __call__(self, *a, **kw): return _Fake()
for mod in ("tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"):
    sys.modules[mod] = _Fake()

import os
_here = os.path.dirname(os.path.abspath(__file__))
_main = os.path.join(_here, '..', 'netapp_audit_viewer.py')
src = open(_main).read()
boundary = src.find('# GUI')
pre_gui = src[:boundary]
ns = {'__name__': '__notmain__'}
exec(pre_gui, ns)
TailReader = ns['TailReader']
parse_event = ns['parse_event']

def mk(eid, user, ip, ts="2026-01-01T00:00:01Z"):
    return (f'<Event><s><EventID>{eid}</EventID>'
            f'<EventName>T</EventName><Source>CIFS</Source>'
            f'<r>Audit Success</r>'
            f'<TimeCreated SystemTime="{ts}"/><Computer>x</Computer>'
            f'</s><EventData>'
            f'<Data Name="IpAddress">{ip}</Data>'
            f'<Data Name="TargetUserName">{user}</Data>'
            f'</EventData></Event>\n').encode()

def drain_all(q, settle=0.3):
    """Wait until queue has been quiet for `settle` seconds, then collect all."""
    kinds = {}
    last = time.time()
    while time.time() - last < settle:
        try:
            kind, payload = q.get(timeout=0.1)
            kinds.setdefault(kind, []).append(payload)
            last = time.time()
        except queue.Empty:
            pass
    return kinds


# ---------------------------------------------------------------------------
print("="*70)
print("HARD TEST A: 5000 events at high write rate, no drops")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.05)
reader.start()
time.sleep(0.1)
_ = drain_all(q, 0.1)

def writer5k():
    with open(fname, 'ab') as f:
        for i in range(5000):
            f.write(mk('4625', f'u{i}', f'10.0.0.{i%256}'))
            if i % 50 == 0: f.flush()
        f.flush()

t0 = time.time()
wt = threading.Thread(target=writer5k); wt.start()
wt.join()
# Wait for drain
time.sleep(0.5)
kinds = drain_all(q, 0.5)
all_new = [e for batch in kinds.get('new', []) for e in batch]
print(f"  Wrote 5000 events in {time.time()-t0:.2f}s")
print(f"  Received: {len(all_new)}")
okA = len(all_new) == 5000
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if okA else f"FAIL - lost {5000-len(all_new)}")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("HARD TEST B: Repeated in-place truncation rotations (like NetApp hourly rotate)")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')
    f.write(mk('4625', 'gen0_0', '10.0.0.1'))

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1)
reader.start()
time.sleep(0.2)
_ = drain_all(q, 0.3)

rotations_received = 0
events_received = []
# Simulate 5 rotations, each with 10 events (unique timestamps per generation)
for gen in range(5):
    # Rotate: truncate and start fresh
    with open(fname, 'wb') as f:
        f.write(b'<Events>\n')
        for i in range(10):
            ts = f"2026-01-0{gen+1}T{10+i:02d}:00:00Z"
            f.write(mk('4625', f'gen{gen+1}_{i}', f'10.0.{gen}.{i}', ts=ts))
    time.sleep(0.3)

time.sleep(0.5)
kinds = drain_all(q, 0.5)
rotations = len(kinds.get('rotated', []))
all_new = [e for batch in kinds.get('new', []) for e in batch]
print(f"  Rotation signals received: {rotations} (expected 5, tolerate 4-6)")
print(f"  Events received: {len(all_new)} (expected 50)")
# Last rotation's events should definitely be present
last_gen_users = [e['User'] for e in all_new if e['User'].startswith('gen5_')]
print(f"  Last generation events: {len(last_gen_users)} / 10")
okB = rotations >= 4 and len(all_new) >= 40 and len(last_gen_users) == 10
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if okB else "FAIL")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("HARD TEST C: Random chunk-size writes, no dropped or duplicated events")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.08)
reader.start()
time.sleep(0.1)
_ = drain_all(q, 0.1)

# Build 500 events, then dribble them to the file in random-sized chunks
payload = b''.join(mk('4625', f'r{i}', f'10.0.0.{i%256}') for i in range(500))
random.seed(42)
with open(fname, 'ab') as f:
    i = 0
    while i < len(payload):
        n = random.randint(1, 300)
        f.write(payload[i:i+n])
        f.flush()
        i += n
        if random.random() < 0.1:
            time.sleep(0.02)

time.sleep(0.6)
kinds = drain_all(q, 0.5)
all_new = [e for batch in kinds.get('new', []) for e in batch]
users = [e['User'] for e in all_new]
uniq = set(users)
print(f"  Received: {len(all_new)} events, {len(uniq)} unique users")
okC = len(all_new) == 500 and len(uniq) == 500
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if okC else f"FAIL (duplicates: {len(all_new)-len(uniq)})")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("HARD TEST D: Rename-rotate (rename away + new file created)")
print("="*70)
# NetApp sometimes does this: mv audit.xml audit.xml-1; touch audit.xml
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')
    f.write(mk('4625', 'oldA', '10.0.0.1'))

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1)
reader.start()
time.sleep(0.3)
_ = drain_all(q, 0.3)

# Rename-rotate
import shutil
backup = fname + ".bak"
os.rename(fname, backup)
with open(fname, 'wb') as f:
    f.write(b'<Events>\n')
    f.write(mk('4624', 'newB', '10.0.0.2'))

time.sleep(0.5)
kinds = drain_all(q, 0.5)
rotations = len(kinds.get('rotated', []))
all_new = [e for batch in kinds.get('new', []) for e in batch]
print(f"  Rotation signals: {rotations}")
print(f"  New events: {len(all_new)}")
for e in all_new: print(f"    - {e['User']}")
okD = rotations >= 1 and any(e['User'] == 'newB' for e in all_new)
stop.set(); reader.join(1)
for p in (fname, backup):
    try: os.unlink(p)
    except: pass
print("  RESULT:", "PASS" if okD else "FAIL")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("SUMMARY")
print("="*70)
results = {
    "A 5000 events high rate":         okA,
    "B 5 in-place rotations":          okB,
    "C random chunk sizes":            okC,
    "D rename-based rotation":         okD,
}
for name, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}   {name}")
passed = sum(results.values())
print(f"\n{passed}/{len(results)} tests passed")
