"""
Stress test for TailReader edge cases that could fail in production.

Scenarios tested:
1. Partial event at write boundary (already covered earlier)
2. Very small chunks (byte by byte writes)
3. File rotation while a partial event is buffered
4. Race: file grows DURING _read_chunk() call
5. Concurrent write + size check inconsistency
6. What if parse fails on a malformed event? Does it skip and continue?
7. What if the file stops existing mid-tail? (unlink/move)
8. What happens when POLL_INTERVAL falls behind the write rate?
9. start_at_end with a file that's being actively written
10. Rotation detection when new file is smaller but also immediately grows past old _pos
"""
import os, queue, re, threading, time, tempfile, shutil, sys

# Extract parser + TailReader from main file without the GUI class
import importlib.util

# Mock tkinter so we can import the module
class _Fake:
    def __getattr__(self, _): return _Fake()
    def __call__(self, *a, **kw): return _Fake()
    def __setattr__(self, *a, **kw): pass
    def __iter__(self): return iter([])
for mod in ("tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"):
    sys.modules[mod] = _Fake()

# Surgery: parse the file up to the GUI class boundary
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
EVENT_RE = ns['EVENT_RE']

# Test helper: make an event
def mk(eid, user, ip, ts="2026-01-01T00:00:01Z"):
    return (f'<Event><System><EventID>{eid}</EventID>'
            f'<EventName>TestEvent</EventName><Source>CIFS</Source>'
            f'<Result>Audit Success</Result>'
            f'<TimeCreated SystemTime="{ts}"/><Computer>x</Computer>'
            f'</System><EventData>'
            f'<Data Name="IpAddress">{ip}</Data>'
            f'<Data Name="TargetUserName">{user}</Data>'
            f'</EventData></Event>\n').encode()


def drain(q, timeout=1.0):
    """Collect all events currently in queue."""
    events = []
    events_by_kind = {}
    t_end = time.time() + timeout
    while time.time() < t_end:
        try:
            kind, payload = q.get(timeout=0.1)
            events_by_kind.setdefault(kind, []).append(payload)
            if kind == 'new':
                events.extend(payload)
        except queue.Empty:
            if events or events_by_kind:
                break
    return events, events_by_kind


# ---------------------------------------------------------------------------
print("="*70)
print("TEST 1: Byte-by-byte writes (simulates slow network-mounted file)")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')

q = queue.Queue()
stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1)
reader.start()
time.sleep(0.2)
_ = drain(q, 0.3)  # consume initial

ev = mk('4625', 'user1', '10.0.0.1')
# Write byte by byte
with open(fname, 'ab') as f:
    for b in ev:
        f.write(bytes([b])); f.flush()
        time.sleep(0.005)

time.sleep(0.3)
events, _ = drain(q, 0.5)
print(f"  Events received: {len(events)} (expected 1)")
if events:
    print(f"  -> {events[0]['User']}, {events[0]['IP']}")
ok1 = len(events) == 1
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if ok1 else "FAIL")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("TEST 2: File grows DURING _read_chunk (race condition simulation)")
print("="*70)
# Hard to reliably reproduce but we can simulate by making the writer
# very fast while the reader polls
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.05)
reader.start()
time.sleep(0.1)
_ = drain(q, 0.2)

# Writer thread: writes 100 events as fast as possible
def writer():
    with open(fname, 'ab') as f:
        for i in range(100):
            f.write(mk('4625', f'user{i}', f'10.0.0.{i}'))
            if i % 10 == 0: f.flush()
        f.flush()

wt = threading.Thread(target=writer); wt.start(); wt.join()
time.sleep(0.5)
events, _ = drain(q, 1.0)
print(f"  Events received: {len(events)} (expected 100)")
ok2 = len(events) == 100
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if ok2 else f"FAIL - missing {100-len(events)}")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("TEST 3: Rotation while partial event is buffered")
print("="*70)
# Scenario: NetApp rotates the file right in the middle of writing an event.
# The buffer has half an event from the OLD file. After rotation, we should
# DROP the buffer, not try to combine with the new file.
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1)
reader.start()
time.sleep(0.2)
_ = drain(q, 0.3)

# Write half an event
ev = mk('4625', 'userA', '10.0.0.1')
with open(fname, 'ab') as f:
    f.write(ev[:40])  # half
time.sleep(0.2)

# Now ROTATE (truncate + rewrite) before the event is complete
with open(fname, 'wb') as f:
    f.write(b'<Events>\n')
    f.write(mk('4624', 'userB', '10.0.0.2'))

time.sleep(0.5)
events, kinds = drain(q, 1.0)
print(f"  Rotation signals: {len(kinds.get('rotated', []))}")
print(f"  Events received: {len(events)}")
for e in events:
    print(f"    - {e['User']}/{e['IP']} EID={e['EventID']}")
# Expect: 1 rotated signal + exactly 1 event (userB), NOT userA (which was only half)
ok3 = (len(kinds.get('rotated', [])) >= 1
       and len(events) == 1
       and events[0]['User'] == 'userB')
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if ok3 else "FAIL - buffer not cleaned on rotation?")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("TEST 4: Malformed event in the middle of valid ones")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')
    f.write(mk('4625', 'userA', '10.0.0.1'))
    # malformed: broken XML
    f.write(b'<Event><System><EventID>9999</EventID<<BROKEN</Event>\n')
    f.write(mk('4624', 'userB', '10.0.0.2'))

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1)
reader.start()
time.sleep(0.3)
events, kinds = drain(q, 0.5)

# initial payload
initial = kinds.get('initial', [[]])[0]
print(f"  Initial events: {len(initial)} (expected 2 valid; malformed should be skipped)")
for e in initial:
    print(f"    - {e['User']}, EID={e['EventID']}")
ok4 = len(initial) == 2
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if ok4 else "FAIL")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("TEST 5: File deleted mid-tail (unlink)")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')
    f.write(mk('4625', 'userA', '10.0.0.1'))

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1)
reader.start()
time.sleep(0.3)
_ = drain(q, 0.3)

# Delete the file
os.unlink(fname)
time.sleep(0.5)

# Recreate
with open(fname, 'wb') as f:
    f.write(b'<Events>\n')
    f.write(mk('4624', 'userB', '10.0.0.2'))

time.sleep(0.5)
events, kinds = drain(q, 1.0)
print(f"  Rotated signals: {len(kinds.get('rotated', []))}")
print(f"  Events received: {len(events)}")
for e in events: print(f"    - {e['User']} EID={e['EventID']}")
# Should recover: detect rotation (size smaller), re-read from start, pick up userB
ok5 = any(e['User'] == 'userB' for e in events)
stop.set(); reader.join(1)
try: os.unlink(fname)
except: pass
print("  RESULT:", "PASS" if ok5 else "FAIL - tail did not recover after unlink/recreate")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("TEST 6: start_at_end mode (folder load, then tail latest)")
print("="*70)
with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as f:
    fname = f.name
    f.write(b'<Events>\n')
    # Pretend this file already has 100 events at load time
    for i in range(100):
        f.write(mk('4625', f'old{i}', f'10.0.0.{i}'))

q = queue.Queue(); stop = threading.Event()
reader = TailReader(fname, q, stop, poll=0.1, start_at_end=True)
reader.start()
time.sleep(0.3)
events_before, kinds_before = drain(q, 0.3)
print(f"  Initial events (should be 0 in start_at_end mode): {len(events_before)}")
initial_payload = kinds_before.get('initial', [[]])[0] if kinds_before.get('initial') else []
print(f"  Initial payload length: {len(initial_payload)}")

# Now append new events
with open(fname, 'ab') as f:
    f.write(mk('4624', 'newA', '10.0.0.101'))
    f.write(mk('4624', 'newB', '10.0.0.102'))

time.sleep(0.5)
events_after, _ = drain(q, 0.5)
print(f"  New events received after append: {len(events_after)}")
for e in events_after: print(f"    - {e['User']}")
ok6 = len(initial_payload) == 0 and len(events_after) == 2
stop.set(); reader.join(1); os.unlink(fname)
print("  RESULT:", "PASS" if ok6 else "FAIL")


# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("SUMMARY")
print("="*70)
results = {
    "1 byte-by-byte writes":               ok1,
    "2 fast concurrent writes":            ok2,
    "3 rotation during partial event":     ok3,
    "4 malformed event handling":          ok4,
    "5 unlink + recreate":                 ok5,
    "6 start_at_end mode":                 ok6,
}
for name, ok in results.items():
    print(f"  {'PASS' if ok else 'FAIL'}   {name}")
passed = sum(results.values())
print(f"\n{passed}/{len(results)} tests passed")
