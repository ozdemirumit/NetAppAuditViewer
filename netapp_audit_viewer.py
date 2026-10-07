#!/usr/bin/env python3
"""
NetApp Audit XML Viewer
========================

A GUI viewer for NetApp ONTAP and Huawei OceanStor (e.g. 5510) CIFS Security
Audit XML log files. Parses events,
auto-loads new lines as they arrive (like `tail -f`), and supports filtering
by EventID, Result, User, IP, time range, and free-text search across all fields.

Handles both logon events (4624/4625/4634) and file-operation events
(4656/4663/4670/4907) by unifying their User/IP/Object/Action fields.

- Single file, uses only Python standard library (tkinter).
- Compatible with Python 3.10+ (including 3.13/3.14).
- Assumes one <Event>...</Event> block per line (NetApp default).

Usage:
    python netapp_audit_viewer.py
    python netapp_audit_viewer.py audit_log.xml
    python netapp_audit_viewer.py audit_log.xml --tail
    python netapp_audit_viewer.py audit_log.xml --filter-ip 10.0.0.5 --only-failures
"""

import argparse
import csv
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

__version__ = "1.1.0"   # keep in sync with pyproject.toml

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

POLL_INTERVAL = 1.0          # Tail polling interval (seconds)
MAX_DISPLAY_ROWS = 10000     # Maximum rows shown in Treeview at one time
EVENT_RE = re.compile(rb"<Event\b.*?</Event>", re.DOTALL)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

PARSE_STATS = {"failed": 0, "repaired": 0}
_BAD_AMP = re.compile(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)")
_BAD_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _parse_lenient(xml_bytes: bytes):
    """Retry parsing events that strict XML rejects: bare '&' in file names,
    control characters, or non-UTF-8 bytes (e.g. legacy Turkish code pages)."""
    for enc in ("utf-8", "cp1254", "latin-1"):
        try:
            text = xml_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    text = _BAD_CTRL.sub("", _BAD_AMP.sub("&amp;", text))
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    PARSE_STATS["repaired"] += 1
    return root


def parse_event(xml_bytes: bytes) -> dict | None:
    """Parse a single <Event>...</Event> block and return as dict."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        root = _parse_lenient(xml_bytes)
        if root is None:
            PARSE_STATS["failed"] += 1
            return None

    # Huawei events carry an xmlns on <Event>; strip namespaces so the same
    # find() calls work for every vendor.
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag[1:].split("}", 1)[0]
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]

    rec = {
        "EventID": "",
        "EventName": "",
        "Source": "",
        "Result": "",
        "Time": "",
        "Computer": "",
        "Channel": "",
        "Vendor": "NetApp",
        "VendorDetected": "NetApp",
        "Share": "",
        "Path": "",
        "AccessText": "",
        # Logon events use these
        "IpAddress": "",
        "IpPort": "",
        "TargetUserName": "",
        "TargetDomainName": "",
        "TargetUserSid": "",
        "TargetUserIsLocal": "",
        "Status": "",
        "FailureReason": "",
        "FailureReasonString": "",
        "AuthenticationPackageName": "",
        "LogonType": "",
        # File-operation events use these
        "SubjectIP": "",
        "SubjectUserName": "",
        "SubjectDomainName": "",
        "SubjectUserSid": "",
        "SubjectUserIsLocal": "",
        "ObjectServer": "",
        "ObjectType": "",
        "ObjectName": "",
        "HandleID": "",
        "AccessList": "",
        "AccessMask": "",
        "DesiredAccess": "",
        "InformationRequested": "",
        "Attributes": "",
        "OldSD": "",
        "NewSD": "",
        # Unified columns - filled from either logon or file-op fields
        "User": "",
        "Domain": "",
        "IP": "",
        "Object": "",
        "Action": "",
        "_extra": {},
    }

    sysn = root.find("System")
    if sysn is not None:
        for k in ("EventID", "EventName", "Version", "Source",
                  "Level", "Opcode", "Computer", "Channel"):
            el = sysn.find(k)
            if el is not None and el.text:
                if k in rec:
                    rec[k] = el.text.strip()
                else:
                    rec["_extra"][k] = el.text.strip()
        prov = sysn.find("Provider")
        if "huawei" in (ns + (prov.attrib.get("Name", "") if prov is not None
                              else "")).lower():
            rec["Vendor"] = rec["VendorDetected"] = "Huawei"
        known = {"EventID", "EventName", "Version", "Source", "Level", "Opcode",
                 "Computer", "Channel", "Result", "TimeCreated", "Provider"}
        for child in sysn:
            if child.tag not in known and child.text and child.text.strip():
                rec["_extra"][child.tag] = child.text.strip()
        r = sysn.find("Result")
        if r is not None and r.text:
            rec["Result"] = r.text.strip()
        t = sysn.find("TimeCreated")
        if t is not None:
            rec["Time"] = t.attrib.get("SystemTime", "")

    ed = root.find("EventData")
    if ed is not None:
        for d in ed.findall("Data"):
            name = d.attrib.get("Name", "")
            value = (d.text or "").strip()
            if not name:
                continue
            if name in rec:
                rec[name] = value
            else:
                rec["_extra"][name] = value
            # Keep informative attributes (e.g. Huawei SubjectUnix Uid/Gid)
            if not value:
                attrs = {k: v for k, v in d.attrib.items() if k != "Name"}
                if attrs and name not in rec:
                    rec["_extra"][name] = ", ".join(
                        f"{k}={v}" for k, v in attrs.items())

    # Unified columns: prefer Subject* (file ops) when present, else Target* (logon)
    rec["User"]   = rec["SubjectUserName"]   or rec["TargetUserName"]
    rec["Domain"] = rec["SubjectDomainName"] or rec["TargetDomainName"]
    rec["IP"]     = rec["SubjectIP"]         or rec["IpAddress"]
    rec["Object"] = rec["ObjectName"]
    # ObjectName looks like "(ShareName);/dir/file"
    m = re.match(r"\(([^)]*)\);\s*(.*)$", rec["ObjectName"], re.DOTALL)
    if m:
        rec["Share"], rec["Path"] = m.group(1), m.group(2).strip()
    else:
        rec["Path"] = rec["ObjectName"]
    rec["AccessText"] = decode_access_list(rec["AccessList"])
    # "Action" summary: depends on event type
    eid = rec["EventID"]
    if eid in ("4656", "4663"):
        rec["Action"] = (rec["DesiredAccess"]
                         or rec["InformationRequested"]
                         or rec["AccessText"]
                         or rec["AccessList"])
    elif eid == "4660":
        rec["Action"] = "Object deleted"
    elif eid == "4658":
        rec["Action"] = "Handle closed"
    elif eid == "4670":
        rec["Action"] = "Permissions changed"
    elif eid == "4907":
        rec["Action"] = "Audit settings changed"
    elif eid in ("4624", "4625", "4634"):
        rec["Action"] = rec["FailureReasonString"]   # only failures populate
        if not rec["Action"] and rec["LogonType"]:
            rec["Action"] = f"LogonType {rec['LogonType']}"
    if not rec["EventName"]:
        rec["EventName"] = EVENT_NAMES.get(eid, "")

    rec["TimeDisplay"] = _format_time(rec["Time"])
    return rec


EVENT_NAMES = {
    "4624": "Logon Attempt", "4625": "Logon Failure", "4634": "Logoff",
    "4656": "Open Object", "4658": "Close Handle", "4660": "Delete Object",
    "4663": "Get Object Attributes", "4670": "Permissions Changed",
    "4907": "Auditing Settings Changed",
}

# Windows-style access-right message codes used in AccessList (%%NNNN)
ACCESS_CODES = {
    "1537": "DELETE", "1538": "READ_CONTROL", "1539": "WRITE_DAC",
    "1540": "WRITE_OWNER", "1541": "SYNCHRONIZE",
    "4416": "ReadData/ListDirectory", "4417": "WriteData/AddFile",
    "4418": "AppendData/AddSubdirectory", "4419": "ReadEA", "4420": "WriteEA",
    "4421": "Execute/Traverse", "4422": "DeleteChild",
    "4423": "ReadAttributes", "4424": "WriteAttributes",
}


def decode_access_list(access_list: str) -> str:
    """'%%4416 %%4423' -> 'ReadData/ListDirectory; ReadAttributes'"""
    if not access_list:
        return ""
    names = [ACCESS_CODES.get(c, f"%%{c}")
             for c in re.findall(r"%%(\d+)", access_list)]
    return "; ".join(names)


def _format_time(iso: str) -> str:
    """ '2026-04-03T13:15:25.954874000Z' -> '2026-04-03 13:15:25' """
    if not iso:
        return ""
    try:
        clean = iso.rstrip("Z")
        if "." in clean:
            head, frac = clean.split(".", 1)
            clean = f"{head}.{frac[:6]}"   # truncate to microseconds
        return datetime.fromisoformat(clean).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return iso


# ---------------------------------------------------------------------------
# Tail thread
# ---------------------------------------------------------------------------

class TailReader(threading.Thread):
    """Watch file in background, push parsed events to queue."""

    def __init__(self, path: str, out_queue: queue.Queue,
                 stop_event: threading.Event, poll: float = POLL_INTERVAL,
                 start_at_end: bool = False, follow: bool = True,
                 start_pos: int | None = None):
        super().__init__(daemon=True)
        self.path = path
        self.q = out_queue
        self.stop_event = stop_event
        self.poll = poll
        self.start_at_end = start_at_end
        self.follow = follow            # False: read once and stop (Open File)
        self.start_pos = start_pos      # resume tailing from this offset
        self._buf = b""
        self._pos = 0

    def _emit(self, kind: str, payload):
        self.q.put((kind, payload))

    def _read_chunk(self, start: int) -> tuple[bytes, int]:
        with open(self.path, "rb") as f:
            f.seek(start)
            chunk = f.read()
            new_pos = f.tell()
        return chunk, new_pos

    def _consume(self, data: bytes) -> list[dict]:
        """Append data to buffer and extract complete <Event>...</Event> blocks."""
        self._buf += data
        events = []
        last = 0
        for m in EVENT_RE.finditer(self._buf):
            ev = parse_event(m.group(0))
            if ev:
                events.append(ev)
            last = m.end()
        # Keep trailing fragment (might be a partial event) in buffer
        self._buf = self._buf[last:]
        return events

    def _stat_signature(self):
        """Return a tuple that changes when the file is rotated/recreated.
        On POSIX this is (st_ino, st_dev). On Windows st_ino is also populated
        and changes when a file is deleted+recreated or moved-aside+new.
        Returns None if the file can't be stat'ed (deleted)."""
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_ino, st.st_dev)

    def _head_signature(self):
        """Read up to 4 KB from the start of the file. This is used as a
        fingerprint: if the file is truncated and rewritten in place (same
        inode), the head content almost certainly differs (different timestamps,
        provider IDs, etc.). 4 KB is chosen to span several events worth of
        data so accidental-collision is vanishingly unlikely on audit logs
        that include high-resolution timestamps.
        Returns None on error."""
        try:
            with open(self.path, "rb") as f:
                return f.read(4096)
        except OSError:
            return None

    def run(self):
        self._file_sig = self._stat_signature()
        self._head_sig = self._head_signature()
        if self.start_pos is not None:
            # Resume right after what "Open File" already loaded
            try:
                self._pos = min(self.start_pos, os.path.getsize(self.path))
            except OSError as e:
                self._emit("error", f"Cannot open file: {e}")
                return
            self._emit("initial", [])
        elif self.start_at_end:
            # Only watch the end of the file, do not re-read existing content
            try:
                self._pos = os.path.getsize(self.path)
            except OSError as e:
                self._emit("error", f"Cannot open file: {e}")
                return
            self._emit("initial", [])
        else:
            try:
                chunk, self._pos = self._read_chunk(0)
            except OSError as e:
                self._emit("error", f"Cannot open file: {e}")
                return
            initial = self._consume(chunk)
            if self.stop_event.is_set():
                return
            self._emit("initial", initial)
            if not self.follow:
                self._emit("loaded", self._pos)
                return

        missing_since = None

        while not self.stop_event.is_set():
            try:
                st = os.stat(self.path)
                size = st.st_size
                current_sig = (st.st_ino, st.st_dev)
            except OSError:
                if missing_since is None:
                    missing_since = time.time()
                self.stop_event.wait(self.poll)
                continue

            rotated = False

            # File reappeared after being missing -> treat as rotation
            if missing_since is not None:
                missing_since = None
                rotated = True

            # Inode/device changed -> file was rotated (renamed + new created)
            elif self._file_sig is not None and current_sig != self._file_sig:
                rotated = True

            # In-place truncation detectable by size
            elif size < self._pos:
                rotated = True

            # In-place truncation where the rewrite already grew past our
            # previous position: check if the file head content changed in
            # a way that cannot be explained by normal growth.
            # Normal growth: new head starts with old head (old is a prefix).
            # Rotation: new head differs in the overlapping region.
            elif self._head_sig is not None:
                new_head = self._head_signature()
                if new_head is not None:
                    old = self._head_sig
                    overlap = min(len(old), len(new_head))
                    if overlap > 0 and old[:overlap] != new_head[:overlap]:
                        rotated = True

            if rotated:
                self._pos = 0
                self._buf = b""
                self._file_sig = current_sig
                self._head_sig = self._head_signature()
                self._emit("rotated", None)
                # Re-stat in case head-read changed nothing else; fall through
                # to read the new content below.
                try:
                    size = os.path.getsize(self.path)
                except OSError:
                    self.stop_event.wait(self.poll)
                    continue

            if size > self._pos:
                try:
                    chunk, new_pos = self._read_chunk(self._pos)
                except OSError:
                    self.stop_event.wait(self.poll)
                    continue
                self._pos = new_pos
                # Refresh head signature periodically (after meaningful growth)
                if self._head_sig is None or len(self._head_sig) < 4096:
                    self._head_sig = self._head_signature()
                new_events = self._consume(chunk)
                if new_events:
                    self._emit("new", new_events)

            self.stop_event.wait(self.poll)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

DETAIL_ORDER = [
    "Time", "Vendor", "EventID", "EventName", "Source", "Result",
    "Computer", "Channel",
    "User", "Domain", "IP", "IpPort",
    "IpAddress", "TargetUserName", "TargetDomainName", "TargetUserSid",
    "TargetUserIsLocal", "Status", "FailureReason", "FailureReasonString",
    "AuthenticationPackageName", "LogonType",
    "SubjectIP", "SubjectUserName", "SubjectDomainName", "SubjectUserSid",
    "SubjectUserIsLocal",
    "ObjectServer", "ObjectType", "Share", "Path", "ObjectName", "HandleID",
    "AccessText", "AccessList", "AccessMask", "DesiredAccess",
    "InformationRequested", "Attributes", "OldSD", "NewSD",
]


class AuditViewer(tk.Tk):

    COLUMNS = [
        ("TimeDisplay", "Time",     150),
        ("EventID",     "ID",       60),
        ("EventName",   "Event",    160),
        ("Result",      "Result",   100),
        ("IP",          "IP",       125),
        ("User",        "User",     130),
        ("Domain",      "Domain",   100),
        ("Share",       "Share",    110),
        ("Path",        "Object",   320),
        ("Action",      "Action / Reason", 260),
    ]

    def __init__(self):
        super().__init__()
        self.title(f"NetApp Audit XML Viewer  v{__version__}")
        self.geometry("1340x800")
        self.minsize(900, 500)

        # Veri
        self.events: list[dict] = []
        self.filtered_indices: list[int] = []
        self.tail_thread: TailReader | None = None
        self.tail_stop: threading.Event | None = None
        self.queue: queue.Queue = queue.Queue()
        self.tailing = False
        self._known_event_ids: set[str] = set()
        self._loaded_path = ""          # file loaded by "Open File"
        self._loaded_pos: int | None = None

        # Filter variables
        self.path_var       = tk.StringVar()
        self.filter_eventid = tk.StringVar(value="All")
        self.filter_result  = tk.StringVar(value="All")
        self.vendor_mode    = tk.StringVar(value="Auto")
        self.filter_user    = tk.StringVar()
        self.filter_ip      = tk.StringVar()
        self.filter_search  = tk.StringVar()
        self.filter_from    = tk.StringVar()
        self.filter_to      = tk.StringVar()
        self.autoscroll     = tk.BooleanVar(value=True)
        self.live_filter    = tk.BooleanVar(value=True)

        self._build_ui()
        self.after(150, self._drain_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=22, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        # ---- Top bar: file selection and tail control ----
        top = ttk.Frame(self, padding=(10, 8, 10, 4))
        top.pack(fill="x")
        ttk.Label(top, text="File:").pack(side="left")
        ttk.Entry(top, textvariable=self.path_var).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse...", command=self._browse).pack(side="left")
        ttk.Button(top, text="Open File", command=self._open_file).pack(
            side="left", padx=(6, 0))
        self.tail_btn = ttk.Button(top, text="Start Tail",
                                   command=self._toggle_tail)
        self.tail_btn.pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Folder (rotated)...",
                   command=self._open_directory).pack(side="left", padx=(6, 0))
        ttk.Label(top, text="Vendor:").pack(side="left", padx=(10, 2))
        vcombo = ttk.Combobox(top, textvariable=self.vendor_mode, width=8,
                              values=["Auto", "NetApp", "Huawei"],
                              state="readonly")
        vcombo.pack(side="left")
        vcombo.bind("<<ComboboxSelected>>", lambda _e: self._on_vendor_changed())
        ttk.Button(top, text="Reload", command=self._reload).pack(
            side="left", padx=(6, 0))
        ttk.Button(top, text="Statistics...", command=self._show_stats).pack(
            side="left", padx=(6, 0))
        ttk.Button(top, text="Export CSV...", command=self._export_csv).pack(
            side="left", padx=(6, 0))

        # ---- Filter panel ----
        flt = ttk.LabelFrame(self, text="Filters", padding=(10, 6))
        flt.pack(fill="x", padx=10, pady=(0, 4))

        ttk.Label(flt, text="Event ID:").grid(row=0, column=0, sticky="w")
        self.eventid_combo = ttk.Combobox(
            flt, textvariable=self.filter_eventid,
            values=["All"], width=10, state="readonly")
        self.eventid_combo.grid(row=0, column=1, padx=(4, 12))

        ttk.Label(flt, text="Result:").grid(row=0, column=2, sticky="w")
        self.result_combo = ttk.Combobox(
            flt, textvariable=self.filter_result,
            values=["All", "Audit Success", "Audit Failure"],
            width=15, state="readonly")
        self.result_combo.grid(row=0, column=3, padx=(4, 12))

        ttk.Label(flt, text="User contains:").grid(row=0, column=4, sticky="w")
        e_user = ttk.Entry(flt, textvariable=self.filter_user, width=18)
        e_user.grid(row=0, column=5, padx=(4, 12))

        ttk.Label(flt, text="IP contains:").grid(row=0, column=6, sticky="w")
        e_ip = ttk.Entry(flt, textvariable=self.filter_ip, width=18)
        e_ip.grid(row=0, column=7, padx=(4, 12))

        # --- Time range (row 1) ---
        ttk.Label(flt, text="From (YYYY-MM-DD HH:MM):").grid(
            row=1, column=0, sticky="w", pady=(6, 0))
        e_from = ttk.Entry(flt, textvariable=self.filter_from, width=20)
        e_from.grid(row=1, column=1, columnspan=2, sticky="w",
                    padx=(4, 12), pady=(6, 0))
        ttk.Label(flt, text="To (YYYY-MM-DD HH:MM):").grid(
            row=1, column=3, sticky="w", pady=(6, 0))
        e_to = ttk.Entry(flt, textvariable=self.filter_to, width=20)
        e_to.grid(row=1, column=4, columnspan=2, sticky="w",
                  padx=(4, 12), pady=(6, 0))
        ttk.Button(flt, text="Last 1 hour",
                   command=lambda: self._set_relative_range(60)).grid(
            row=1, column=6, padx=(0, 4), pady=(6, 0))
        ttk.Button(flt, text="Last 24 hours",
                   command=lambda: self._set_relative_range(60 * 24)).grid(
            row=1, column=7, padx=(0, 4), pady=(6, 0))

        # --- Search + buttons (row 2) ---
        ttk.Label(flt, text="Search (all fields):").grid(
            row=2, column=0, sticky="w", pady=(6, 0))
        e_search = ttk.Entry(flt, textvariable=self.filter_search, width=40)
        e_search.grid(row=2, column=1, columnspan=3, sticky="we",
                      padx=(4, 12), pady=(6, 0))

        ttk.Button(flt, text="Apply", command=self._apply_filters).grid(
            row=2, column=4, padx=(0, 6), pady=(6, 0))
        ttk.Button(flt, text="Reset", command=self._reset_filters).grid(
            row=2, column=5, padx=(0, 6), pady=(6, 0))
        ttk.Checkbutton(flt, text="Auto-scroll",
                        variable=self.autoscroll).grid(
            row=2, column=6, sticky="w", pady=(6, 0))
        ttk.Checkbutton(flt, text="Filter as you type",
                        variable=self.live_filter).grid(
            row=2, column=7, sticky="w", pady=(6, 0))

        # Press Enter to apply filter
        for w in (e_user, e_ip, e_search, e_from, e_to):
            w.bind("<Return>", lambda _e: self._apply_filters())
        # Live filtering (debounced)
        for var in (self.filter_user, self.filter_ip, self.filter_search,
                    self.filter_from, self.filter_to):
            var.trace_add("write", self._on_filter_typed)
        self.eventid_combo.bind("<<ComboboxSelected>>",
                                lambda _e: self._apply_filters())
        self.result_combo.bind("<<ComboboxSelected>>",
                               lambda _e: self._apply_filters())

        # ---- Ana panel: tablo + detay ----
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        tree_frame = ttk.Frame(paned)
        paned.add(tree_frame, weight=3)

        cols = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(tree_frame, columns=cols,
                                 show="headings", selectmode="browse")
        for key, label, width in self.COLUMNS:
            self.tree.heading(key, text=label,
                              command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, anchor="w", stretch=True)

        self.tree.tag_configure("failure", background="#fde2e2")
        self.tree.tag_configure("success", background="#e7f4ea")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="we")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._show_context_menu)        # Windows/Linux
        self.tree.bind("<Button-2>", self._show_context_menu)        # macOS
        self.tree.bind("<Control-Button-1>", self._show_context_menu)  # macOS alt

        # Right-click context menu
        self._ctx_menu = tk.Menu(self, tearoff=0)

        detail_frame = ttk.LabelFrame(paned, text="Event detaylari")
        paned.add(detail_frame, weight=1)
        self.detail = tk.Text(detail_frame, wrap="word", height=10,
                              font=("Consolas", 9))
        self.detail.pack(fill="both", expand=True, padx=4, pady=4)
        self.detail.configure(state="disabled")

        self.status_var = tk.StringVar(value="Ready. Select an XML file.")
        bar = ttk.Frame(self, relief="sunken")
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, text=f"v{__version__}", anchor="e",
                  padding=(8, 4)).pack(side="right")
        ttk.Label(bar, textvariable=self.status_var, anchor="w",
                  padding=(8, 4)).pack(side="left", fill="x", expand=True)

    # ----------------------------------------------------------- Dosya/tail

    def _browse(self):
        p = filedialog.askopenfilename(
            title="Select NetApp Audit XML file",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if p:
            self.path_var.set(p)

    def _open_directory(self):
        """Bir klasor sec; icindeki tum audit XML dosyalarini (rotate edilmis
        olanlar dahil) zaman sirasiyla yukle, sonra en yeni dosyayi tail et."""
        d = filedialog.askdirectory(
            title="Select audit XML folder (including rotated files)")
        if not d:
            return
        # Audit dosyalarini bul: .xml ve .xml-N, .xml.N gibi varyantlar
        try:
            entries = os.listdir(d)
        except OSError as e:
            messagebox.showerror("Error", f"Cannot read folder: {e}")
            return

        pattern = re.compile(r"\.xml(?:[._-]\d+)?$", re.IGNORECASE)
        files = []
        for name in entries:
            full = os.path.join(d, name)
            if not os.path.isfile(full):
                continue
            if not pattern.search(name):
                continue
            try:
                mtime = os.path.getmtime(full)
            except OSError:
                continue
            files.append((mtime, full))

        if not files:
            messagebox.showinfo(
                "Folder", "Folderde uygun bir audit XML dosyasi bulunamadi.\n"
                "(.xml, .xml-1, .xml.0 vs.)")
            return

        # Eski -> yeni siralayarak yukle
        files.sort(key=lambda x: x[0])

        # Mevcut tail/state'i sifirla
        self._stop_tail()
        self._reset_data()
        self._loaded_path = ""

        total = 0
        errors = []
        for _, fp in files:
            try:
                with open(fp, "rb") as f:
                    data = f.read()
            except OSError as e:
                errors.append(f"{os.path.basename(fp)}: {e}")
                continue
            for m in EVENT_RE.finditer(data):
                ev = parse_event(m.group(0))
                if ev:
                    self.events.append(ev)
                    total += 1

        self._relabel_vendor(self.events)

        # En yeni dosyayi tail et
        latest = files[-1][1]
        self.path_var.set(latest)
        self._update_event_id_combo()
        self._apply_filters()
        self._start_tail_existing()

        msg = (f"{len(files)} files, {total:,} events loaded. "
               f"Tail: {os.path.basename(latest)}")
        if errors:
            msg += f"  ({len(errors)} files unreadable)"
        self.status_var.set(msg)

    def _start_tail_existing(self):
        """Mevcut self.events listesini SIFIRLAMADAN sadece dosyanin sonunu tail et.
        Folder yukleme sonrasi en yeni dosyaya yeni event'leri eklemek icin."""
        path = self.path_var.get().strip()
        if not os.path.isfile(path):
            return
        self.tail_stop = threading.Event()
        self.tail_thread = TailReader(path, self.queue, self.tail_stop,
                                      start_at_end=True)
        self.tail_thread.start()
        self.tailing = True
        self.tail_btn.configure(text="Stop Tail")

    def _toggle_tail(self):
        if self.tailing:
            self._stop_tail()
            self.status_var.set("Tail stopped.")
        else:
            self._start_tail()

    def _reset_data(self):
        self.events.clear()
        self.filtered_indices.clear()
        self._known_event_ids.clear()
        self._clear_tree()
        self._set_detail("")
        self._loaded_pos = None
        try:                      # drop events still queued from old readers
            while True:
                self.queue.get_nowait()
        except queue.Empty:
            pass

    def _valid_path(self) -> str | None:
        path = self.path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select a valid XML file.")
            return None
        return path

    def _open_file(self):
        """Load the whole file once. No live following."""
        path = self._valid_path()
        if not path:
            return
        self._stop_tail()
        self._reset_data()
        self._loaded_path = path
        self.tail_stop = threading.Event()
        self.tail_thread = TailReader(path, self.queue, self.tail_stop,
                                      follow=False)
        self.tail_thread.start()
        self.status_var.set(f"Loading: {path}")

    def _start_tail(self):
        """Follow the file for new events. If it was already opened with
        "Open File", continue from where that load ended; otherwise read the
        file from the start and then follow it."""
        path = self._valid_path()
        if not path:
            return
        resume = (self._loaded_pos if path == self._loaded_path
                  and self.events else None)
        self._stop_tail()
        if resume is None:
            self._reset_data()
            self._loaded_path = ""
        self.tail_stop = threading.Event()
        self.tail_thread = TailReader(path, self.queue, self.tail_stop,
                                      start_pos=resume)
        self.tail_thread.start()
        self.tailing = True
        self.tail_btn.configure(text="Stop Tail")
        self.status_var.set(f"Tailing: {path}")

    def _stop_tail(self):
        if self.tail_stop is not None:
            self.tail_stop.set()
        self.tail_thread = None
        self.tail_stop = None
        self.tailing = False
        self.tail_btn.configure(text="Start Tail")

    def _reload(self):
        """Re-read the file from scratch, keeping tail on if it was on."""
        if not self.path_var.get().strip():
            return
        was_tailing = self.tailing
        self._loaded_path = ""
        if was_tailing:
            self._start_tail()
        else:
            self._open_file()

    # ----------------------------------------------------------- Queue draining

    def _drain_queue(self):
        new_count = 0
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "error":
                    messagebox.showerror("Error", payload)
                    self._stop_tail()
                elif kind == "initial":
                    self._relabel_vendor(payload)
                    self.events.extend(payload)
                    self._update_event_id_combo()
                    self._apply_filters()
                elif kind == "loaded":
                    self._loaded_pos = payload
                    self._update_status()
                elif kind == "new":
                    self._relabel_vendor(payload)
                    start = len(self.events)
                    self.events.extend(payload)
                    self._update_event_id_combo()
                    self._append_filtered_from(start)
                    new_count += len(payload)
                elif kind == "rotated":
                    self.events.clear()
                    self.filtered_indices.clear()
                    self._known_event_ids.clear()
                    self._clear_tree()
                    self.status_var.set("File rotated - re-reading from start.")
        except queue.Empty:
            pass
        if new_count:
            self._update_status()
        self.after(150, self._drain_queue)

    def _relabel_vendor(self, events: list[dict]):
        """Apply the Vendor selector: Auto keeps the detected vendor, otherwise
        the chosen vendor overrides the label."""
        mode = self.vendor_mode.get()
        for ev in events:
            ev["Vendor"] = (ev.get("VendorDetected", "NetApp")
                            if mode == "Auto" else mode)

    def _on_vendor_changed(self):
        self._relabel_vendor(self.events)
        self._apply_filters()

    def _update_event_id_combo(self):
        ids = {e["EventID"] for e in self.events if e["EventID"]}
        new = ids - self._known_event_ids
        if not new:
            return
        self._known_event_ids |= ids
        values = ["All"] + sorted(self._known_event_ids)
        self.eventid_combo["values"] = values

    # ----------------------------------------------------------- Filtreleme

    def _passes(self, ev: dict) -> bool:
        f_id = self.filter_eventid.get()
        if f_id != "All" and ev.get("EventID") != f_id:
            return False
        f_res = self.filter_result.get()
        if f_res != "All" and ev.get("Result") != f_res:
            return False
        f_user = self.filter_user.get().strip().lower()
        if f_user and f_user not in ev.get("User", "").lower():
            return False
        f_ip = self.filter_ip.get().strip().lower()
        if f_ip and f_ip not in ev.get("IP", "").lower():
            return False
        # Time range (TimeDisplay = "YYYY-MM-DD HH:MM:SS" string-comparable)
        td = ev.get("TimeDisplay", "")
        f_from = self.filter_from.get().strip()
        if f_from and td and td < f_from:
            return False
        f_to = self.filter_to.get().strip()
        if f_to and td and td > f_to:
            return False
        f_search = self.filter_search.get().strip().lower()
        if f_search:
            haystack_parts = [str(v) for k, v in ev.items()
                              if isinstance(v, str)]
            haystack_parts.extend(ev.get("_extra", {}).values())
            if f_search not in " ".join(haystack_parts).lower():
                return False
        return True

    def _set_relative_range(self, minutes: int):
        """Set filter to 'last N minutes' — uses the most recent event time
        in the dataset as reference (for live tail this means 'last N min from now')."""
        if not self.events:
            messagebox.showinfo("Time", "Open a file first.")
            return
        # Find the latest event with a parseable time
        last_ts = ""
        for ev in reversed(self.events):
            if ev.get("TimeDisplay"):
                last_ts = ev["TimeDisplay"]
                break
        if not last_ts:
            return
        try:
            end = datetime.strptime(last_ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return
        from datetime import timedelta
        start = end - timedelta(minutes=minutes)
        self.filter_from.set(start.strftime("%Y-%m-%d %H:%M:%S"))
        self.filter_to.set(end.strftime("%Y-%m-%d %H:%M:%S"))
        self._apply_filters()

    _filter_after_id = None

    def _on_filter_typed(self, *_args):
        if not self.live_filter.get():
            return
        if self._filter_after_id is not None:
            self.after_cancel(self._filter_after_id)
        # 250 ms bekle, sonra uygula (debounce)
        self._filter_after_id = self.after(250, self._apply_filters)

    def _apply_filters(self):
        self._filter_after_id = None
        self._clear_tree()
        self.filtered_indices = [i for i, e in enumerate(self.events)
                                 if self._passes(e)]
        to_show = self.filtered_indices[-MAX_DISPLAY_ROWS:]
        for idx in to_show:
            self._insert_row(idx, self.events[idx])
        self._update_status()
        if self.autoscroll.get():
            self._scroll_to_bottom()

    def _append_filtered_from(self, start_index: int):
        added = 0
        for i in range(start_index, len(self.events)):
            ev = self.events[i]
            if self._passes(ev):
                self.filtered_indices.append(i)
                self._insert_row(i, ev)
                added += 1
        # Treeview cap
        children = self.tree.get_children()
        excess = len(children) - MAX_DISPLAY_ROWS
        if excess > 0:
            for iid in children[:excess]:
                self.tree.delete(iid)
        if added and self.autoscroll.get():
            self._scroll_to_bottom()

    def _insert_row(self, idx: int, ev: dict):
        values = [ev.get(c[0], "") for c in self.COLUMNS]
        result = ev.get("Result", "")
        tag = ()
        if "Failure" in result:
            tag = ("failure",)
        elif "Success" in result:
            tag = ("success",)
        self.tree.insert("", "end", iid=str(idx), values=values, tags=tag)

    def _reset_filters(self):
        self.filter_eventid.set("All")
        self.filter_result.set("All")
        self.filter_user.set("")
        self.filter_ip.set("")
        self.filter_search.set("")
        self.filter_from.set("")
        self.filter_to.set("")
        self._apply_filters()

    def _scroll_to_bottom(self):
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

    def _clear_tree(self):
        # Bulk delete is faster than item-by-item
        children = self.tree.get_children()
        if children:
            self.tree.delete(*children)

    # ----------------------------------------------------------- Sort

    def _sort_by(self, col_key: str):
        if not self.filtered_indices:
            return
        reverse = getattr(self, "_sort_reverse_" + col_key, False)
        self.filtered_indices.sort(
            key=lambda i: self.events[i].get(col_key, ""),
            reverse=reverse)
        setattr(self, "_sort_reverse_" + col_key, not reverse)
        self._clear_tree()
        for idx in self.filtered_indices[-MAX_DISPLAY_ROWS:]:
            self._insert_row(idx, self.events[idx])

    # ----------------------------------------------------------- Sag tik menusu

    def _show_context_menu(self, event):
        """Tablo satirinda sag tik: hizli filtre/aksiyon menusu."""
        # Mouse altindaki satiri sec
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        try:
            idx = int(iid)
        except ValueError:
            return
        if not (0 <= idx < len(self.events)):
            return
        ev = self.events[idx]

        ip   = ev.get("IP", "")
        user = ev.get("User", "")
        eid  = ev.get("EventID", "")
        dom  = ev.get("Domain", "")
        reason = ev.get("FailureReasonString", "")

        m = self._ctx_menu
        m.delete(0, "end")

        # Filtreleme
        if ip:
            m.add_command(label=f"Filter by IP:  {ip}",
                          command=lambda v=ip: self._set_and_apply("ip", v))
        if user:
            m.add_command(label=f"Filter by user:  {user}",
                          command=lambda v=user: self._set_and_apply("user", v))
        if eid:
            m.add_command(label=f"Filter by Event ID:  {eid}",
                          command=lambda v=eid: self._set_and_apply("eid", v))
        if dom:
            m.add_command(
                label=f"Filter by domain (search):  {dom}",
                command=lambda v=dom: self._set_and_apply("search", v))
        if reason:
            short = reason[:40] + ("..." if len(reason) > 40 else "")
            m.add_command(
                label=f"Filter by failure reason:  {short}",
                command=lambda v=reason: self._set_and_apply("search", v))
        m.add_separator()

        # Kombine drill-in
        if ip and user:
            m.add_command(
                label=f"This IP + this user (failure analysis)",
                command=lambda i=ip, u=user: self._set_and_apply_combo(
                    ip=i, user=u, only_failures=True))
        if ip:
            m.add_command(
                label=f"Only failures from this IP",
                command=lambda i=ip: self._set_and_apply_combo(
                    ip=i, only_failures=True))
        if user:
            m.add_command(
                label=f"Only failures from this user",
                command=lambda u=user: self._set_and_apply_combo(
                    user=u, only_failures=True))
        m.add_separator()

        # Kopyalama
        if ip:
            m.add_command(label=f"Copy IP to clipboard",
                          command=lambda v=ip: self._to_clipboard(v))
        if user:
            m.add_command(label=f"Copy user to clipboard",
                          command=lambda v=user: self._to_clipboard(v))
        m.add_command(label="Copy full details to clipboard",
                      command=lambda i=idx: self._copy_event_details(i))
        m.add_separator()

        # Reset
        m.add_command(label="Reset all filters",
                      command=self._reset_filters)

        # Show menu
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _set_and_apply(self, kind: str, value: str):
        if kind == "ip":
            self.filter_ip.set(value)
        elif kind == "user":
            self.filter_user.set(value)
        elif kind == "eid":
            self.filter_eventid.set(value)
        elif kind == "search":
            self.filter_search.set(value)
        self._apply_filters()

    def _set_and_apply_combo(self, ip="", user="", only_failures=False):
        """Birden fazla filtreyi tek seferde uygula (drill-in icin)."""
        if ip:
            self.filter_ip.set(ip)
        if user:
            self.filter_user.set(user)
        if only_failures:
            self.filter_result.set("Audit Failure")
        self._apply_filters()

    def _to_clipboard(self, text: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()  # macOS'ta gerekli
            self.status_var.set(f"Copied to clipboard: {text}")
        except tk.TclError:
            pass

    def _copy_event_details(self, idx: int):
        if not (0 <= idx < len(self.events)):
            return
        ev = self.events[idx]
        lines = [f"{k}\t{ev[k]}" for k in DETAIL_ORDER if ev.get(k)]
        for k, v in ev.get("_extra", {}).items():
            lines.append(f"{k}\t{v}")
        self._to_clipboard("\n".join(lines))

    # ----------------------------------------------------------- Detay paneli

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0])
        except ValueError:
            return
        if not (0 <= idx < len(self.events)):
            return
        ev = self.events[idx]

        lines = [f"{k:<28} {ev[k]}" for k in DETAIL_ORDER if ev.get(k)]
        for k, v in ev.get("_extra", {}).items():
            lines.append(f"{k:<28} {v}")
        self._set_detail("\n".join(lines))

    def _set_detail(self, text: str):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if text:
            self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    # ----------------------------------------------------------- Status

    def _update_status(self):
        total = len(self.events)
        shown = len(self.filtered_indices)
        rendered = len(self.tree.get_children())
        state = "Tail active" if self.tailing else "Stopped"
        vendor = ""
        if self.events:
            mode = self.vendor_mode.get()
            vendor = (f"Vendor: {self.events[-1].get('Vendor', '')}"
                      f"{' (auto-detected)' if mode == 'Auto' else ' (manual)'}"
                      "  |  ")
        if PARSE_STATS["failed"] or PARSE_STATS["repaired"]:
            vendor += (f"Unparsable: {PARSE_STATS['failed']:,} / "
                       f"repaired: {PARSE_STATS['repaired']:,}  |  ")
        msg = (f"{vendor}{state}  |  Total: {total:,}  |  "
               f"Filtered: {shown:,}  |  Shown: {rendered:,}")
        if rendered < shown:
            msg += f"  (son {MAX_DISPLAY_ROWS:,} satir)"
        self.status_var.set(msg)

    # ----------------------------------------------------------- Statistics

    def _show_stats(self):
        """Open a summary statistics window for the filtered events."""
        if not self.events:
            messagebox.showinfo("Statistics", "Open a file first.")
            return
        indices = self.filtered_indices or list(range(len(self.events)))
        events = [self.events[i] for i in indices]

        # Counts
        total = len(events)
        results_c   = Counter(e.get("Result", "") or "(yok)" for e in events)
        eid_c       = Counter(e.get("EventID", "") or "(yok)" for e in events)
        evname_c    = Counter(e.get("EventName", "") or "(yok)" for e in events)
        ip_c        = Counter(e.get("IP", "") for e in events
                              if e.get("IP"))
        user_c      = Counter(e.get("User", "") for e in events
                              if e.get("User"))
        domain_c    = Counter(e.get("Domain", "") for e in events
                              if e.get("Domain"))
        share_c     = Counter(e.get("Share", "") for e in events
                              if e.get("Share"))
        object_c    = Counter(e.get("ObjectName", "") for e in events
                              if e.get("ObjectName"))
        action_c    = Counter(e.get("Action", "") for e in events
                              if e.get("Action")
                              and e.get("EventID") in ("4656", "4663",
                                                       "4660", "4670", "4907"))
        file_user_c = Counter(e.get("User", "") for e in events
                              if e.get("User") and e.get("ObjectName"))
        vendor_c    = Counter(e.get("Vendor", "") for e in events)
        reason_c    = Counter(e.get("FailureReasonString", "") for e in events
                              if e.get("FailureReasonString"))
        # Failure-only IP/User (for attack candidates)
        fail_ip_c   = Counter(e.get("IP", "") for e in events
                              if e.get("IP")
                              and "Failure" in e.get("Result", ""))
        fail_user_c = Counter(e.get("User", "") for e in events
                              if e.get("User")
                              and "Failure" in e.get("Result", ""))
        # Hourly distribution
        hours_c = Counter()
        for e in events:
            td = e.get("TimeDisplay", "")
            if len(td) >= 13:
                hours_c[td[:13]] += 1   # YYYY-MM-DD HH

        win = tk.Toplevel(self)
        win.title("Statistics Summary")
        win.geometry("1100x720")
        win.transient(self)

        # Ust ozet
        head = ttk.Frame(win, padding=(10, 8))
        head.pack(fill="x")
        succ = sum(v for k, v in results_c.items() if "Success" in k)
        fail = sum(v for k, v in results_c.items() if "Failure" in k)
        unique_ips = len(ip_c)
        unique_users = len(user_c)
        rng = "-"
        if events:
            times = [e["TimeDisplay"] for e in events if e.get("TimeDisplay")]
            if times:
                rng = f"{min(times)}  →  {max(times)}"
        summary = (
            f"Total: {total:,}    "
            f"Success: {succ:,}    Failure: {fail:,}    "
            f"Unique IPs: {unique_ips:,}    Unique users: {unique_users:,}\n"
            f"Time range: {rng}    "
            f"Vendors: " + ", ".join(f"{k} {v:,}" for k, v in vendor_c.items())
        )
        ttk.Label(head, text=summary, font=("Segoe UI", 10, "bold"),
                  justify="left").pack(anchor="w")

        # Notebook (sekmeler)
        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        def make_table(parent, columns, rows):
            frm = ttk.Frame(parent)
            tv = ttk.Treeview(frm, columns=columns, show="headings",
                              selectmode="browse")
            for c, w in columns:
                tv.heading(c, text=c)
                tv.column(c, width=w, anchor="w")
            vsb = ttk.Scrollbar(frm, orient="vertical", command=tv.yview)
            tv.configure(yscrollcommand=vsb.set)
            tv.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            frm.rowconfigure(0, weight=1)
            frm.columnconfigure(0, weight=1)
            for r in rows:
                tv.insert("", "end", values=r)
            return frm, tv

        def topk(counter: Counter, k: int = 50):
            tot = sum(counter.values()) or 1
            return [(name, cnt, f"{cnt * 100 / tot:.1f}%")
                    for name, cnt in counter.most_common(k)]

        # Tab: Event ID + EventName
        tab1, _ = make_table(
            nb, [("EventID", 100), ("Event", 220), ("Count", 100), ("%", 80)],
            [(eid, evname_c.most_common(1)[0][0] if not eid else
              next((n for n, _ in evname_c.most_common()
                    if any(e.get("EventID") == eid and e.get("EventName") == n
                           for e in events)), ""),
              cnt, f"{cnt * 100 / max(total, 1):.1f}%")
             for eid, cnt in eid_c.most_common()]
        )
        nb.add(tab1, text=f"Event types ({len(eid_c)})")

        # Tab: Top failure IP'ler  
        tab2, tv2 = make_table(
            nb, [("IP", 180), ("Failure count", 120), ("%", 80)],
            topk(fail_ip_c, 100))
        nb.add(tab2, text=f"Failure IPs ({len(fail_ip_c)})")
        tv2.bind("<Double-1>", lambda _e: self._stats_filter(
            tv2, "IP", win))

        # Tab: Top failure users
        tab3, tv3 = make_table(
            nb, [("User", 180), ("Failure count", 120), ("%", 80)],
            topk(fail_user_c, 100))
        nb.add(tab3, text=f"Failure users ({len(fail_user_c)})")
        tv3.bind("<Double-1>", lambda _e: self._stats_filter(
            tv3, "User", win))

        # Tab: All IPs
        tab4, _ = make_table(
            nb, [("IP", 180), ("Total", 120), ("%", 80)],
            topk(ip_c, 200))
        nb.add(tab4, text=f"All IPs ({len(ip_c)})")

        # Tab: Domain
        tab5, _ = make_table(
            nb, [("Domain", 180), ("Count", 120), ("%", 80)],
            topk(domain_c, 100))
        nb.add(tab5, text=f"Domains ({len(domain_c)})")

        # Tab: Failure reasons
        tab6, _ = make_table(
            nb, [("Error sebebi", 480), ("Count", 100), ("%", 80)],
            topk(reason_c, 100))
        nb.add(tab6, text=f"Failure reasons ({len(reason_c)})")

        # Tabs for file-access (CIFS object) analysis
        tab8, _ = make_table(
            nb, [("Share", 220), ("Count", 100), ("%", 80)], topk(share_c, 100))
        nb.add(tab8, text=f"Shares ({len(share_c)})")

        tab9, _ = make_table(
            nb, [("Object", 560), ("Count", 100), ("%", 80)],
            topk(object_c, 200))
        nb.add(tab9, text=f"Top objects ({len(object_c)})")

        tab10, tv10 = make_table(
            nb, [("User", 180), ("File events", 120), ("%", 80)],
            topk(file_user_c, 100))
        nb.add(tab10, text=f"File access users ({len(file_user_c)})")
        tv10.bind("<Double-1>", lambda _e: self._stats_filter(
            tv10, "User", win))

        tab11, _ = make_table(
            nb, [("Access", 480), ("Count", 100), ("%", 80)],
            topk(action_c, 100))
        nb.add(tab11, text=f"Access types ({len(action_c)})")

        # Tab: Hourly distribution (simple ASCII bar chart)
        tab7 = ttk.Frame(nb)
        nb.add(tab7, text=f"Hourly distribution ({len(hours_c)} saat)")
        txt = tk.Text(tab7, font=("Consolas", 10), wrap="none")
        txt.pack(fill="both", expand=True, padx=4, pady=4)
        if hours_c:
            mx = max(hours_c.values())
            lines = []
            for h in sorted(hours_c):
                cnt = hours_c[h]
                bar = "█" * int(cnt * 50 / mx)
                lines.append(f"{h}  {cnt:>6,}  {bar}")
            txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")

        # Bottom button bar
        btns = ttk.Frame(win, padding=(10, 4, 10, 10))
        btns.pack(fill="x")
        ttk.Label(btns, text="(Double-click a row in IP/User tabs to filter "
                             "on the main screen)",
                  foreground="#555").pack(side="left")
        ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")

    def _stats_filter(self, treeview: ttk.Treeview, kind: str, win: tk.Toplevel):
        """When double-clicked in stats window, apply the corresponding filter on main screen."""
        sel = treeview.selection()
        if not sel:
            return
        value = treeview.item(sel[0], "values")[0]
        if kind == "IP":
            self.filter_ip.set(value)
        elif kind == "User":
            self.filter_user.set(value)
        self._apply_filters()
        win.lift()  # bring window forward so user can continue

    # ----------------------------------------------------------- CSV export

    def _export_csv(self):
        if not self.filtered_indices:
            messagebox.showinfo(
                "CSV", "No events to export (no records match the filter).")
            return
        p = filedialog.asksaveasfilename(
            title="Save filtered records",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if not p:
            return
        cols = ["TimeDisplay", "Vendor", "EventID", "EventName", "Source",
                "Result", "Computer", "IP", "User", "Domain", "Share",
                "ObjectName", "ObjectType", "Action", "AccessMask",
                "IpAddress", "IpPort",
                "TargetUserName", "TargetDomainName", "TargetUserSid",
                "Status", "FailureReason", "FailureReasonString",
                "AuthenticationPackageName", "LogonType"]
        try:
            with open(p, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(cols)
                for idx in self.filtered_indices:
                    ev = self.events[idx]
                    w.writerow([ev.get(c, "") for c in cols])
            messagebox.showinfo(
                "CSV", f"{len(self.filtered_indices):,} rows saved:\n{p}")
        except OSError as e:
            messagebox.showerror("CSV error", str(e))

    # ----------------------------------------------------------- Kapanis

    def _on_close(self):
        self._stop_tail()
        self.destroy()


# ---------------------------------------------------------------------------

def _parse_cli_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netapp_audit_viewer",
        description="NetApp ONTAP CIFS Security Audit XML viewer (GUI, tail).")
    p.add_argument("path", nargs="?",
                   help="XML file to load on startup (optional).")
    p.add_argument("--tail", "-t", action="store_true",
                   help="Automatically open file and start tailing.")
    p.add_argument("--filter-ip", default="",
                   help="Pre-fill the IP-contains filter on startup.")
    p.add_argument("--filter-user", default="",
                   help="Pre-fill the user-contains filter on startup.")
    p.add_argument("--filter-eventid", default="",
                   help="Pre-filter by a specific EventID on startup (e.g. 4625).")
    p.add_argument("--vendor", default="Auto",
                   type=lambda v: v.capitalize(),
                   choices=["Auto", "Netapp", "Huawei"],
                   help="Storage vendor label (default: auto-detect).")
    p.add_argument("--only-failures", action="store_true",
                   help="Show only Audit Failure events on startup.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None):
    args = _parse_cli_args(argv if argv is not None else sys.argv[1:])
    app = AuditViewer()

    if args.path:
        app.path_var.set(os.path.abspath(args.path))
    if args.filter_ip:
        app.filter_ip.set(args.filter_ip)
    if args.filter_user:
        app.filter_user.set(args.filter_user)
    if args.filter_eventid:
        app.filter_eventid.set(args.filter_eventid)
    if args.vendor != "Auto":
        app.vendor_mode.set("NetApp" if args.vendor == "Netapp" else args.vendor)
    if args.only_failures:
        app.filter_result.set("Audit Failure")
    if args.path and args.tail:
        # Tk event loop baslamadan once start_tail cagirma; minik gecikme ile yap
        app.after(200, app._start_tail)

    app.mainloop()


if __name__ == "__main__":
    main()
