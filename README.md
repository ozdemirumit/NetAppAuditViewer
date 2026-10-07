# NetApp Audit XML Viewer

A single-file Python GUI for browsing **NetApp ONTAP** and **Huawei OceanStor (e.g. 5510) CIFS Security Audit XML** logs. Opens large files instantly, follows them like `tail -f` as new events are written, and lets you slice the data by user, IP, time range, and event type — with no external dependencies beyond Python's standard library.

Built for storage and infrastructure engineers who need to triage `audit_*.xml` output without spinning up Splunk/ELK.

[![PyPI](https://img.shields.io/pypi/v/netapp-audit-viewer.svg)](https://pypi.org/project/netapp-audit-viewer/) [![Python versions](https://img.shields.io/pypi/pyversions/netapp-audit-viewer.svg)](https://pypi.org/project/netapp-audit-viewer/) ![status: working](https://img.shields.io/badge/status-working-brightgreen) ![deps: stdlib only](https://img.shields.io/badge/deps-stdlib%20only-success) ![license: MIT](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Features

- **Separate Open File / Start Tail buttons** — *Open File* loads the file once (no following); *Start Tail* follows it for new events, continuing right after the loaded content if you opened it first.
- **Live tail** — watches the XML file and streams new events to the table as they're written, with proper handling of partial events that get split across writes.
- **Rotated file support** — point it at a folder and it loads `audit.xml`, `audit.xml-1`, `audit.xml.0` etc. in chronological order, then tails the newest one.
- **Huawei OceanStor support** — auto-detects Huawei audit XML (`Huawei-Security-Auditing`, namespaced `<Event>`, `<Events>` wrapper). Adds a `Share` column and a Vendor selector in the top bar (Auto / NetApp / Huawei; Auto detects the vendor from the file and shows it in the status bar; CLI: `--vendor huawei`), decodes `%%4416`-style `AccessList` codes, and file-access statistics tabs (Shares, Top objects, File access users, Access types).
- **Unified columns for both event families** — logon events (4624/4625/4634) and file-operation events (4656/4663/4670/4907) share a single `User` / `IP` / `Object` / `Action` view, so you don't have to know which schema applies.
- **Filters** — Event ID, Result, User, IP, time range (with `Last 1 hour` / `Last 24 hours` shortcuts), and a free-text search across all fields. Filters apply as you type (debounced).
- **Right-click drill-in** — right-click any row to instantly filter by that IP/user, or run a combined "this IP + this user, failures only" pivot. Also copies values to clipboard.
- **Statistics window** — top failure IPs, top failure users, hourly distribution as ASCII bar chart, double-click to filter the main table.
- **CSV export** — UTF-8 with BOM and `;` delimiter, opens cleanly in Excel with a Turkish or other non-ASCII locale.
- **CLI flags** — pre-load filters from the command line, e.g. for shortcut-driven workflows.
- **No installation, no dependencies** — single `.py` file, only Python stdlib (`tkinter` ships with Python on Windows by default).

---

## Install

From PyPI:

```bash
pip install netapp-audit-viewer
netapp-audit-viewer
```

Or run directly from source — no install needed since the only dependency is the Python stdlib:

```bash
git clone https://github.com/ozdemirumit/NetAppAuditViewer.git
cd NetAppAuditViewer
python netapp_audit_viewer.py
```

Works on Windows, Linux and macOS.

---

## Quick start

```bash
netapp-audit-viewer
netapp-audit-viewer /path/to/audit_log.xml
netapp-audit-viewer /path/to/audit_log.xml --tail
netapp-audit-viewer /path/to/audit_log.xml --filter-ip 10.0.0.5 --only-failures --tail
```

(If running from source, substitute `python netapp_audit_viewer.py` for `netapp-audit-viewer`.)

### CLI options

| Flag | Description |
|---|---|
| `path` (positional) | XML file to open on startup. |
| `--tail`, `-t` | Auto-open the file and start tailing immediately. |
| `--filter-ip IP` | Pre-fill the IP-contains filter. |
| `--filter-user USER` | Pre-fill the user-contains filter. |
| `--filter-eventid ID` | Pre-filter by a specific Event ID (e.g. `4625`). |
| `--vendor V` | Vendor label: `auto` (default), `netapp` or `huawei`. |
| `--only-failures` | Show only `Audit Failure` events on startup. |

---

## Supported events

The parser recognises two families of NetApp CIFS audit events and exposes them through unified columns:

| Event ID | Name | Family | Key fields |
|---|---|---|---|
| 4624 | Logon Attempt | Logon | `TargetUserName`, `IpAddress` |
| 4625 | Logon Failure | Logon | `TargetUserName`, `IpAddress`, `FailureReasonString` |
| 4634 | Logoff | Logon | `TargetUserName`, `IpAddress` |
| 4656 | Open Object | File-op | `SubjectUserName`, `SubjectIP`, `ObjectName`, `DesiredAccess` |
| 4663 | Get Object Attributes | File-op | `SubjectUserName`, `SubjectIP`, `ObjectName`, `InformationRequested` |
| 4670 | Permissions Changed | File-op | `SubjectUserName`, `ObjectName`, `OldSD`, `NewSD` |
| 4907 | Auditing Settings Changed | File-op | `SubjectUserName`, `ObjectName`, `OldSD`, `NewSD` |

Other event types are still parsed and shown — only the unified `User`/`IP`/`Object`/`Action` columns may be empty for unrecognised IDs.

---

## Real-world example

Here's a quick triage on a 54 MB / 54,806-event audit file from a production CIFS share:

```
Event distribution
  4625 Logon Failure          49,839
  4624 Logon Attempt           3,003
  4634 Logoff                  1,841
  4656 Open Object                54
  4663 Get Object Attributes      52
  4907 Auditing Settings           9
  4670 Permissions Changed         8

Top failure IPs
  172.17.10.165   37,350  (74.9%)   <- single host, almost the whole file
  172.17.10.150    3,625   (7.3%)
  172.17.9.9       2,047   (4.1%)

Top failure usernames
  tb2783          37,350  (74.9%)   <- repeating against the same SVM
  tb1386           3,675   (7.4%)

Top failure reasons
  No such user account                              44,186  (88.7%)
  User name is correct but the password is wrong    3,858   (7.7%)
  Unknown user name or bad password                 1,780   (3.6%)
```

A single host hammering one username with `No such user account` failures over multiple days — classic credential-stuffing pattern. From the GUI, this is two clicks: open the Statistics window → double-click `172.17.10.165` in the Failure IPs tab → main table is filtered to that IP for further review or CSV export to the SOC team.

---

## Build a Windows `.exe`

Ship the viewer to colleagues who don't have Python installed. The build produces a **single, self-contained `NetAppAuditViewer.exe`** — the Python runtime, Tcl/Tk and every required DLL are packed inside it, so **no external DLLs, no Python install and no extra files** are needed on the target machine. Copy the one file anywhere and run it.

### Using `build.bat` (recommended)

`build.bat` is included in the repo. On a Windows machine with Python 3.10+ installed:

1. Open the repo folder.
2. Double-click `build.bat` (or run it from `cmd`).
3. Take the result from `dist\NetAppAuditViewer.exe`.

What the script does:

- Removes previous `build\` and `dist\` folders.
- Installs [PyInstaller](https://pyinstaller.org) with `pip` if it is missing.
- Runs PyInstaller with `--onefile --windowed --clean`, which gives one exe and no console window.
- Stops with an error message if the build fails.

### Manual build

```cmd
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name "NetAppAuditViewer" --clean netapp_audit_viewer.py
```

**Notes:**
- A `--onefile` exe unpacks itself to a temporary folder on every start, so launch takes a second or two longer. Corporate antivirus sometimes flags PyInstaller's onefile bootloader — whitelist the exe if that happens. If it keeps being quarantined, build without `--onefile` (folder build in `dist\NetAppAuditViewer\`, more AV-friendly, but you must ship the whole folder).
- The exe must be built on Windows; PyInstaller cannot cross-compile from Linux/macOS.
- Add `--icon=audit.ico` if you want a custom icon.
- For a tiny portable alternative when target machines have Python: `python -m zipapp . -m "netapp_audit_viewer:main" -o NetAppAuditViewer.pyz` produces a ~40 KB single-file zipapp.

---

## How tail works (technical note)

The tail thread reads the file in chunks starting from the last position, keeps a buffer of unparsed bytes, and emits parsed events to the GUI thread via a `queue.Queue`. If a write happens mid-event, the partial bytes stay in the buffer until the closing `</Event>` arrives — no malformed records ever reach the table. File rotation/truncation is detected by comparing on-disk size to the last read position.

The GUI never blocks on disk I/O. Filtering is debounced (250 ms) so you can type freely without freezing the UI on a 100k-event dataset.

---

## Limitations

- The Treeview shows at most 10,000 rows at a time (configurable via `MAX_DISPLAY_ROWS` at the top of the file). All events are kept in memory; only the displayed slice is capped for rendering performance.
- Memory footprint is roughly 1.5 KB per event, so 1M events ≈ 1.5 GB RAM. For larger datasets, filter on import or split the file first.
- Dates and times are interpreted as the literal string in `TimeCreated/@SystemTime` (UTC in NetApp's output). No timezone conversion.

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. Particularly interested in:
- Coverage of additional NetApp event IDs (NFS audit, anti-virus events, etc.)
- Performance improvements for very large files (memory-mapped reading?)
- Optional Splunk/ELK forwarder mode
