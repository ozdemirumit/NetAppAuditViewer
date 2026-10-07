# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Huawei OceanStor CIFS audit XML support (namespaced events, `<Events>` wrapper, vendor auto-detection).
- `Share` column, Vendor selector (Auto/NetApp/Huawei) with detected vendor in the status bar, `--vendor` CLI flag.
- `%%NNNN` AccessList decoding; Shares / Top objects / File access users / Access types statistics tabs.

### Changed
- Statistics, context menu, detail pane and CSV now use unified User/IP fields, so file-operation events are included.

## [1.0.0] - 2026-04-22

Initial public release.

### Added
- GUI viewer for NetApp ONTAP CIFS audit XML files (Tkinter, single file).
- Live `tail -f`-style file watching with proper handling of partial events.
- Robust rotation detection covering three real-world scenarios:
  - Rename-based rotation (`mv audit.xml audit.xml-1` + new file created) —
    detected via inode/device change from `os.stat`.
  - In-place truncation (`open(path, "wb")` with same inode) — detected via
    a 4 KB head-content fingerprint, with prefix check to distinguish
    ordinary growth from real truncation.
  - Unlink + recreate — detected via tracking `os.stat` failures and
    resyncing state when the file reappears.
- Folder mode: load all rotated audit files (`audit.xml`, `audit.xml-1`,
  `audit.xml.0`, etc.) in chronological order, then tail the newest.
- Filters: Event ID, Result, User, IP, time range, free-text search.
- "Last 1 hour" / "Last 24 hours" time range shortcuts.
- Right-click context menu: filter by IP/user/event ID, drill-in
  combinations, copy to clipboard.
- Statistics window with top failure IPs, top failure users, hourly
  distribution as ASCII bar chart, and double-click filtering.
- CSV export (UTF-8 with BOM, `;` delimiter for Excel compatibility).
- CLI flags: `--tail`, `--filter-ip`, `--filter-user`, `--filter-eventid`,
  `--only-failures`.
- Unified `User` / `IP` / `Object` / `Action` columns covering both logon
  events (4624/4625/4634) and file-operation events (4656/4663/4670/4907).
- `build.bat` for one-command Windows `.exe` packaging via PyInstaller.

### Tested
- Python 3.10, 3.11, 3.12, 3.13, 3.14 compatibility.
- Real production audit XML, 54k events, 7 distinct event types,
  100% parse success.
- Tail reliability test suite with 10 scenarios covering: byte-by-byte
  writes, 5000-event bursts, rotation during partial events, malformed
  event skipping, unlink+recreate, rename-rotate, repeated in-place
  rotations, and random-chunk-size writes.
