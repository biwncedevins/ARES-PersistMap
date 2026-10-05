# PersistMap — Windows Persistence Inventory

A read-only, offline, desktop forensics tool that inventories Windows
persistence points (registry Run/RunOnce, Startup folders, Scheduled Tasks,
Services and WMI permanent event subscriptions) and produces an explainable
risk assessment plus exportable reports.

**PersistMap never modifies the system.** It does not delete, disable,
quarantine or "fix" anything; it does not stop or start services or tasks,
does not touch the registry/WMI/task scheduler, and never executes a
discovered command. Everything stays local — no network access, no telemetry.

## Features

- Five collection sources:
  - **Registry** — per-user and per-machine Run / RunOnce keys, with correct
    64-bit vs. 32-bit (WOW6432Node) view handling so nothing is double counted.
  - **Startup** — user and common Startup folders; inline `.lnk` (MS-SHLLINK)
    binary parser resolves target path, arguments and working directory.
  - **Scheduled Tasks** — Task Scheduler COM API with an automatic
    `schtasks /query` CSV fallback; XML definitions are kept as evidence.
  - **Services** — `psutil` with an `sc query` fallback; svchost-hosted Dlls
    resolved from the registry.
  - **WMI** — permanent event subscriptions, filters and bindings via an
    encoded PowerShell query; degraded gracefully when access is denied.
- **Offline signature checking** — in-process `WinVerifyTrust` via `ctypes`,
  no revocation lookups. Statuses: Signed / Unsigned / Invalid / Unknown /
  Unavailable.
- **Explainable risk scoring** — additive, auditable `+N reason` lines,
  score 0..100, levels Low → Critical. Flags, indicators and reasons are kept
  per entry.
- **Duplicate correlation** — same binary path / hash grouped under a
  `DUP-xxx` id, with one "Duplicate Persistence Path" indicator per group.
- **Hashing** — SHA-256 computed only for flagged files (256 MB cap), cached
  per (path, size, mtime).
- **Reports** — JSON, CSV, TXT and HTML exports with full metadata, sources,
  problems, indicators and risk reasons.
- **UI** — PySide6 (Qt), black/red forensic theme, sidebar navigation, live
  search and filters (source, risk, signer, user, status, flagged/unsigned/
  missing/duplicates), details panel, overview page.

## Requirements

- Windows 10/11 (64-bit)
- Python 3.11+
- `PySide6` and `psutil` (see `requirements.txt`)

## Quick start (from source)

```bat
pip install -r requirements.txt
python app.py
```

or double-click `run.bat`.

## Tests

The suite is fully offline and deterministic — collectors are mocked, no
real malware is needed.

```bat
pip install pytest
python -m pytest tests -q
```

## Build the EXE

```bat
pip install pyinstaller
build.bat
```

This produces `dist\PersistMap\PersistMap.exe` (one-folder build) via
`PersistMap.spec`.

## Verdicts

**PersistMap does not make verdicts.** A high risk score is an invitation to
investigate, not a conclusion. Unsigned does not mean malicious; signed does
not mean benign. Every point in a score is traceable to evidence kept from
the original artifact.

## License

See `LICENSE`.