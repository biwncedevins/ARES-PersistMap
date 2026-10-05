"""Plain-text report. Designed to be greppable and paste-friendly."""

from __future__ import annotations

from typing import Optional

from app.models.scan_result import ScanResult

_SEP = "=" * 78
_THIN = "-" * 78


def _section(title: str) -> str:
    return f"\n{_SEP}\n{title}\n{_SEP}\n"


def render_txt(result: ScanResult) -> str:
    lines = []
    lines.append(_SEP)
    lines.append("PersistMap - Windows Persistence Inventory")
    lines.append(_SEP)
    lines.append(f"Scan ID      : {result.scan_id}")
    lines.append(f"Started      : {result.scan_started}")
    lines.append(f"Finished     : {result.scan_finished or 'n/a'}")
    lines.append(f"Computer     : {result.computer_name}")
    lines.append(f"OS           : {result.os_name} {result.os_version} ({result.os_architecture})")
    lines.append(f"Tool version : {result.tool_version}")
    lines.append(f"Privilege    : {result.privilege}")

    lines.append(_section("Collection Status"))
    if not result.sources:
        lines.append("  (no collectors ran)")
    for s in result.sources:
        lines.append(f"  {s.source:<18} {str(s.status):<14} entries={s.entry_count}"
                     + (f"  {s.detail}" if s.detail else ""))

    lines.append(_section("Collection Problems / Warnings"))
    if not result.problems:
        lines.append("  (none)")
    for p in result.problems:
        lines.append(f"  [{p.level}] {p.source}: {p.message}")

    counts = result.count_by_source()
    lines.append(_section("Summary"))
    lines.append(f"  Total entries         : {len(result.entries)}")
    lines.append(f"  Registry              : {counts.get('Registry', 0)}")
    lines.append(f"  Startup               : {counts.get('Startup', 0)}")
    lines.append(f"  Scheduled Tasks       : {counts.get('Scheduled Task', 0)}")
    lines.append(f"  Services              : {counts.get('Service', 0)}")
    lines.append(f"  WMI                   : {counts.get('WMI', 0)}")
    lines.append(f"  Flagged (risk>=50)    : {result.flagged_count}")
    lines.append(f"  Unsigned              : {result.unsigned_count}")
    lines.append(f"  Missing targets       : {result.missing_target_count}")

    lines.append(_section("Persistence Entries"))
    if not result.entries:
        lines.append("  No persistence entries found.")
    for idx, e in enumerate(result.entries, start=1):
        lines.append(_THIN)
        lines.append(f"[{idx}] {e.risk_level.upper()} (risk {e.risk_score}) {str(e.source)} / {e.name}")
        lines.append(f"    Category : {e.category}")
        lines.append(f"    Path     : {e.path or 'n/a'}")
        if e.command:
            lines.append(f"    Command  : {e.command}")
        if e.arguments:
            lines.append(f"    Args     : {e.arguments}")
        lines.append(f"    User     : {e.user}")
        lines.append(f"    Status   : {e.status}")
        lines.append(f"    Signer   : {e.signer_status}"
                     + (f"  ({e.publisher})" if e.publisher else ""))
        lines.append(f"    File     : {e.file_state}")
        if e.sha256:
            lines.append(f"    SHA256   : {e.sha256}")
        if e.duplicate_group_id:
            lines.append(f"    DupGroup : {e.duplicate_group_id}")
        if e.indicators:
            lines.append("    Indicators:")
            for ind in e.indicators:
                ev = f" => {ind.evidence}" if ind.evidence else ""
                lines.append(f"      - {ind.label}{ev}")
        if e.risk_reasons:
            lines.append("    Risk reasons:")
            for r in e.risk_reasons:
                lines.append(f"      {r}")
        for ev in e.evidence_raw:
            lines.append(f"    Evidence: {ev}")
    lines.append(_SEP)
    return "\n".join(lines)


def export_txt(result: ScanResult, file_path: str, errors: Optional[callable] = None) -> bool:
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(render_txt(result))
        return True
    except OSError as exc:
        if errors:
            errors("TXT Export", f"{file_path}: {exc}")
        return False