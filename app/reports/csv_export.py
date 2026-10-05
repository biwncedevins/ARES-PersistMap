"""CSV export. One row per persistence entry. Deterministic column set."""

from __future__ import annotations

import csv
from typing import Optional

from app.models.scan_result import ScanResult

COLUMNS = [
    "id", "source", "category", "name", "path", "command", "arguments",
    "working_directory", "user", "publisher", "signer_status", "file_state",
    "sha256", "status", "architecture", "risk_score", "risk_level", "flagged",
    "duplicate_group_id", "created_time", "modified_time", "last_run_time",
    "next_run_time", "indicators", "evidence",
]


def _row(entry) -> list[str]:
    inds = "; ".join(i.label for i in entry.indicators)
    ev = " | ".join(entry.evidence_raw)
    return [
        entry.id, str(entry.source), str(entry.category), entry.name,
        entry.path, entry.command, entry.arguments, entry.working_directory,
        entry.user, entry.publisher, str(entry.signer_status), entry.file_state,
        entry.sha256, entry.status, entry.architecture,
        str(entry.risk_score), entry.risk_level, "Yes" if entry.flagged else "No",
        entry.duplicate_group_id, entry.created_time, entry.modified_time,
        entry.last_run_time, entry.next_run_time, inds, ev,
    ]


def export_csv(result: ScanResult, file_path: str, errors: Optional[callable] = None) -> bool:
    try:
        with open(file_path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(COLUMNS)
            for e in result.entries:
                writer.writerow(_row(e))
        return True
    except (OSError, csv.Error) as exc:
        if errors:
            errors("CSV Export", f"{file_path}: {exc}")
        return False