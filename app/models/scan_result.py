"""Aggregated scan result: entries + per-source collection status + errors.

This is the object handed back from the scan worker to the UI and used as
the single source of truth for reports.
"""

from __future__ import annotations

import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from app.models.entry import PersistenceEntry
from app.models.enums import CollectionStatus


@dataclass
class CollectionProblem:
    """A recorded non-fatal collection issue."""

    source: str
    message: str
    level: str = "WARNING"  # WARNING | ERROR | INFO

    def to_dict(self) -> dict:
        return {"source": self.source, "message": self.message, "level": self.level}

    @classmethod
    def from_dict(cls, data: dict) -> "CollectionProblem":
        return cls(source=data.get("source", ""), message=data.get("message", ""),
                   level=data.get("level", "WARNING"))


@dataclass
class SourceResult:
    """Per-source collection outcome."""

    source: str
    status: CollectionStatus = CollectionStatus.NOT_RUN
    entry_count: int = 0
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "status": str(self.status),
            "entry_count": self.entry_count,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SourceResult":
        return cls(
            source=data.get("source", ""),
            status=CollectionStatus(data.get("status", "Not Run")),
            entry_count=int(data.get("entry_count", 0)),
            detail=data.get("detail", ""),
        )


@dataclass
class ScanResult:
    """Complete result of one scan."""

    entries: list[PersistenceEntry] = field(default_factory=list)
    problems: list[CollectionProblem] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    scan_started: str = ""
    scan_finished: str = ""
    computer_name: str = ""
    os_name: str = ""
    os_version: str = ""
    os_architecture: str = ""
    tool_version: str = ""
    privilege: str = ""
    scan_id: str = ""

    # ------------------------------------------------------------------
    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat(timespec="seconds")

    @classmethod
    def begin(cls, tool_version: str, privilege: str, scan_id: str) -> "ScanResult":
        return cls(
            scan_started=cls._now(),
            computer_name=socket.gethostname() or "Unknown",
            os_name=platform.system(),
            os_version=platform.version(),
            os_architecture=platform.machine(),
            tool_version=tool_version,
            privilege=privilege,
            scan_id=scan_id,
        )

    def finish(self) -> None:
        self.scan_finished = self._now()

    # ------------------------------------------------------------------
    def add_entry(self, entry: PersistenceEntry) -> None:
        self.entries.append(entry)

    def add_entries(self, entries: list[PersistenceEntry]) -> None:
        self.entries.extend(entries)

    def add_problem(self, source: str, message: str, level: str = "WARNING") -> None:
        self.problems.append(CollectionProblem(source=source, message=message, level=level))

    def set_source_status(self, source: str, status: CollectionStatus,
                          entry_count: int = 0, detail: str = "") -> None:
        for s in self.sources:
            if s.source == source:
                s.status = status
                s.entry_count = entry_count
                s.detail = detail
                return
        self.sources.append(SourceResult(source=source, status=status,
                                         entry_count=entry_count, detail=detail))

    def get_source_status(self, source: str) -> Optional[SourceResult]:
        for s in self.sources:
            if s.source == source:
                return s
        return None

    # ------------------------------------------------------------------
    def count_by_source(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entries:
            counts[str(e.source)] = counts.get(str(e.source), 0) + 1
        return counts

    @property
    def flagged_count(self) -> int:
        return sum(1 for e in self.entries if e.flagged)

    @property
    def unsigned_count(self) -> int:
        return sum(1 for e in self.entries if str(e.signer_status) == "Unsigned")

    @property
    def missing_target_count(self) -> int:
        return sum(1 for e in self.entries if str(e.file_state) == "Missing")

    @property
    def wmi_count(self) -> int:
        return self.count_by_source().get("WMI", 0)

    @property
    def has_warnings(self) -> bool:
        return any(p.level in ("WARNING", "ERROR") for p in self.problems)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "scan_id": self.scan_id,
            "scan_started": self.scan_started,
            "scan_finished": self.scan_finished,
            "computer_name": self.computer_name,
            "os": {
                "name": self.os_name,
                "version": self.os_version,
                "architecture": self.os_architecture,
            },
            "tool": {"name": "PersistMap", "version": self.tool_version},
            "privilege": self.privilege,
            "sources": [s.to_dict() for s in self.sources],
            "problems": [p.to_dict() for p in self.problems],
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        result = cls(
            scan_started=data.get("scan_started", ""),
            scan_finished=data.get("scan_finished", ""),
            computer_name=data.get("computer_name", ""),
            os_name=(data.get("os") or {}).get("name", ""),
            os_version=(data.get("os") or {}).get("version", ""),
            os_architecture=(data.get("os") or {}).get("architecture", ""),
            tool_version=(data.get("tool") or {}).get("version", ""),
            privilege=data.get("privilege", ""),
            scan_id=data.get("scan_id", ""),
        )
        result.sources = [SourceResult.from_dict(s) for s in data.get("sources", [])]
        result.problems = [CollectionProblem.from_dict(p) for p in data.get("problems", [])]
        result.entries = [PersistenceEntry.from_dict(e) for e in data.get("entries", [])]
        return result

    def summary_text(self) -> str:
        c = self.count_by_source()
        lines = [
            f"Total entries: {len(self.entries)}",
            f"Registry: {c.get('Registry', 0)}",
            f"Startup: {c.get('Startup', 0)}",
            f"Scheduled Tasks: {c.get('Scheduled Task', 0)}",
            f"Services: {c.get('Service', 0)}",
            f"WMI: {c.get('WMI', 0)}",
            f"Flagged: {self.flagged_count}",
            f"Unsigned: {self.unsigned_count}",
            f"Missing targets: {self.missing_target_count}",
        ]
        return "\n".join(lines)