"""Unified persistence entry model.

Every artifact - registry run key, startup file, scheduled task,
Windows service or WMI subscription - is normalized into this single
record so it can live in one table.

The model deliberately keeps both ``raw_*`` evidence and normalized
values. If a field is genuinely unavailable the string constants from
:mod:`app.models.enums` are used instead of invented data.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.enums import (
    DEFAULT_NOT_REPORTED,
    DEFAULT_UNAVAILABLE,
    DEFAULT_UNKNOWN,
    EntryStatus,
    RiskLevel,
    SignerStatus,
    Source,
)


def _risk_level_from_score(score: int) -> RiskLevel:
    if score <= 20:
        return RiskLevel.LOW
    if score <= 40:
        return RiskLevel.MEDIUM
    if score <= 60:
        return RiskLevel.ELEVATED
    if score <= 80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


@dataclass
class Indicator:
    """A single explainable detection note."""

    #: Human-readable label, e.g. "Encoded Command"
    label: str
    #: Machine tag (see IndicatorType) - a str to stay serialization-simple
    tag: str
    #: Optional human-readable evidence snippet (the value that tripped it)
    evidence: Optional[str] = None
    #: Optional risk-point contribution (used by the risk engine)
    points: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "tag": self.tag,
            "evidence": self.evidence,
            "points": self.points,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Indicator":
        return cls(
            label=str(data.get("label", "")),
            tag=str(data.get("tag", "")),
            evidence=data.get("evidence"),
            points=data.get("points"),
        )


@dataclass
class RiskReport:
    """Explainable risk scoring result."""

    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def level(self) -> RiskLevel:
        return _risk_level_from_score(self.score)

    def to_dict(self) -> dict:
        return {"score": self.score, "level": str(self.level), "reasons": list(self.reasons)}

    @classmethod
    def from_dict(cls, data: dict) -> "RiskReport":
        return cls(score=int(data.get("score", 0)), reasons=list(data.get("reasons", [])))


def _stable_id(seed: str) -> str:
    """Deterministic id from content seeding (stable across runs)."""
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class PersistenceEntry:
    """Normalized record for one persistence point."""

    # Identity
    source: str = ""                     # Source enum value
    category: str = ""                   # e.g. "Run", "Startup", "Task", "Service", "WMI"
    name: str = ""
    id: str = ""

    # Execution
    path: str = ""
    command: str = ""
    arguments: str = ""
    working_directory: str = ""

    # Context
    user: str = ""
    hive: str = ""
    key_path: str = ""
    value_name: str = ""
    architecture: str = ""

    # Signature / file facts
    publisher: str = ""
    signer_status: str = ""
    file_state: str = ""
    sha256: str = ""
    file_size: int | None = None
    file_extension: str = ""

    # Timeline
    created_time: str = ""
    modified_time: str = ""
    last_run_time: str = ""
    next_run_time: str = ""

    # Status (enabled/stopped/...)
    status: str = ""

    # Analysis results
    risk_score: int = 0
    risk_level: str = ""
    risk_reasons: list[str] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    duplicate_group_id: str = ""
    flagged: bool = False

    # Evidence
    evidence_raw: list[str] = field(default_factory=list)  # plain-line evidence
    raw_data: dict[str, Any] = field(default_factory=dict)  # source-specific raw

    # ------------------------------------------------------------------
    def __post_init__(self) -> None:
        if not self.id:
            seed = "|".join([str(self.source), str(self.category), str(self.name),
                             str(self.path), str(self.command), str(self.user)])
            self.id = _stable_id(seed)
        if self.flagged is False:
            self.flagged = self.risk_score >= 50
        if not self.risk_level:
            self.risk_level = str(_risk_level_from_score(self.risk_score)).lower().capitalize() \
                if self.risk_score else RiskLevel.LOW.value

    # ------------------------------------------------------------------
    def indicator_labels(self) -> list[str]:
        return [i.label for i in self.indicators]

    def indicator_tags(self) -> list[str]:
        return [i.tag for i in self.indicators]

    def add_indicator(self, label: str, tag: str, evidence: Any = None, points: int | None = None) -> None:
        ev = None if evidence is None else str(evidence)
        self.indicators.append(Indicator(label=label, tag=tag, evidence=ev, points=points))

    def has_indicator(self, tag: str) -> bool:
        return any(i.tag == tag for i in self.indicators)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": str(self.source or DEFAULT_UNKNOWN),
            "category": str(self.category or DEFAULT_UNKNOWN),
            "name": self.name,
            "path": self.path,
            "command": self.command,
            "arguments": self.arguments,
            "working_directory": self.working_directory,
            "user": self.user,
            "hive": self.hive,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "architecture": self.architecture,
            "publisher": self.publisher,
            "signer_status": str(self.signer_status or DEFAULT_UNKNOWN),
            "file_state": str(self.file_state or DEFAULT_UNAVAILABLE),
            "sha256": self.sha256,
            "file_size": self.file_size,
            "file_extension": self.file_extension,
            "created_time": self.created_time,
            "modified_time": self.modified_time,
            "last_run_time": self.last_run_time,
            "next_run_time": self.next_run_time,
            "status": str(self.status or DEFAULT_UNKNOWN),
            "risk_score": self.risk_score,
            "risk_level": str(self.risk_level or DEFAULT_UNKNOWN),
            "risk_reasons": list(self.risk_reasons),
            "indicators": [i.to_dict() for i in self.indicators],
            "duplicate_group_id": self.duplicate_group_id,
            "flagged": self.flagged,
            "evidence": list(self.evidence_raw),
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PersistenceEntry":
        entry = cls(
            source=data.get("source", "") or DEFAULT_UNKNOWN,
            category=data.get("category", "") or DEFAULT_UNKNOWN,
            name=data.get("name", "") or "",
            id=data.get("id", "") or "",
            path=data.get("path", "") or "",
            command=data.get("command", "") or "",
            arguments=data.get("arguments", "") or "",
            working_directory=data.get("working_directory", "") or "",
            user=data.get("user", "") or "",
            hive=data.get("hive", "") or "",
            key_path=data.get("key_path", "") or "",
            value_name=data.get("value_name", "") or "",
            architecture=data.get("architecture", "") or "",
            publisher=data.get("publisher", "") or "",
            signer_status=data.get("signer_status", "") or DEFAULT_UNKNOWN,
            file_state=data.get("file_state", "") or DEFAULT_UNAVAILABLE,
            sha256=data.get("sha256", "") or "",
            file_size=data.get("file_size"),
            file_extension=data.get("file_extension", "") or "",
            created_time=data.get("created_time", "") or "",
            modified_time=data.get("modified_time", "") or "",
            last_run_time=data.get("last_run_time", "") or "",
            next_run_time=data.get("next_run_time", "") or "",
            status=data.get("status", "") or DEFAULT_UNKNOWN,
            risk_score=int(data.get("risk_score", 0) or 0),
            risk_level=data.get("risk_level", "") or "",
            risk_reasons=list(data.get("risk_reasons", [])),
            duplicate_group_id=data.get("duplicate_group_id", "") or "",
            flagged=bool(data.get("flagged", False)),
        )
        entry.indicators = [Indicator.from_dict(i) for i in data.get("indicators", [])]
        entry.evidence_raw = list(data.get("evidence", []))
        entry.raw_data = dict(data.get("raw_data", {}) or {})
        return entry

    # ------------------------------------------------------------------
    def display_path(self) -> str:
        return self.path or (self.command or "")

    def short_path(self, limit: int = 80) -> str:
        p = self.display_path()
        if len(p) <= limit:
            return p
        head = p[: limit // 2 - 3]
        tail = p[-(limit // 2 - 2):]
        return f"{head}...{tail}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<PersistenceEntry {self.source}:{self.name} risk={self.risk_score}>"


# Convenience aliases used by modules that build entries.
def make_entry(*, source: Source, **kw: Any) -> PersistenceEntry:
    """Create an entry, coercing the source to its string value."""
    kw["source"] = source.value if isinstance(source, Source) else source
    return PersistenceEntry(**kw)