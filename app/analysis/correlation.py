"""Duplicate correlation.

Entries that reference the same normalized binary path (or identical
command lines / hash) are grouped. Groups are informational: each entry
keeps its identity, and the group id is attached so the UI can surface
"3 persistence entries, sources: Registry, Startup, Service".

Two levels are used, strongest first:

1. exact computed SHA256 when available
2. normalized executable path (case-insensitive, env-expanded, quoted-stripped)
3. identical normalized command line (for non-file artifacts)
"""

from __future__ import annotations

import os
from collections import defaultdict

from config import RISK_POINTS
from app.models.entry import Indicator, PersistenceEntry
from app.models.enums import IndicatorType
from app.utils import paths

_GROUP_SEP = "\x1f"


def _norm_path(path: str) -> str:
    if not path:
        return ""
    candidate = paths.expand_env(path)
    if len(candidate) >= 2 and candidate[0] == '"' and candidate[-1] == '"':
        candidate = candidate[1:-1]
    candidate = candidate.replace("/", "\\").strip().lower()
    return candidate


def _normalize_binary(path_or_cmd: str) -> str:
    if not path_or_cmd:
        return ""
    # A bare path (drive/UNC) is taken whole; a command line is reduced to
    # its program so loose argument changes don't break grouping.
    candidate = paths.expand_env(path_or_cmd)
    if candidate[:1] == '"':
        candidate = candidate[1:-1] if candidate.endswith('"') else candidate[1:]
    candidate = candidate.replace("/", "\\").strip().lower()
    return candidate


def correlate(entries: list[PersistenceEntry]) -> dict[int, list[PersistenceEntry]]:
    """Assign duplicate_group_id to entries and return {group_id: entries}."""
    for e in entries:
        e.duplicate_group_id = ""

    by_hash: dict[str, list[PersistenceEntry]] = defaultdict(list)
    by_path: dict[str, list[PersistenceEntry]] = defaultdict(list)
    by_cmd: dict[str, list[PersistenceEntry]] = defaultdict(list)

    for e in entries:
        if e.sha256:
            by_hash[e.sha256.lower()].append(e)
        bin_path = _normalize_binary(e.path or e.command)
        if bin_path:
            by_path[bin_path].append(e)
        cmd_norm = (paths.expand_env(e.command or "") or "").strip().lower()
        if cmd_norm:
            by_cmd[cmd_norm].append(e)

    seen: set[str] = set()
    group_counter = 0
    groups: dict[int, list[PersistenceEntry]] = {}

    def _make_group(members: list[PersistenceEntry]) -> None:
        fresh = [m for m in members if m.id not in seen]
        if not fresh:
            return
        nonlocal group_counter
        group_counter += 1
        gid = f"DUP-{group_counter:03d}"
        for m in members:
            if m.id in seen:
                continue
            m.duplicate_group_id = gid
            seen.add(m.id)
            groups.setdefault(gid, []).append(m)
        if len(groups[gid]) > 1:
            for m in groups[gid]:
                # remove previously-added duplicate markers, append fresh
                m.indicators = [i for i in m.indicators
                                if i.label != "Duplicate Persistence Path"] + [
                    Indicator(tag=IndicatorType.DUPLICATE_BINARY.value,
                              label="Duplicate Persistence Path",
                              evidence=gid,
                              points=RISK_POINTS["multiple_entries_same_binary"])]

    # strongest grouping first
    for members in by_hash.values():
        _make_group(members)
    for members in by_path.values():
        _make_group(members)
    for members in by_cmd.values():
        _make_group(members)

    return groups