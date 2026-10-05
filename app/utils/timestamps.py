"""Timestamp helpers.

Windows timestamps come in many shapes (FILETIME, ISO from COM, None...).
We defensively convert to a readable UTC/local string, never crashing, and
fall back to explicit unknown constants when the value is unusable.
"""

from __future__ import annotations

import datetime
from typing import Any, Optional

from app.models.enums import DEFAULT_NOT_REPORTED, DEFAULT_UNAVAILABLE, DEFAULT_UNKNOWN


def _format(dt: datetime.datetime | datetime.date | None) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def from_datetime(value: Any) -> str:
    """Normalize a datetime/date to a display string."""
    if isinstance(value, datetime.datetime):
        return _format(value)
    if isinstance(value, datetime.date):
        return value.strftime("%Y-%m-%d")
    return ""


def from_iso(value: Any) -> str:
    """Parse an ISO string/datetime to display format; returns '' on failure."""
    if isinstance(value, datetime.datetime):
        return _format(value)
    if value in (None, "", "None"):
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d"):
            try:
                return _format(datetime.datetime.strptime(text, fmt))
            except ValueError:
                continue
    return ""


def from_epoch_seconds(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return ""
    try:
        return _format(datetime.datetime.fromtimestamp(seconds))
    except (OverflowError, OSError, ValueError):
        return ""


def from_filetime(value: Any) -> str:
    """FILETIME (100ns since 1601). COM/WMI sometimes give it directly."""
    if value in (None, ""):
        return ""
    try:
        ft = float(value)
    except (TypeError, ValueError):
        return ""
    if ft <= 0:
        return ""
    try:
        return _format(datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft / 10.0))
    except (OverflowError, ValueError):
        return ""


def from_com_date(value: Any) -> str:
    """COM automation date (OLE date)."""
    if value in (None, ""):
        return ""
    try:
        days = float(value)
    except (TypeError, ValueError):
        return ""
    if not (0 <= days <= 109205):
        return ""
    try:
        epoch = datetime.datetime(1899, 12, 30)
        return _format(epoch + datetime.timedelta(days=days))
    except (OverflowError, ValueError):
        return ""


def now_local() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def win32_ticks(value: Any) -> str:
    """Milliseconds since 1601 (as returned by some WMI providers)."""
    if value in (None, ""):
        return ""
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return ""
    if ms <= 0:
        return ""
    try:
        return _format(datetime.datetime(1601, 1, 1) + datetime.timedelta(milliseconds=ms))
    except (OverflowError, ValueError):
        return ""


__all__ = [
    "from_datetime", "from_iso", "from_epoch_seconds", "from_filetime",
    "from_com_date", "now_local", "win32_ticks",
    "DEFAULT_UNKNOWN", "DEFAULT_UNAVAILABLE", "DEFAULT_NOT_REPORTED",
]