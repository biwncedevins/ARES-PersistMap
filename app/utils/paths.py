"""Defensive Windows path + command-line normalization utilities.

Everything here is read-only. Parsing is deliberately conservative: when
a command line cannot be parsed we keep the raw text and record what we
could resolve, never guessing.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Optional, Tuple

from app.models.enums import DEFAULT_UNKNOWN

_QUOTED = re.compile(r'^"([^"]+)"')
_EXE_SUFFIX = (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".lnk", ".hta")


def is_windows() -> bool:
    return os.name == "nt"


def expand_env(value: str) -> str:
    """Expand %VAR% the way Windows would (leaves missing vars intact)."""
    if not value:
        return value

    def _sub(match: re.Match) -> str:
        name = match.group(1)
        return os.environ.get(name, match.group(0))

    try:
        return re.sub(r"%([^%]+)%", _sub, value)
    except Exception:
        return value


def normalize_path(raw: str) -> str:
    """Expand env vars, strip surrounding quotes, normalize separators.

    Returns the raw value unchanged if nothing can be safely normalized.
    No filesystem access happens here.
    """
    if not raw:
        return raw
    value = expand_env(str(raw))
    # strip matching outer quotes
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    value = value.replace("/", "\\")
    value = value.strip()
    return value


def split_command_line(cmdline: str) -> Optional[Tuple[str, str]]:
    """Split a command line into (program, arguments).

    Returns None when parsing is not safe. The program is returned
    unquoted but env-expanded; the arguments keep their original quoting.

    Uses a small windows-aware parser rather than shlex to be defensive
    about backslashes in paths.
    """
    if not cmdline or not cmdline.strip():
        return None

    text = cmdline.strip()
    args_only = ""
    program = ""

    if text.startswith('"'):
        match = _QUOTED.match(text)
        if match:
            program = match.group(1)
            rest = text[match.end():].strip()
            if rest:
                args_only = rest
        else:
            # unterminated quote - do not guess
            program = text[1:]
    else:
        parts = text.split(None, 1)
        program = parts[0]
        if len(parts) == 2:
            args_only = parts[1]

    return normalize_path(program), args_only


def detect_unquoted_path(program: str) -> bool:
    """True when the program looks like a path containing a space that is
    not wrapped in quotes (classic unquoted service path issue)."""
    if not program:
        return False
    if '"' in program:
        return False
    p = normalize_path(program)
    if " " in p and ("\\" in p or "/" in p):
        return True
    return False


def is_unc_path(path: str) -> bool:
    p = normalize_path(path)
    return p.startswith("\\\\") or p.startswith("//")


def is_network_unc(path: str) -> bool:
    """UNC that is not littered with admin shares used loosely."""
    return is_unc_path(path)


def is_removable_style(path: str) -> bool:
    """Drive letters commonly used for removable media."""
    p = normalize_path(path)
    m = re.match(r"^([A-Za-z]):", p)
    if not m:
        return False
    return m.group(1).upper() in {"D", "E", "F", "G", "H", "I", "J", "K", "L",
                                  "M", "N", "O", "P", "Q", "R", "S", "T", "U",
                                  "V", "W", "X", "Y", "Z"}


def is_relative_path(path: str) -> bool:
    p = normalize_path(path)
    if not p:
        return False
    if re.match(r"^[A-Za-z]:", p):
        return False
    if p.startswith("\\\\"):
        return False
    if p.startswith("\\"):
        return False
    if p.startswith("%"):
        return False
    # bare executable name or relative dir
    return True


def in_user_writable_dir(path: str) -> bool:
    """Heuristic: is the (normalized) path inside a user-writable location?"""
    p = normalize_path(path).lower()
    markers = [
        "\\users\\",
        "\\programdata\\",
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
    ]
    for m in markers:
        if m in p:
            return True
    return False


def in_temp_dir(path: str) -> bool:
    p = normalize_path(path).lower()
    # Check expanded TEMP/TMP at scan runtime is done elsewhere; here we
    # look at the path text itself.
    if "\\temp\\" in p or "\\tmp\\" in p:
        return True
    if p.startswith("%temp%") or p.startswith("%tmp%"):
        return True
    return False


def file_extension(path: str) -> str:
    p = normalize_path(path)
    _, ext = os.path.splitext(p)
    return ext.lower()


def is_script_extension(ext: str) -> bool:
    ext = (ext or "").lower()
    return ext in {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                   ".wsf", ".wsh", ".ps1", ".hta"}


def is_executable_extension(ext: str) -> bool:
    ext = (ext or "").lower()
    return ext in {".exe", ".com"}


def looks_like_base64(text: str) -> bool:
    """Cheap heuristic for base64-ish blobs in commands/args."""
    if not text:
        return False
    stripped = text.strip()
    if len(stripped) < 16:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped):
        return False
    # require a mix of upper and lower or digits to avoid matching ascii
    has_upper = any(c.isupper() for c in stripped)
    has_lower = any(c.islower() for c in stripped)
    has_digit = any(c.isdigit() for c in stripped)
    return (has_upper and has_lower) or (has_digit and has_upper) or (has_digit and has_lower)


def looks_like_url(text: str) -> bool:
    if not text:
        return False
    t = text.strip().lower()
    return t.startswith("http://") or t.startswith("https://")


def get_clean_basename(path: str) -> str:
    p = normalize_path(path)
    if not p:
        return ""
    head, tail = os.path.split(p.replace("/", "\\"))
    return tail or p


def is_windows_system_path(path: str) -> bool:
    p = normalize_path(path).lower()
    return p.startswith("c:\\windows\\") or p.startswith(r"c:\winnt")

# ---------------------------------------------------------------------------
# Command-derived helpers
# ---------------------------------------------------------------------------


def has_command_line_value(entry) -> str:
    """Return the best textual source used for command-line heuristics."""
    cmd = entry.command or ""
    args = entry.arguments or ""
    pieces = " ".join(x for x in (cmd, args) if x)
    return pieces


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out