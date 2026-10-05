"""Startup folders collector.

Reads the per-user and machine-wide Startup folders. Files are inspected
read-only (metadata + LNK binary parsing). No file is ever executed,
renamed or touched - only opened for reading when it is a .lnk.
"""

from __future__ import annotations

import getpass
import os
import struct
import sys
from typing import Callable, Optional

from config import STARTUP_EXTENSIONS
from app.models.enums import CollectionStatus, Source
from app.models.entry import PersistenceEntry, make_entry
from app.models.models import StartupFile

# Known Folder GUID: {B97D20BB-F46A-4C97-BA10-5E3608430854} == CSIDL_STARTUP
_KF_STARTUP = "B97D20BB-F46A-4C97-BA10-5E3608430854"
# Common Startup: {82A5EA35-D9CD-47C5-9629-E15D2F714E6E}
_KF_COMMON_STARTUP = "82A5EA35-D9CD-47C5-9629-E15D2F714E6E"


def _known_folder(guid: str, default: str) -> str:
    """Resolve a Known Folder without win32com (ctypes SHGetKnownFolderPath)."""
    try:
        import ctypes
        from ctypes import wintypes

        SHGetKnownFolderPath = ctypes.windll.shell32.SHGetKnownFolderPath
        SHGetKnownFolderPath.argtypes = [ctypes.c_wchar_p, wintypes.DWORD,
                                         wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
        SHGetKnownFolderPath.restype = wintypes.HRESULT

        buffer = ctypes.c_wchar_p()
        hr = SHGetKnownFolderPath(guid, 0, None, ctypes.byref(buffer))
        if hr == 0 and buffer.value:
            path = buffer.value
            ctypes.windll.ole32.CoTaskMemFree(buffer)
            return path
    except Exception:
        pass
    return default


def _user_startup() -> str:
    default = os.path.join(os.environ.get("APPDATA", ""),
                           "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    return _known_folder(_KF_STARTUP, default)


def _common_startup() -> str:
    default = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                           "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    return _known_folder(_KF_COMMON_STARTUP, default)


class LinkResolver:
    """Minimal, defensive binary parser for .lnk (MS-SHLLINK) files.

    Extracts the local target path, arguments and working directory when
    present. Any malformed structure returns WhatWeCouldRead plus Unknown
    placeholders - exceptions never escape.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.target: Optional[str] = None
        self.arguments: Optional[str] = None
        self.workdir: Optional[str] = None
        self._parse()

    def _parse(self) -> None:
        try:
            with open(self.path, "rb") as fh:
                data = fh.read(64 * 1024)
        except OSError:
            return
        if len(data) < 76:
            return
        if data[:4] != b"\x4c\x00\x00\x00":  # LNK magic {00021401-...}
            return

        flags = struct.unpack_from("<I", data, 20)[0]
        has_link_info = bool(flags & 0x02)
        is_unicode = bool(flags & 0x0200)
        has_args = bool(flags & 0x20)
        has_workdir = bool(flags & 0x40)
        has_relpath = bool(flags & 0x04)

        off = 76
        if flags & 0x01:  # HasLinkTargetIDList
            if off + 2 > len(data):
                return
            idlist_size = struct.unpack_from("<H", data, off)[0]
            off += 2 + idlist_size

        if has_link_info:
            if off + 4 > len(data):
                return
            header_size = struct.unpack_from("<I", data, off)[0]
            if header_size < 28 or off + header_size > len(data):
                return
            local_base_offset = struct.unpack_from("<I", data, off + 16)[0]
            if local_base_offset:
                pos = off + local_base_offset
                target = self._read_null_str(data, pos, is_unicode)
                if target:
                    self.target = target
            off += header_size

        def _read_string_block(current: int) -> int:
            if current + 2 > len(data):
                return -1
            if is_unicode:
                length = struct.unpack_from("<H", data, current)[0]
                start = current + 2
                end = start + length * 2 + 2  # + terminating null char
                if start + length * 2 > len(data):
                    return -1
                raw = data[start:end - 2]
                return current + 2 + length * 2 + 2, raw.decode("utf-16-le", "replace")
            else:
                length = struct.unpack_from("<B", data, current)[0]
                start = current + 1
                end = start + length + 1
                if end > len(data):
                    return -1
                raw = data[start:end - 1]
                return current + 1 + length + 1, raw.decode("latin-1", "replace")

        if has_relpath:
            result = _read_string_block(off)
            if result == -1:
                return
            off, _rel = result
        if has_workdir:
            result = _read_string_block(off)
            if result == -1:
                return
            off, wd = result
            if wd and not self.workdir:
                self.workdir = wd
        if has_args:
            result = _read_string_block(off)
            if result == -1:
                return
            _off, args = result
            if args and not self.arguments:
                self.arguments = args

    @staticmethod
    def _read_null_str(data: bytes, pos: int, unicode_: bool) -> str:
        if unicode_:
            # advance in 2-byte code units until a 0x0000 terminator
            out = []
            i = pos
            while i + 2 <= len(data):
                unit = struct.unpack_from("<H", data, i)[0]
                if unit == 0:
                    break
                out.append(chr(unit))
                i += 2
            return "".join(out)
        end = data.find(b"\x00", pos)
        if end == -1:
            return ""
        return data[pos:end].decode("latin-1", "replace")


def _safe_stat(path: str) -> tuple[Optional[int], Optional[str]]:
    try:
        st = os.stat(path)
        import datetime
        mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        return st.st_size, mtime
    except OSError:
        return None, None


def _scan_folder(folder: str, user: str, category: str) -> list[StartupFile]:
    found: list[StartupFile] = []
    try:
        names = os.listdir(folder)
    except OSError:
        return found

    for name in names:
        full = os.path.join(folder, name)
        try:
            if not os.path.isfile(full):
                continue
        except OSError:
            continue
        ext = os.path.splitext(name)[1].lower()
        item = StartupFile(path=full, name=name, extension=ext, user=user, category=category)
        if ext == ".lnk":
            resolver = LinkResolver(full)
            item.target = resolver.target or ""
            item.arguments = resolver.arguments or ""
        elif ext == ".url":
            item.target = _read_url_target(full)
        found.append(item)
    return found


def _read_url_target(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.lower().startswith("url="):
                    return line[4:].strip()
    except OSError:
        return ""
    return ""


def collect(progress: Optional[Callable[[str], None]] = None,
            errors: Optional[Callable[[str, str], None]] = None) -> tuple[list[PersistenceEntry], CollectionStatus, dict]:
    """Scan both startup folders. Never raises."""
    entries: list[PersistenceEntry] = []
    problems: list[str] = []
    meta = {"folders_scanned": 0, "folders_failed": 0}

    current_user = "Current User"
    try:
        current_user = getpass.getuser()
    except Exception:
        pass

    folders = [
        (_user_startup(), current_user, "User Startup"),
        (_common_startup(), "Common (All Users)", "Common Startup"),
    ]

    for folder, user, category in folders:
        try:
            files = _scan_folder(folder, user, category)
            meta["folders_scanned"] += 1
            for f in files:
                entries.append(_file_to_entry(f))
        except Exception as exc:
            meta["folders_failed"] += 1
            problems.append(f"{folder}: {exc}")

    for p in problems:
        if errors:
            errors("Startup", p)

    status = CollectionStatus.COMPLETE if not problems else CollectionStatus.PARTIAL
    if meta["folders_failed"] == len(folders) and not entries:
        status = CollectionStatus.ACCESS_DENIED
    return entries, status, meta


def _file_to_entry(f: StartupFile) -> PersistenceEntry:
    size, mtime = _safe_stat(f.path)
    evidence = [
        f"Folder: {f.category}",
        f"File: {f.path}",
    ]
    target = f.target or ""
    command_source = target or f.path
    return make_entry(
        source=Source.STARTUP,
        category=f.category,
        name=f.name,
        path=f.path,
        command=command_source,
        arguments=f.arguments if f.arguments else "",
        user=f.user,
        file_extension=f.extension,
        file_size=size,
        modified_time=mtime or "",
        raw_data=f.to_dict(),
        evidence_raw=evidence,
    )