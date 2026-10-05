"""Startup collector: LNK parsing (deterministic binary fixtures)."""

from __future__ import annotations

import struct

import pytest

from app.collectors.startup import LinkResolver
from app.models.models import StartupFile

from app.collectors.startup import _file_to_entry


def build_lnk(local_path: str, workdir: str = "", arguments: str = "",
              unicode_blocks: bool = False) -> bytes:
    """Build a minimal valid MS-SHLLINK with a LinkInfo + stringdata blocks.

    StringData blocks (WorkingDir then Arguments) follow the LinkInfo block.
    LocalBasePath is placed inside LinkInfo directly after its 28-byte header.
    """
    flags = 0x00000002  # HasLinkInfo

    # --- LinkInfo block ------------------------------------------
    if unicode_blocks:
        local_bytes = local_path.encode("utf-16-le") + b"\x00\x00"
    else:
        local_bytes = local_path.encode("latin-1") + b"\x00"

    link_info_header = 28
    local_base_offset = link_info_header  # 28
    # Layout: 28-byte header + local base path (+null) + CommonPathSuffix
    suffix_bytes = b"\x00"
    suffix_offset = link_info_header + len(local_bytes)
    total = suffix_offset + len(suffix_bytes)
    link_info = struct.pack("<IIIIIII",
                            total,
                            link_info_header,
                            0x00000001,   # VolumeIDAndLocalBasePath
                            0,
                            local_base_offset,
                            0,            # common network rel off
                            suffix_offset)
    link_info += local_bytes
    link_info += suffix_bytes

    # --- StringData blocks ---------------------------------------
    def string_block(text: str) -> bytes:
        if unicode_blocks:
            encoded = text.encode("utf-16-le")
            return struct.pack("<H", len(text)) + encoded + b"\x00\x00"
        encoded = text.encode("latin-1")
        return bytes([len(encoded)]) + encoded + b"\x00"

    if workdir:
        flags |= 0x00000040  # HasWorkingDir
    if arguments:
        flags |= 0x00000020  # HasArguments
    if unicode_blocks:
        flags |= 0x00000200  # IsUnicode

    strings = b""
    if workdir:
        strings += string_block(workdir)
    if arguments:
        strings += string_block(arguments)

    # --- fixed 76-byte header ------------------------------------
    header_size = 0x4C
    clsid = bytes.fromhex("0114020000000000C000000000000046")
    header = struct.pack("<I", header_size) + clsid
    header += struct.pack("<I", flags)
    header += struct.pack("<I", 0x20)          # attributes
    header += struct.pack("<QQQ", 0, 0, 0)     # times
    header += struct.pack("<I", 0)             # filesize
    header += struct.pack("<i", 0)             # icon index
    header += struct.pack("<II", 1, 0)         # showcommand, hotkey+reserved
    header += struct.pack("<II", 0, 0)         # reserved2, reserved3
    assert len(header) == 76

    return header + link_info + strings


def test_link_resolver_plain(tmp_path):
    lnk = tmp_path / "a.lnk"
    lnk.write_bytes(build_lnk(r"C:\Program Files\App\app.exe",
                              workdir=r"C:\Program Files\App",
                              arguments="--update"))
    resolver = LinkResolver(str(lnk))
    assert resolver.target == r"C:\Program Files\App\app.exe"
    assert resolver.arguments == "--update"
    assert resolver.workdir == r"C:\Program Files\App"


def test_link_resolver_unicode(tmp_path):
    lnk = tmp_path / "u.lnk"
    lnk.write_bytes(build_lnk(r"C:\Users\jöhn\App\j.exe",
                              arguments="-u x", unicode_blocks=True))
    resolver = LinkResolver(str(lnk))
    assert resolver.target == r"C:\Users\jöhn\App\j.exe"
    assert resolver.arguments == "-u x"


def test_link_resolver_corrupt(tmp_path):
    lnk = tmp_path / "bad.lnk"
    lnk.write_bytes(b"\x00\x01\x02\x03" * 10)  # not a real link
    resolver = LinkResolver(str(lnk))
    assert resolver.target is None
    assert resolver.arguments is None


def test_link_resolver_missing_file(tmp_path):
    resolver = LinkResolver(str(tmp_path / "gone.lnk"))
    assert resolver.target is None


def test_file_to_entry_target_used():
    f = StartupFile(path=r"C:\startup\link.lnk", name="link.lnk",
                    extension=".lnk", target=r"C:\x\real.exe",
                    arguments="-fast")
    entry = _file_to_entry(f)
    assert entry.name == "link.lnk"
    assert entry.command == r"C:\x\real.exe"
    assert entry.arguments == "-fast"
    assert entry.source == "Startup"
    assert entry.user == f.user
    assert "link.lnk" in entry.evidence_raw[1]


def test_extension_detected_in_file_to_entry():
    f = StartupFile(path=r"C:\startup\run.ps1", name="run.ps1",
                    extension=".ps1")
    entry = _file_to_entry(f)
    assert entry.file_extension == ".ps1"