"""Duplicate correlation."""

from __future__ import annotations

from app.analysis import correlation
from tests.conftest import make_entry


def test_group_by_normalized_path():
    entries = [
        make_entry(id="a", command=r'"C:\Program Files\X\app.exe" -a', path=r"C:\Program Files\X\app.exe"),
        make_entry(id="b", command=r'C:\Program Files\X\app.exe -b', path=r"C:\Program Files\X\app.exe"),
        make_entry(id="c", command=r'"C:\Program Files\Y\other.exe"', path=r"C:\Program Files\Y\other.exe"),
    ]
    groups = correlation.correlate(entries)
    joined = {e.id: e.duplicate_group_id for e in entries}
    assert joined["a"] == joined["b"]
    assert joined["a"] != joined["c"]
    assert joined["c"]  # assigned a group too (single-member)
    sizes = {gid: len(m) for gid, m in groups.items()}
    assert any(s == 2 for s in sizes.values())


def test_group_case_insensitive():
    entries = [
        make_entry(id="a", command=r"c:\windows\system32\runme.exe"),
        make_entry(id="b", command=r"C:\WINDOWS\System32\RunMe.EXE"),
    ]
    correlation.correlate(entries)
    assert entries[0].duplicate_group_id == entries[1].duplicate_group_id


def test_group_by_hash():
    entries = [
        make_entry(id="a", sha256="aa", command=r"C:\one.exe"),
        make_entry(id="b", sha256="AA", command=r"C:\different.exe"),
    ]
    correlation.correlate(entries)
    assert entries[0].duplicate_group_id == entries[1].duplicate_group_id


def test_independent_entries():
    e1 = make_entry(id="a", path=r"C:\a.exe", command=r"C:\a.exe")
    e2 = make_entry(id="b", path=r"C:\b.exe", command=r"C:\b.exe")
    correlation.correlate([e1, e2])
    assert e1.duplicate_group_id != e2.duplicate_group_id


def test_duplicate_indicator_applied_to_group_only():
    entries = [
        make_entry(id="a", command=r"C:\legit.exe"),
        make_entry(id="b", command=r"C:\legit.exe"),
    ]
    correlation.correlate(entries)
    dups = [e for e in entries if any(i.label == "Duplicate Persistence Path" for i in e.indicators)]
    assert len(dups) == 2
    # indicators remain structured
    for e in entries:
        for i in e.indicators:
            assert i.tag and i.label