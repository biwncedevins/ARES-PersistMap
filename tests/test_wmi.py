"""WMI collector: reference parsing + subscription joining (mocked PS output)."""

from __future__ import annotations

from app.collectors import wmi as wmi_mod
from app.models.enums import CollectionStatus


def test_parse_ref():
    cls, name = wmi_mod._parse_ref(
        r'\\MACHINE\root\subscription:CommandLineEventConsumer.Name="EvilConsumer"')
    assert cls == "CommandLineEventConsumer"
    assert name == "EvilConsumer"


def test_subscription_from_commandline_consumer():
    consumer = {
        "Name": "EvilConsumer",
        "__CLASS": "CommandLineEventConsumer",
        "ExecutablePath": r"C:\evil.exe",
        "CommandLineTemplate": r'"C:\evil.exe" -payload x',
        "UserName": "SYSTEM",
    }
    filt = {"Name": "Filter1", "Query": "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_Process'",
            "EventNamespace": "root\\cimv2"}
    sub = wmi_mod._subscription_from(consumer, filt)
    assert sub.consumer_name == "EvilConsumer"
    assert sub.filter_name == "Filter1"
    assert "SELECT *" in sub.query
    assert sub.command_line == r'"C:\evil.exe" -payload x'
    assert sub.executable == r"C:\evil.exe"
    assert "SELECT *" in sub.raw_data["filter"]["Query"]


def test_subscription_from_activescript():
    consumer = {"Name": "Scr", "__CLASS": "ActiveScriptEventConsumer",
                "ScriptText": "WScript.Echo 'hi'", "UserName": "SYSTEM"}
    sub = wmi_mod._subscription_from(consumer, None)
    assert sub.consumer_type == "ActiveScriptEventConsumer"
    assert sub.script == "WScript.Echo 'hi'"


def test_collect_deterministic(monkeypatch):
    raw = [
        ("filter", {"Name": "F1", "Query": "SELECT * FROM x", "EventNamespace": "root\\cimv2"}),
        ("consumer", {"Name": "C1", "__CLASS": "CommandLineEventConsumer",
                      "CommandLineTemplate": "cmd.exe /c evil",
                      "ExecutablePath": "cmd.exe"}),
        ("binding", {"Filter": r'\\M\root\subscription:__EventFilter.Name="F1"',
                     "Consumer": r'\\M\root\subscription:CommandLineEventConsumer.Name="C1"'}),
    ]
    monkeypatch.setattr(wmi_mod, "_powershell_json", lambda: raw)
    entries, status, meta = wmi_mod.collect()
    assert status is CollectionStatus.COMPLETE
    assert len(entries) == 1
    e = entries[0]
    assert e.source == "WMI"
    assert e.name and "C1" in e.name
    assert e.raw_data["filter_raw"] is not None


def test_collect_orphan_objects_kept(monkeypatch):
    raw = [
        ("filter", {"Name": "F1", "Query": "SELECT * FROM x", "EventNamespace": "root\\cimv2"}),
        ("consumer", {"Name": "C1", "__CLASS": "ActiveScriptEventConsumer",
                      "ScriptText": "x=1"}),
    ]
    monkeypatch.setattr(wmi_mod, "_powershell_json", lambda: raw)
    entries, status, meta = wmi_mod.collect()
    assert len(entries) == 2  # orphan filter + orphan consumer


def test_collect_unavailable_when_no_powershell(monkeypatch):
    monkeypatch.setattr(wmi_mod, "_powershell_json", lambda: None)
    entries, status, meta = wmi_mod.collect()
    assert status is CollectionStatus.UNAVAILABLE
    assert entries == []


def test_collect_partial_on_error(monkeypatch):
    raw = [
        ("ERROR", {"class": "filter", "message": "Access denied to some objects"}),
        ("filter", {"Name": "F1", "Query": "q", "EventNamespace": "ns"}),
        ("consumer", {"Name": "C1", "__CLASS": "LogFileEventConsumer", "FileName": "C:\\x"}),
        ("binding", {"Filter": r'\\M\root\subscription:__EventFilter.Name="F1"',
                     "Consumer": r'\\M\root\subscription:LogFileEventConsumer.Name="C1"'}),
    ]
    monkeypatch.setattr(wmi_mod, "_powershell_json", lambda: raw)
    entries, status, meta = wmi_mod.collect()
    assert status is CollectionStatus.PARTIAL
    assert len(entries) == 1


def test_never_invent_missing_properties():
    consumer = {"Name": "Minimal", "__CLASS": "CommandLineEventConsumer"}
    sub = wmi_mod._subscription_from(consumer, None)
    assert sub.executable == "" or sub.executable in ("", "CommandLineEventConsumer")
    d = sub.to_dict()
    # placeholders only in text fields, not fake numbers
    assert "script" in d
    assert isinstance(d["query"], str)