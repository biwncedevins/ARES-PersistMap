"""Services collector helpers: binary path parse, account/state mapping."""

from __future__ import annotations

from app.collectors import services as services_mod
from app.models.enums import Source


def test_extract_image_quoted():
    assert services_mod._extract_image(r'"C:\Program Files\X\svc.exe" -k grp') == \
        r"C:\Program Files\X\svc.exe"


def test_extract_image_unquoted():
    assert services_mod._extract_image(r"C:\Windows\System32\svchost.exe -k netsvcs") == \
        r"C:\Windows\System32\svchost.exe"


def test_extract_image_empty():
    assert services_mod._extract_image("") == ""


def test_system_accounts():
    assert services_mod._is_system_account("LocalSystem")
    assert services_mod._is_system_account("NT AUTHORITY\\SYSTEM")
    assert services_mod._is_system_account("NT AUTHORITY\\LocalService") is False
    assert services_mod._is_system_account("bob") is False


def test_map_state():
    assert services_mod._map_state("4 RUNNING") == "Running"
    assert services_mod._map_state("1 STOPPED") == "Stopped"
    assert services_mod._map_state("") == "Unknown"


def test_service_to_entry():
    info = services_mod.ServiceInfo(
        name="svc", display_name="Bad Svc", state="Running", start_type="Auto",
        account="LocalSystem", binary_path=r"C:\Users\bob\evil.exe --svc",
        image=r"C:\Users\bob\evil.exe",
    )
    entry = services_mod._service_to_entry(info)
    assert entry.source == Source.SERVICE.value
    assert entry.command == r"C:\Users\bob\evil.exe --svc"
    assert entry.path == r"C:\Users\bob\evil.exe"
    assert entry.user == "LocalSystem"
    assert entry.status == "Running"


def test_service_dll_resolution(monkeypatch):
    """svchost resolves its hosted DLL from Parameters\ServiceDll."""
    import winreg

    called = []

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake_reg = __import__("types", fromlist=["SimpleNamespace"]).SimpleNamespace(
        HKEY_LOCAL_MACHINE="HKLM",
        OpenKey=lambda *a, **k: _Key(),
        QueryValueEx=lambda key, name: (
            (r"C:\Windows\System32\wudfsvc.dll", 1) if name == "ServiceDll" else (_ for _ in ()).throw(OSError)
        ),
    )
    monkeypatch.setattr(services_mod, "winreg", fake_reg)
    dll = services_mod._resolve_service_dll("svc", r"C:\Windows\System32\svchost.exe -k foo")
    assert dll == r"C:\Windows\System32\wudfsvc.dll"


def test_non_svchost_no_dll_lookup(monkeypatch):
    monkeypatch.setattr(services_mod, "winreg", None)
    dll = services_mod._resolve_service_dll("svc", r"C:\Windows\System32\notepad.exe")
    assert dll == ""