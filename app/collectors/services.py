"""Windows Services collector.

Primary: ``psutil.win_service_iter`` (no pywin32 dependency). Per-service
failures are isolated: one unreadable service never aborts the sweep.

For svchost-style binaries the actually-hosted service DLL is resolved
read-only from the service's ``\\Parameters`` registry key. No service is
started, stopped or configured.
"""

from __future__ import annotations

import subprocess
import winreg
from typing import Callable, Optional

from app.models.enums import CollectionStatus, Source
from app.models.entry import PersistenceEntry, make_entry
from app.models.models import ServiceInfo

START_TYPE_LABELS = {
    "auto start": "Auto",
    "demand start": "Manual",
    "disabled": "Disabled",
    "boot start": "Boot",
    "system start": "System",
    "unknown": "Unknown",
}


def _psutil_available() -> bool:
    try:
        import psutil  # noqa: F401
        return True
    except ImportError:
        return False


def collect(progress: Optional[Callable[[str], None]] = None,
            errors: Optional[Callable[[str, str], None]] = None) -> tuple[list[PersistenceEntry], CollectionStatus, dict]:
    services: list[ServiceInfo] = []
    problems: list[str] = []
    method = "psutil"

    if _psutil_available():
        try:
            services = _enumerate_psutil(problems)
        except Exception as exc:
            problems.append(f"psutil service enumeration failed: {exc}")
            services = _enumerate_sc(problems)
            method = "sc"
    else:
        services = _enumerate_sc(problems)
        method = "sc"

    entries = [_service_to_entry(s) for s in services]

    status = CollectionStatus.COMPLETE
    if problems:
        status = CollectionStatus.PARTIAL
        for p in problems:
            if errors:
                errors("Service", p)
    if not entries and not problems:
        status = CollectionStatus.UNAVAILABLE

    meta = {"services_collected": len(services), "method": method,
            "errors": len(problems)}
    return entries, status, meta


# ---------------------------------------------------------------------------
# psutil path
# ---------------------------------------------------------------------------

def _enumerate_psutil(problems: list[str]) -> list[ServiceInfo]:
    import psutil

    services: list[ServiceInfo] = []
    iterator = psutil.win_service_iter()
    for svc in iterator:
        try:
            data = svc.as_dict()
            name = str(data.get("name", "") or svc.name())
            binpath = str(data.get("binpath", "") or "")
            start_type = str(data.get("start_type", "") or "unknown")
            account = str(data.get("username", "") or "")
            status = str(data.get("status", "") or svc.status())

            info = ServiceInfo(
                name=name,
                display_name=str(data.get("display_name", "") or ""),
                description=svc.description() or "",
                state=_map_state(status),
                start_type=START_TYPE_LABELS.get(start_type.lower().strip(), start_type),
                account=account,
                binary_path=binpath,
                image=_extract_image(binpath),
                run_as_system=_is_system_account(account),
                raw_data={"psutil": {k: str(v) for k, v in data.items() if v is not None}},
            )
            info.svc_dll = _resolve_service_dll(name, binpath)
            import psutil as _p
            try:
                proc = _p.Process(svc.pid())
                info.pid = proc.pid
            except Exception:
                info.pid = None
            services.append(info)
        except Exception as exc:
            problems.append(f"Service '{svc.name()}': {exc}")
    return services


# ---------------------------------------------------------------------------
# sc path (fallback)
# ---------------------------------------------------------------------------

def _run_sc(args: list[str]) -> str:
    try:
        proc = subprocess.run(["sc"] + args, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        return proc.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _enumerate_sc(problems: list[str]) -> list[ServiceInfo]:
    output = _run_sc(["query", "type=", "service", "state=", "all", "bufsize=", "65536"])
    services: list[ServiceInfo] = []
    current_name = None
    current_state = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current_name:
                services.append(_service_from_sc(current_name, current_state or "Unknown"))
            current_name = line.split(":", 1)[1].strip()
            current_state = None
        elif line.startswith("STATE"):
            current_state = line.split(":", 1)[1].strip().split()[0] if ":" in line else None
    if current_name:
        services.append(_service_from_sc(current_name, current_state or "Unknown"))
    return services


def _service_from_sc(name: str, state: str) -> ServiceInfo:
    info = ServiceInfo(name=name, state=_map_state(state))
    details = _run_sc(["qc", name])
    for line in details.splitlines():
        line = line.strip()
        if line.startswith("BINARY_PATH_NAME"):
            info.binary_path = line.split(":", 1)[1].strip()
            info.image = _extract_image(info.binary_path)
        elif line.startswith("START_TYPE"):
            raw = line.split(":", 1)[1].strip()
            info.start_type = "Auto" if "AUTO" in raw.upper() else (
                "Manual" if "DEMAND" in raw.upper() else (
                    "Disabled" if "DISABLED" in raw.upper() else raw))
        elif line.startswith("SERVICE_START_NAME"):
            info.account = line.split(":", 1)[1].strip()
            info.run_as_system = _is_system_account(info.account)
        elif line.startswith("DISPLAY_NAME"):
            info.display_name = line.split(":", 1)[1].strip()
        elif line.startswith("SERVICE_DLL"):
            info.svc_dll = line.split(":", 1)[1].strip()
    try:
        desc = _run_sc(["description", name]) or ""
        for line in desc.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_DESCRIPTION"):
                info.description = line.split(":", 1)[1].strip()
    except Exception:
        pass
    info.svc_dll = _resolve_service_dll(name, info.binary_path) or info.svc_dll
    return info


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _extract_image(binpath: str) -> str:
    if not binpath:
        return ""
    text = binpath.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        if end != -1:
            return text[1:end]
        return text[1:]
    return text.split()[0] if text else ""


def _is_system_account(account: str) -> bool:
    if not account:
        return False
    a = account.lower()
    return "localsystem" in a or "nt authority\\system" in a or "local system" in a or a == "system"


def _map_state(state: str) -> str:
    if not state:
        return "Unknown"
    s = state.strip().lower()
    if "running" in s or "run" in s:
        return "Running"
    if "stopped" in s or "stop" in s:
        return "Stopped"
    if "paused" in s or "pause" in s:
        return "Paused"
    return str(state).strip().title()


def _resolve_service_dll(name: str, binpath: str) -> str:
    """For svchost-style services find the DLL from Parameters\ServiceDll."""
    low = (binpath or "").lower()
    if "svchost" not in low:
        return ""
    subkeys = [
        rf"SYSTEM\CurrentControlSet\Services\{name}\Parameters",
        rf"SYSTEM\CurrentControlSet\Services\{name}\Parameters\ServiceDll",
    ]
    for subkey in subkeys:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "ServiceDll")
                if value:
                    return str(value)
        except OSError:
            continue
    # parameter path fallback: ImagePath may be svchost with undocumented
    # reference in the service's own parameters key
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            rf"SYSTEM\CurrentControlSet\Services\{name}") as key:
            val, _ = winreg.QueryValueEx(key, "ServiceDllUnquotedPathFallback")
            return str(val)
    except OSError:
        return ""


def _service_to_entry(s: ServiceInfo) -> PersistenceEntry:
    evidence = [
        f"Service: {s.name}",
        f"Path: {s.binary_path}",
        f"Start Type: {s.start_type}",
        f"Account: {s.account}",
    ]
    return make_entry(
        source=Source.SERVICE,
        category="Service",
        name=s.name,
        path=s.image or s.binary_path,
        command=s.binary_path,
        arguments=s.arguments if s.arguments else "",
        user=s.account,
        status=s.state,
        publisher="",
        working_directory="",
        file_extension=_ext(s.image or s.binary_path),
        raw_data=s.to_dict(),
        evidence_raw=evidence,
    )


def _ext(path: str) -> str:
    import os
    return os.path.splitext(path)[1].lower() if path else ""