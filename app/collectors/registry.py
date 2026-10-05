"""Registry Run / RunOnce collector.

Read-only. Probe rules, kept simple and verifiable on real Windows:

* ``HKCU`` run keys are NOT subject to WOW64 registry redirection, so each
  key is read exactly once.
* ``HKLM`` run keys ARE redirected for 32-bit processes. To enumerate both
  storage locations exactly once we:
    1. read the primary path with an explicit 64-bit view, and
    2. read the ``Software\WOW6432Node\...`` mirror (physical 32-bit data)
       only when it exists.
  We never pass ``KEY_WOW64_32KEY`` on the primary path, which avoids
  double counting. Each entry records its architecture view.

When the whole HKLM hive is unreadable (no admin), we record partial
status, keep whatever HKCU gave us, and move on.
"""

from __future__ import annotations

import getpass
import winreg
from typing import Callable, Optional

from config import REGISTRY_RUN_KEYS, WOW64_NODE_PREFIX
from app.models.enums import CollectionStatus, Source
from app.models.entry import PersistenceEntry, make_entry
from app.models.models import RunItem
from app.utils import paths

HIVES = {
    "HKCU": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
}


def _is_wow64() -> bool:
    """True when the OS may host 32-bit apps (i.e. is 64-bit)."""
    try:
        import platform as _p
        return _p.machine().lower() in ("amd64", "x64", "arm64")
    except Exception:
        return False


def _category_for(key_path: str) -> str:
    tail = (key_path or "").replace("/", "\\").rstrip("\\").split("\\")[-1]
    return "RunOnce" if tail.lower() == "runonce" else "Run"


def _user_for_hive(hive: str) -> str:
    if hive == "HKCU":
        try:
            return getpass.getuser()
        except Exception:
            return "Current User"
    return "Local Machine"


def _read_run_key(root: int, subkey: str, view: int,
                  hive_name: str, architecture: str) -> list[RunItem]:
    """Enumerate string values under one run key (single view)."""
    items: list[RunItem] = []
    with winreg.OpenKey(root, subkey, 0, view) as key:
        idx = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, idx)
            except OSError:
                break
            if value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                data = str(value).strip()
                if data:
                    items.append(RunItem(
                        command=data,
                        hive=hive_name,
                        key_path=subkey,
                        value_name=name,
                        architecture=architecture,
                        category=_category_for(subkey),
                        user=_user_for_hive(hive_name),
                    ))
            idx += 1
    return items


def collect(progress: Optional[Callable[[str], None]] = None,
            errors: Optional[Callable[[str, str], None]] = None) -> tuple[list[PersistenceEntry], CollectionStatus, dict]:
    """Collect registry run/runonce entries. Never raises."""
    entries: list[PersistenceEntry] = []
    problems: list[str] = []
    meta = {"keys_read": 0, "keys_missing": 0}

    for hive, key_path in REGISTRY_RUN_KEYS:
        hive_attr = HIVES.get(hive, "HKEY_CURRENT_USER")
        try:
            root = getattr(winreg, hive_attr)
        except AttributeError:
            problems.append(f"{hive}: registry driver unavailable")
            continue
        view = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        architecture = "64-bit"

        # --- primary path -------------------------------------------------
        try:
            items = _read_run_key(root, key_path, view, hive, architecture)
            meta["keys_read"] += 1
            entries.extend(_item_to_entry(i) for i in items)
        except FileNotFoundError:
            meta["keys_missing"] += 1
        except PermissionError as exc:
            problems.append(f"{hive}\\{key_path}: access denied ({exc})")
        except OSError as exc:
            problems.append(f"{hive}\\{key_path}: {exc}")

        # --- HKLM 32-bit mirror (WOW6432Node) ----------------------------
        if hive == "HKLM" and _is_wow64():
            mirror = key_path
            software_prefix = "Software\\"
            if mirror.lower().startswith(software_prefix.lower()):
                mirror = WOW64_NODE_PREFIX + "\\" + mirror[len(software_prefix):]
            else:
                mirror = WOW64_NODE_PREFIX + "\\" + mirror
            try:
                items = _read_run_key(root, mirror, winreg.KEY_READ, hive, "32-bit")
                meta["keys_read"] += 1
                for item in items:
                    item.key_path = mirror
                    entries.append(_item_to_entry(item))
            except FileNotFoundError:
                meta["keys_missing"] += 1
            except (PermissionError, OSError) as exc:
                problems.append(f"{hive}\\{mirror}: {exc}")

    for p in problems:
        if errors:
            errors("Registry", p)

    status = CollectionStatus.COMPLETE if not problems else CollectionStatus.PARTIAL
    if meta["keys_missing"] and not entries and not problems:
        status = CollectionStatus.COMPLETE
    return entries, status, meta


def _item_to_entry(item: RunItem) -> PersistenceEntry:
    program, _ = paths.split_command_line(item.command)
    probe_path = program or paths.normalize_path(item.command)
    return make_entry(
        source=Source.REGISTRY,
        category=item.category,
        name=item.value_name,
        command=item.command,
        path=probe_path,
        user=item.user,
        hive=item.hive,
        key_path=item.key_path,
        value_name=item.value_name,
        architecture=item.architecture,
        raw_data=item.to_dict(),
        evidence_raw=[
            f"Source: {item.hive}\\{item.key_path}",
            f"Value: {item.value_name}",
            f"Command: {item.command}",
            f"View: {item.architecture}",
        ],
    )