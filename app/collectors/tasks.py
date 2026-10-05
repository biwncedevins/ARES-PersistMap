"""Scheduled Tasks collector.

Primary: Task Scheduler COM API (win32com). Fallback: ``schtasks /query``
CSV. Both paths are read-only - we enumerate and read metadata, never run a
task action.

Handles: subfolders, hidden tasks, SYSTEM / highest-run tasks, missing
actions, and malformed definitions. Each task keeps its XML snippet as raw
evidence.
"""

from __future__ import annotations

import csv
import io
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Callable, Optional

from app.models.enums import CollectionStatus, Source
from app.models.entry import PersistenceEntry, make_entry
from app.models.models import ScheduledTask, TaskAction, TaskTrigger
from app.utils import timestamps

TRIGGER_TYPES = {
    0: "Event", 1: "Time", 2: "Daily", 3: "Weekly", 4: "Monthly",
    5: "Monthly Day-Of-Week", 6: "Idle", 7: "Registration", 8: "Boot",
    9: "Logon", 10: "Session State Change", 11: "Custom",
}

TASK_STATES = {
    0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running",
}


# ---------------------------------------------------------------------------
# XML helpers (task definition register info / actions / triggers)
# ---------------------------------------------------------------------------

def _xmlsum(element, tag: str) -> str:
    if element is None:
        return ""
    node = element.find(tag)
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def _trigger_summary(trig: ET.Element) -> str:
    parts = []
    for key, fmt in (
        ("StartBoundary", "start {}"),
        ("EndBoundary", "end {}"),
        ("Interval", "every {}"),
        ("Duration", "duration {}"),
        ("Enabled", "enabled={}"),
        ("Delay", "delay {}"),
        ("RandomDelay", "+rand {}"),
        ("Period", "every {}"),
        ("DaysInterval", "days every {}"),
        ("WeeksInterval", "weeks every {}"),
        ("Month", "month={}"),
        ("DayOfMonth", "day {}"),
        ("DayOfWeek", "days={}"),
        ("Week", "week {}"),
    ):
        node = trig.find(key)
        if node is not None and node.text:
            parts.append(fmt.format(node.text))
    # Children carrying a "how often" meaning
    for child in trig:
        if child.tag in ("EventTrigger", "BootTrigger", "LogonTrigger", "IdleTrigger",
                         "RegistrationTrigger", "SessionStateChangeTrigger"):
            parts.append(child.tag.replace("Trigger", "").lower() or child.tag)
    for child in trig.iter():
        if child.tag in ("Subscription", "Query") and child.text:
            parts.append("query=" + child.text[:200])
    return " ".join(parts) or ""


def _state_from_xml(root: ET.Element) -> Optional[bool]:
    elem = root.find("Settings")
    if elem is None:
        return None
    enabled = elem.find("Enabled")
    if enabled is None or enabled.text is None:
        return None
    return enabled.text.strip().lower() == "true"


def _trigger_type_name(typ) -> str:
    try:
        value = int(typ)
        return TRIGGER_TYPES.get(value, f"Trigger type {value}")
    except (TypeError, ValueError):
        return "Unknown"


# ---------------------------------------------------------------------------
# COM path
# ---------------------------------------------------------------------------

def _com_available() -> bool:
    try:
        import win32com.client  # noqa: F401
        return True
    except (ImportError, AttributeError):
        return False


def _enumerate_com() -> list[ScheduledTask]:
    import win32com.client

    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    root = scheduler.GetFolder("\\")
    tasks: list[ScheduledTask] = []
    _walk_com_folder(root, tasks)
    return tasks


def _walk_com_folder(folder, tasks: list[ScheduledTask]) -> None:
    for sub in folder.GetSubFolders(0):
        try:
            _walk_com_folder(sub, tasks)
        except Exception:
            continue
    for task in folder.GetTasks(1):  # TASK_ENUM_HIDDEN = 1
        try:
            tasks.append(_com_task_to_model(task))
        except Exception:
            continue


def _com_task_to_model(com_task) -> ScheduledTask:
    name = getattr(com_task, "Name", "") or ""
    full_path = getattr(com_task, "Path", "") or name
    state_raw = int(getattr(com_task, "State", 0) or 0)
    state = TASK_STATES.get(state_raw, f"Unknown ({state_raw})")

    model = ScheduledTask(
        task_path=full_path,
        name=name,
        state=state,
        last_run_time=_com_date(getattr(com_task, "LastRunTime", None)),
        next_run_time=_com_date(getattr(com_task, "NextRunTime", None)),
    )

    try:
        definition = com_task.Definition
        xml_text = None
        try:
            xml_text = definition.XmlText
        except Exception:
            pass
        if xml_text:
            model.raw_data["xml"] = xml_text
            _apply_xml(model, xml_text)

        try:
            reg = definition.RegistrationInfo
            model.author = reg.Author or "Unknown"
            model.description = reg.Description or ""
            model.registration = timestamps.from_datetime(reg.Date) if not isinstance(reg.Date, str) else reg.Date or "Unknown"
        except Exception:
            pass

        try:
            principal = definition.Principal
            model.principal = principal.UserId or "Unknown"
            model.logon_type = _logon_type(principal.LogonType)
            model.run_level = "Highest" if int(principal.RunLevel or 0) == 1 else "Least Privilege"
            model.run_level = principal.RunLevel or model.run_level
        except Exception:
            pass

        try:
            settings = definition.Settings
            try:
                model.enabled = bool(settings.Enabled)
            except Exception:
                model.enabled = None
            try:
                model.hidden = bool(settings.Hidden)
            except Exception:
                model.hidden = False
        except Exception:
            pass
    except Exception:
        pass

    return model


def _logon_type(value) -> str:
    table = {
        0: "None", 1: "Password", 2: "S4U", 3: "Interactive",
        4: "Group", 5: "ServiceAccount", 6: "InteractiveOrPassword",
    }
    try:
        return table.get(int(value or 0), f"LogonType {value}")
    except (TypeError, ValueError):
        return "Unknown"


def _com_date(value) -> str:
    if value in (None, ""):
        return "Unknown"
    # win32com gives datetime, float (OLE date), or raw string depending on build
    from datetime import datetime
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (int, float)):
        return timestamps.from_com_date(value) or "Unknown"
    if isinstance(value, str):
        return timestamps.from_iso(value) or "Unknown"
    return "Unknown"


# ---------------------------------------------------------------------------
# XML path (helper)
# ---------------------------------------------------------------------------

def _apply_xml(model: ScheduledTask, xml_text: str) -> None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return
    # namespace-agnostic traversal
    def _find(elem, tag):
        for e in elem.iter():
            if e.tag.split("}")[-1] == tag:
                return e
        return None

    reg = _find(root, "RegistrationInfo")
    if reg is not None:
        model.author = _xml_local(reg, "Author") or model.author
        model.description = _xml_local(reg, "Description") or model.description
        model.registration = _xml_local(reg, "Date") or model.registration

    principal = _find(root, "Principal")
    if principal is not None:
        model.principal = _xml_local(principal, "UserId") or model.principal
        model.logon_type = _xml_local(principal, "LogonType") or model.logon_type
        model.run_level = _xml_local(principal, "RunLevel") or model.run_level

    settings = _find(root, "Settings")
    if settings is not None:
        hidden = _find(settings, "Hidden")
        model.hidden = hidden is not None and hidden.text in ("true", "True")
        enabled = _find(settings, "Enabled")
        if enabled is not None:
            model.enabled = enabled.text in ("true", "True")

    actions_elem = _find(root, "Actions")
    if actions_elem is not None:
        for act in actions_elem:
            if not isinstance(act.tag, str):
                continue
            tag = act.tag.split("}")[-1]
            if tag not in ("Exec", "ComHandler", "SendEmail", "ShowMessage"):
                continue
            a = TaskAction(
                action_type=tag,
                task_path=_xml_local(act, "Command") or "",
                arguments=_xml_local(act, "Arguments") or "",
                work_dir=_xml_local(act, "WorkingDirectory") or "",
            )
            if not a.task_path and tag == "ComHandler":
                a.task_path = "ComHandler: " + _xml_local(act, "ClassId")
            model.actions.append(a)

    triggers_elem = _find(root, "Triggers")
    if triggers_elem is not None:
        for t_elem in triggers_elem:
            if not isinstance(t_elem.tag, str):
                continue
            tag = t_elem.tag.split("}")[-1]
            if not tag.endswith("Trigger"):
                continue
            model.triggers.append(TaskTrigger(
                trigger_type=tag,
                detail=_trigger_summary(t_elem) or "Unknown",
            ))


def _xml_local(elem, tag: str) -> str:
    for e in elem.iter():
        if e.tag.split("}")[-1] == tag:
            if e.text and e.text.strip():
                return e.text.strip()
    return ""


# ---------------------------------------------------------------------------
# schtasks fallback
# ---------------------------------------------------------------------------

def _enumerate_schtasks() -> list[ScheduledTask]:
    cmd = ["schtasks", "/query", "/fo", "CSV", "/v"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    return _parse_schtasks_csv(proc.stdout)


def _parse_schtasks_csv(raw: str) -> list[ScheduledTask]:
    tasks: list[ScheduledTask] = []
    reader = csv.DictReader(io.StringIO(raw))
    for row in reader:
        name = row.get("TaskName", "").strip() or "Unknown"
        full_path = name.replace("\\", "\\", 1) if not name.startswith("\\") else name
        task = ScheduledTask(
            task_path=full_path,
            name=name.rsplit("\\", 1)[-1] or name,
            folder=name.rsplit("\\", 1)[0] if "\\" in name else "\\",
            author=row.get("Author", "") or "Unknown",
            description=row.get("Task To Run", "") or row.get("Comment", ""),
            state=row.get("Scheduled Task State", "Unknown") or "Unknown",
            principal=row.get("Run As User", "") or row.get("Logon Mode", "Unknown"),
            last_run_time=row.get("Last Run Time", "") or "Unknown",
            next_run_time=row.get("Next Run Time", "") or "Unknown",
        )
        action_path = row.get("Task To Run") or row.get("Task to Run") or ""
        start_in = row.get("Start In", "") or ""
        arguments = row.get("Arguments", "") or ""
        if action_path:
            task.actions.append(TaskAction(action_type="Execute",
                                           task_path=action_path.replace('"', '').strip(),
                                           work_dir=start_in, arguments=arguments))
        raw = dict(row)
        task.raw_data["csv_row"] = {k: v for k, v in raw.items() if k and v is not None}
        tasks.append(task)
    return tasks


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def collect(progress: Optional[Callable[[str], None]] = None,
            errors: Optional[Callable[[str, str], None]] = None) -> tuple[list[PersistenceEntry], CollectionStatus, dict]:
    tasks: list[ScheduledTask] = []
    problems: list[str] = []
    method = "COM"
    used = "com"

    if _com_available():
        try:
            tasks = _enumerate_com()
        except Exception as exc:
            problems.append(f"COM Task Scheduler: {exc}. Using schtasks fallback.")
            used = "schtasks"
            tasks = _enumerate_schtasks()
        if not tasks:
            used = "schtasks"
            fallback = _enumerate_schtasks()
            if fallback:
                tasks = fallback
                method = "SCHTASKS"
    else:
        used = "schtasks"
        method = "SCHTASKS"
        tasks = _enumerate_schtasks()

    entries = [_task_to_entry(t, method) for t in tasks]

    # A full system usually has zero-to-few tasks; empty is a valid result.
    status = CollectionStatus.COMPLETE
    if problems:
        status = CollectionStatus.PARTIAL
        for p in problems:
            if errors:
                errors("Scheduled Task", p)

    meta = {"tasks_collected": len(tasks), "method": method, "used_fallback": used == "schtasks"}
    return entries, status, meta


def _task_to_entry(task: ScheduledTask, method: str) -> PersistenceEntry:
    primary = task.primary()
    act_path = primary.task_path if primary else ""
    args = primary.arguments if primary else ""
    workdir = primary.work_dir if primary else ""

    evidence = [
        f"Method: {method}",
        f"Task: {task.task_path}",
        f"State: {task.state}",
    ]
    if task.raw_data.get("xml"):
        evidence.append("XML captured in raw_data")

    if act_path:
        command_text = act_path
        if args:
            command_text += " " + args
    else:
        # No parseable action: keep the author/description-derived command
        # empty rather than science-fictioning one.
        command_text = ""
        act_path = task.description if "http" in (task.description or "").lower() else ""

    triggers = "; ".join(f"{t.trigger_type} ({t.detail})" for t in task.triggers[:10]) or "Unknown"

    entry = make_entry(
        source=Source.SCHEDULED_TASK,
        category="Scheduled Task",
        name=task.name or task.task_path,
        path=act_path,
        command=command_text,
        arguments=args,
        working_directory=workdir,
        user=task.principal,
        status=_task_status(task),
        created_time=task.registration,
        last_run_time=task.last_run_time,
        next_run_time=task.next_run_time,
        architecture=task.run_level,
        raw_data=task.to_dict(),
        evidence_raw=evidence,
    )
    entry.raw_data["triggers_summary"] = triggers
    if task.raw_data.get("csv_row"):
        entry.raw_data["csv_row"] = task.raw_data["csv_row"]
    if task.raw_data.get("xml"):
        entry.raw_data["task_xml"] = task.raw_data["xml"]
    return entry


def _task_status(task: ScheduledTask) -> str:
    if task.enabled is False:
        return "Disabled"
    if task.state:
        lowered = str(task.state).lower()
        if "disabled" in lowered:
            return "Disabled"
        if "running" in lowered:
            return "Running"
        if "ready" in lowered:
            return "Ready"
        if "queued" in lowered:
            return "Queued"
    return "Unknown"