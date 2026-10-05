"""Shared dataclasses used across the app (kept in one place)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.models.enums import CollectionStatus

DEFAULT_UNKNOWN = "Unknown"
DEFAULT_UNAVAILABLE = "Unavailable"
DEFAULT_NOT_REPORTED = "Not Reported"


@dataclass
class RunItem:
    """Single normalised Run-key style persistence point.

    Kept small and source-agnostic; collectors fill what they can and
    leave the rest as the default "not reported" strings.
    """

    command: str = ""
    working_directory: str = ""
    user: str = DEFAULT_UNKNOWN
    hive: str = ""
    key_path: str = ""
    value_name: str = ""
    architecture: str = ""
    category: str = DEFAULT_UNKNOWN  # e.g. Run / RunOnce / StartupFolder / ...

    @property
    def path(self) -> str:
        return self.command

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "working_directory": self.working_directory,
            "user": self.user,
            "hive": self.hive,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "architecture": self.architecture,
            "category": self.category,
        }


@dataclass
class TaskAction:
    """One action of a scheduled task."""

    action_type: str = DEFAULT_UNKNOWN
    task_path: str = ""
    work_dir: str = ""
    arguments: str = ""

    @property
    def command(self) -> str:
        """Full-ish command line the action runs (task_path + arguments)."""
        return f"\"{self.task_path}\" {self.arguments}".strip()

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "task_path": self.task_path,
            "work_dir": self.work_dir,
            "arguments": self.arguments,
            "command": self.command,
        }


@dataclass
class TaskTrigger:
    """One trigger of a scheduled task."""

    trigger_type: str = DEFAULT_UNKNOWN
    detail: str = DEFAULT_UNKNOWN

    def to_dict(self) -> dict:
        return {"trigger_type": self.trigger_type, "detail": self.detail}


@dataclass
class ScheduledTask:
    """Normalised scheduled task metadata."""

    task_path: str = ""            # full \Folder\...\TaskName
    name: str = ""
    folder: str = ""               # path of the folder part
    author: str = DEFAULT_UNKNOWN
    description: str = ""
    run_level: str = DEFAULT_UNKNOWN      # LeastPrivilege / Highest
    principal: str = DEFAULT_UNKNOWN       # account running the task
    logon_type: str = DEFAULT_UNKNOWN
    state: str = DEFAULT_UNKNOWN           # Ready / Running / Disabled / ...
    enabled: bool | None = None
    repeat_interval: str = ""
    duration: str = ""
    registration: str = DEFAULT_UNKNOWN
    task_type: str = DEFAULT_UNKNOWN
    version: str = ""
    last_run_time: str = ""
    last_run_result: str = ""
    next_run_time: str = ""
    hidden: bool = False
    actions: list[TaskAction] = field(default_factory=list)
    triggers: list[TaskTrigger] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    def primary(self) -> TaskAction | None:
        return self.actions[0] if self.actions else None

    def to_dict(self) -> dict:
        return {
            "task_path": self.task_path,
            "name": self.name,
            "folder": self.folder,
            "author": self.author,
            "description": self.description,
            "run_level": self.run_level,
            "principal": self.principal,
            "logon_type": self.logon_type,
            "state": self.state,
            "enabled": self.enabled,
            "repeat_interval": self.repeat_interval,
            "duration": self.duration,
            "registration": self.registration,
            "task_type": self.task_type,
            "version": self.version,
            "last_run_time": self.last_run_time,
            "last_run_result": self.last_run_result,
            "next_run_time": self.next_run_time,
            "hidden": self.hidden,
            "actions": [a.to_dict() for a in self.actions],
            "triggers": [t.to_dict() for t in self.triggers],
        }


@dataclass
class ServiceInfo:
    """Normalised Windows service metadata."""

    name: str = ""
    display_name: str = DEFAULT_UNKNOWN
    description: str = ""
    state: str = DEFAULT_UNKNOWN
    start_type: str = DEFAULT_UNKNOWN
    account: str = DEFAULT_UNKNOWN
    binary_path: str = ""
    arguments: str = ""
    pid: int | None = None
    svc_dll: str = ""
    image: str = ""                      # extracted executable
    run_as_system: bool = False
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "state": self.state,
            "start_type": self.start_type,
            "account": self.account,
            "binary_path": self.binary_path,
            "arguments": self.arguments,
            "pid": self.pid,
            "svc_dll": self.svc_dll,
            "image": self.image,
        }


@dataclass
class WmiSubscription:
    """A candidate WMI permanent event subscription."""

    name: str = DEFAULT_UNKNOWN
    filter_name: str = DEFAULT_UNKNOWN
    consumer_name: str = DEFAULT_UNKNOWN
    namespace: str = "root\\subscription"
    query: str = ""
    consumer_type: str = DEFAULT_UNKNOWN     # CommandLine / ActiveScript / LogFile / ...
    executable: str = ""
    script: str = ""
    arguments: str = ""
    command_line: str = ""
    user: str = DEFAULT_UNKNOWN
    sid: str = ""
    enabled: str = DEFAULT_UNKNOWN
    binding_ns: str = ""
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "filter_name": self.filter_name,
            "consumer_name": self.consumer_name,
            "namespace": self.namespace,
            "query": self.query,
            "consumer_type": self.consumer_type,
            "executable": self.executable,
            "script": self.script,
            "arguments": self.arguments,
            "command_line": self.command_line,
            "user": self.user,
            "sid": self.sid,
            "enabled": self.enabled,
        }


@dataclass
class StartupFile:
    """One file found in a startup folder."""

    path: str = ""
    name: str = ""
    extension: str = ""
    target: str = ""            # for .lnk -> target path
    arguments: str = ""         # for .lnk from target property
    user: str = DEFAULT_UNKNOWN
    category: str = "Startup Folder"

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "extension": self.extension,
            "target": self.target,
            "arguments": self.arguments,
            "user": self.user,
            "category": self.category,
        }


@dataclass
class SourceStatus:
    """Status of one collection source during a scan."""

    source: str = ""
    status: CollectionStatus = CollectionStatus.COMPLETE
    detail: str = ""

    def to_dict(self) -> dict:
        return {"source": self.source, "status": str(self.status), "detail": self.detail}