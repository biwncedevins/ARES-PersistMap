"""Scheduled tasks: schtasks CSV parse, XML apply, model mapping."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from app.collectors.tasks import (
    _apply_xml,
    _parse_schtasks_csv,
    _task_to_entry,
    _trigger_summary,
)
from app.models.models import ScheduledTask, TaskAction, TaskTrigger

CSV_SAMPLE = (
    "TaskName,Next Run Time,Status,Logon Mode,Last Run Time,Last Result,Author,"
    "Task To Run,Start In,Comment,Scheduled Task State,\n"
    "\\UpdateTask,2026-09-21 03:00:00,Ready,Interactive token,"
    "2026-09-20 03:00:00,0,Microsoft,powershell.exe -nop -enc ABCD,C:\\tools,"
    ",Enabled,\n"
    "\\Folder\\HiddenTask,Inactive,Ready,Password,,267009,MICROSOFT\\CORP\\badmin,"
    '"C:\\Program Files\\Tool\\tool.exe" /update,C:\\Program Files\\Tool,,,Enabled,\n'
)


def test_parse_schtasks_csv():
    tasks = _parse_schtasks_csv(CSV_SAMPLE)
    assert len(tasks) == 2


def test_task_to_entry_action_fields():
    task = _parse_schtasks_csv(CSV_SAMPLE)[0]
    entry = _task_to_entry(task, "COM")
    assert entry.source == "Scheduled Task"
    assert entry.user  # bakery author used as principal fallback? no -> row
    assert entry.raw_data["csv_row"]  # raw evidence preserved


def test_disabled_task_status():
    task = ScheduledTask(name="T", state="Disabled", enabled=False)
    entry = _task_to_entry(task, "COM")
    assert entry.status == "Disabled"


def test_system_task_welcomed():
    task = ScheduledTask(name="Sys", principal="SYSTEM", run_level="Highest")
    entry = _task_to_entry(task, "COM")
    assert entry.user == "SYSTEM"
    assert entry.architecture == "Highest"


def test_apply_xml():
    xml = """
    <Task version="1.4">
      <RegistrationInfo><Author>ACME</Author><Description>updater</Description>
        <Date>2026-01-01T00:00:00</Date></RegistrationInfo>
      <Triggers>
        <BootTrigger><Enabled>true</Enabled></BootTrigger>
        <TimeTrigger><StartBoundary>2026-02-01T00:00:00</StartBoundary>
          <Enabled>true</Enabled></TimeTrigger>
      </Triggers>
      <Principal><UserId>S-1-5-18</UserId><LogonType>Password</LogonType>
        <RunLevel>HighestAvailable</RunLevel></Principal>
      <Actions>
        <Exec><Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
          <Arguments>-enc AA</Arguments><WorkingDirectory>C:\\x</WorkingDirectory></Exec>
      </Actions>
      <Settings><Hidden>true</Hidden></Settings>
    </Task>"""
    task = ScheduledTask(name="X")
    _apply_xml(task, xml)
    assert task.author == "ACME"
    assert task.principal == "S-1-5-18"
    assert task.hidden is True
    assert len(task.actions) == 1
    assert task.actions[0].task_path.endswith("powershell.exe")
    assert task.actions[0].arguments == "-enc AA"
    assert len(task.triggers) == 2

    entry = _task_to_entry(task, "XML")
    assert entry.command.endswith("-enc AA")
    assert entry.working_directory == r"C:\x"


def test_missing_action_not_invented():
    task = ScheduledTask(name="Empty", description="legacy task")
    entry = _task_to_entry(task, "COM")
    assert entry.command == "" or entry.path == ""
    assert entry.evidence_raw  # evidence of the state is present


def test_trigger_summary_readable():
    root = ET.fromstring(
        "<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary>"
        "<Enabled>true</Enabled><Interval>P5M</Interval></TimeTrigger>")
    summary = _trigger_summary(root)
    assert "start" in summary
    assert "every" in summary