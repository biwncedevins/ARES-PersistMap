"""Shared test fixtures - all offline/deterministic."""

from __future__ import annotations

import pytest

from app.models.entry import PersistenceEntry
from app.models.enums import Source


def make_entry(**overrides) -> PersistenceEntry:
    base = dict(
        source=Source.REGISTRY.value,
        category="Run",
        name="TestEntry",
        path=r"C:\Windows\System32\test.exe",
        command=r'"C:\Windows\System32\test.exe" -x',
        arguments="-x",
        user="TestUser",
    )
    base.update(overrides)
    return PersistenceEntry(**base)


@pytest.fixture
def fake_entry() -> PersistenceEntry:
    return make_entry()


def sample_batch() -> list[PersistenceEntry]:
    """A diverse, deterministic set used by analysis/report tests."""
    return [
        make_entry(
            id="e1",
            source=Source.REGISTRY.value,
            category="Run",
            name="Updater",
            path=r"C:\Users\victim\AppData\Roaming\Updater\update.exe",
            command=r'"C:\Users\victim\AppData\Roaming\Updater\update.exe" --silent',
            user="victim",
            signer_status="Unsigned",
        ),
        make_entry(
            id="e2",
            source=Source.SCHEDULED_TASK.value,
            category="Scheduled Task",
            name=r"EvilTask",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command=r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand AAAABBBB',
            arguments="-EncodedCommand AAAABBBB",
            user="SYSTEM",
            architecture="Highest",
            signer_status="Signed",
        ),
        make_entry(
            id="e3",
            source=Source.STARTUP.value,
            category="User Startup",
            name=r"legit.lnk",
            path=r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\legit.lnk",
            command=r"C:\Program Files\Legit\app.exe",
            user="victim",
            file_extension=".lnk",
        ),
        make_entry(
            id="e4",
            source=Source.SERVICE.value,
            category="Service",
            name="svc",
            path=r"C:\Program Files\Legit\service.exe",
            command="C:\\Program Files\\Legit\\service.exe",
            user="LocalSystem",
            status="Running",
        ),
        make_entry(
            id="e5",
            source=Source.WMI.value,
            category="WMI Subscription",
            name="CmdConsumer / Filter1",
            path=r"C:\temp\netcat.exe",
            command=r'C:\temp\netcat.exe -e cmd.exe',
            user="NT AUTHORITY\\SYSTEM",
        ),
        make_entry(
            id="e6",
            source=Source.REGISTRY.value,
            category="RunOnce",
            name="Once",
            path=r"C:\Windows\System32\reg.exe",
            command=r"%SystemRoot%\System32\reg.exe add HKLM\...",
            user="Local Machine",
            architecture="64-bit",
        ),
    ]


@pytest.fixture
def sample_entries():
    """Fixture view of sample_batch() for tests that want injection."""
    return sample_batch()