"""Normalize pipeline: candidate resolution, file states, hashing gating."""

from __future__ import annotations

import os

import pytest

from app.analysis import normalize
from app.analysis.indicators import IndicatorEngine
from app.analysis.signatures import SignatureEvaluator
from app.utils.hashing import HashCache
from tests.conftest import make_entry


class _FakeSigner:
    def __init__(self, status=None, publisher="Fake Corp"):
        from app.models.enums import SignerStatus
        self._status = status or SignerStatus.SIGNED.value
        self._publisher = publisher
        self._map = {}

    def evaluate(self, path):
        from app.models.enums import SignerStatus
        st = self._map.get(path)
        if st is None:
            st = __import__("app.analysis.signatures", fromlist=["SignatureResult"]).SignatureResult(
                self._status, publisher=self._publisher)
            self._map[path] = st
        return st


def test_existing_file_state(tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"MZ")
    e = make_entry(path=str(exe), command=f'"{exe}" -a')
    e.raw_data = {}
    normalize._resolve_candidate(e)
    assert e.file_state == "Exists"


def test_missing_file_state():
    e = make_entry(path=r"C:\definitely\missing\evil.exe")
    e.raw_data = {}
    normalize._resolve_candidate(e)
    assert e.file_state == "Missing"


def test_bare_name_unknown():
    e = make_entry(path="", command="notepad.exe")
    e.raw_data = {}
    normalize._resolve_candidate(e)
    assert e.file_state == "Unknown"
    assert e.raw_data.get("_signature_candidate", "") == ""


def test_env_var_unknown():
    e = make_entry(path="", command=r"%SystemRoot%\System32\notepad.exe")
    e.raw_data = {}
    normalize._resolve_candidate(e)
    # %SystemRoot% expands on a real machine; on a non-windows test box it
    # may not. Both are valid outcomes; the key assertion is no crash.
    assert e.file_state in ("Unknown", "Exists", "Missing")


def test_normalize_all_no_sig_for_missing():
    e = make_entry(path=r"C:\missing\thing.exe", signer_status="")
    e.raw_data = {}
    meta = normalize.normalize_all([e], signature_eval=_FakeSigner(), hash_cache=HashCache())
    assert e.signer_status in ("Unavailable", "Unknown")


def test_normalize_all_signed(tmp_path):
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    e = make_entry(path=str(exe), command=f'"{exe}"', signer_status="")
    e.raw_data = {}
    normalize.normalize_all([e], signature_eval=_FakeSigner(), hash_cache=HashCache())
    assert e.publisher == "Fake Corp"
    assert "signature" in e.raw_data


def test_hash_only_when_flagged(tmp_path):
    from app.models.enums import SignerStatus
    exe = tmp_path / "flag.exe"
    exe.write_bytes(b"MZ" * 100)
    e = make_entry(path=str(exe), command=f'"{exe}"', signer_status="Unsigned")
    e.raw_data = {}
    normalize.normalize_all([e], signature_eval=_FakeSigner(SignerStatus.UNSIGNED.value, ""),
                            hash_cache=HashCache())
    assert e.flagged
    assert e.sha256
    assert e.raw_data.get("hash_status") == "Calculated"


def test_hash_skipped_when_not_flagged(tmp_path):
    exe = tmp_path / "calm.exe"
    exe.write_bytes(b"MZ")
    e = make_entry(path=str(exe), command=f'"{exe}"', signer_status="Signed")
    e.raw_data = {}
    normalize.normalize_all([e], signature_eval=_FakeSigner(), hash_cache=HashCache())
    assert not e.sha256
    assert e.raw_data.get("hash_status") == "Not Calculated"


def test_lnk_target_preferred(tmp_path):
    target = tmp_path / "target.exe"
    target.write_bytes(b"MZ")
    lnk = tmp_path / "x.lnk"
    lnk.write_bytes(b"fake")
    e = make_entry(path=str(lnk), command=str(target), file_extension=".lnk")
    e.raw_data = {}
    normalize._resolve_candidate(e)
    assert e.file_state == "Exists"
    assert e.raw_data["_signature_candidate"] == str(target)