"""Report exporters: valid, deterministic output for each format."""

from __future__ import annotations

import csv
import io
import json

import pytest

from app.models.scan_result import ScanResult, SourceResult, CollectionProblem
from app.reports import csv_export, html_export, json_export, txt_export
from tests.conftest import sample_batch


def _scan() -> ScanResult:
    result = ScanResult(
        scan_started="2026-09-20T12:00:00",
        scan_finished="2026-09-20T12:00:05",
        computer_name="HOST",
        os_name="Windows",
        os_version="10.0.19045",
        os_architecture="AMD64",
        tool_version="1.0.0",
        privilege="Standard User",
        scan_id="smoke-test",
    )
    result.entries = sample_batch()
    result.entries[0].add_indicator("Unsigned", "Unsigned", evidence="legacy")
    result.sources = [SourceResult(source="Registry", status="Complete", entry_count=2)]
    result.problems = [CollectionProblem(source="WMI", message="partial", level="WARNING")]
    return result


@pytest.fixture
def scan():
    return _scan()


def test_json_valid(scan, tmp_path):
    out = tmp_path / "r.json"
    assert json_export.export_json(scan, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["computer_name"] == "HOST"
    assert data["schema_version"] == 1
    assert len(data["entries"]) == len(sample_batch())
    # re-loadable through the model
    restored = ScanResult.from_dict(data)
    assert len(restored.entries) == len(scan.entries)
    assert restored.entries[0].indicator_labels() == ["Unsigned"]  # serialized indicators survive


def test_csv_valid(scan, tmp_path):
    out = tmp_path / "r.csv"
    assert csv_export.export_csv(scan, str(out))
    with open(out, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == csv_export.COLUMNS
    assert len(rows) == 1 + len(sample_batch())


def test_txt_output(scan, tmp_path):
    out = tmp_path / "r.txt"
    assert txt_export.export_txt(scan, str(out))
    text = out.read_text(encoding="utf-8")
    assert "PersistMap" in text
    assert "HOST" in text
    assert "Total entries" in text
    assert "Scheduled Task" in text


def test_html_output(scan, tmp_path):
    out = tmp_path / "r.html"
    assert html_export.export_html(scan, str(out))
    text = out.read_text(encoding="utf-8")
    assert "<html" in text
    assert "E53935" in text  # theme colour present
    assert "PersistMap Report" in text


def test_export_errors_are_reported_cleanly(scan, tmp_path):
    errors = []
    ok = json_export.export_json(scan, str(tmp_path / "nope" / "x.json"),
                                 errors=lambda source, detail: errors.append(detail))
    assert not ok
    assert errors


def test_empty_result_exports(scan, tmp_path):
    scan2 = ScanResult(scan_started="x", computer_name="A", os_name="W",
                       scan_finished="y", tool_version="1", scan_id="z", privilege="u")
    out = tmp_path / "e.json"
    assert json_export.export_json(scan2, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["entries"] == []
