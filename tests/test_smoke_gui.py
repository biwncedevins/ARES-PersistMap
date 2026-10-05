"""End-to-end GUI smoke test (Qt offscreen). Offline, mocked collectors."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from app.models.enums import CollectionStatus, Source
from app.models.entry import PersistenceEntry


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _fake_collector(entries):
    def collect(progress=None, errors=None):
        if progress:
            progress("collecting")
        return entries, CollectionStatus.COMPLETE, {"count": len(entries)}
    return collect


def _batch():
    e1 = PersistenceEntry(source=Source.REGISTRY.value, category="Run", name="evil",
                          path=r"C:\Users\victim\AppData\Roaming\up.exe",
                          command=r'"C:\Users\victim\AppData\Roaming\up.exe" -x',
                          signer_status="Unsigned", user="victim", architecture="64-bit")
    e2 = PersistenceEntry(source=Source.SCHEDULED_TASK.value, category="Scheduled Task",
                          name="TaskBackup",
                          path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          command="powershell.exe -EncodedCommand AAAA",
                          user="SYSTEM", architecture="Highest")
    e3 = PersistenceEntry(source=Source.STARTUP.value, category="User Startup",
                          name="clean.lnk", path=r"C:\startup\clean.lnk",
                          command=r"C:\Program Files\Clean\c.exe",
                          user="victim", architecture="64-bit")
    e4 = PersistenceEntry(source=Source.SERVICE.value, category="Service", name="legit",
                          path=r"C:\Program Files\Legit\s.exe",
                          command=r"C:\Program Files\Legit\s.exe",
                          user="LocalSystem", status="Running", architecture="64-bit")
    return [e1, e2, e3, e4]


def test_smoke_scan_and_table(qapp, monkeypatch, tmp_path):
    from app.workers import scan_worker
    from app.ui.main_window import MainWindow

    batch = _batch()
    monkeypatch.setattr(scan_worker, "SOURCE_ORDER", [
        (Source.REGISTRY.value, _fake_collector(batch[0:1])),
        (Source.STARTUP.value, _fake_collector(batch[2:3])),
        (Source.SCHEDULED_TASK.value, _fake_collector(batch[1:2])),
        (Source.SERVICE.value, _fake_collector(batch[3:4])),
        (Source.WMI.value, _fake_collector([])),
    ])

    window = MainWindow()
    try:
        worker = scan_worker.ScanWorker("9.9-test", window)
        result = worker.execute()
        assert len(result.entries) == 4
        assert result.get_source_status(Source.WMI.value).status == CollectionStatus.COMPLETE

        window._on_scan_finished(result)
        table = window.entries_table
        assert table.table_model.rowCount() == 4

        window.search_box.setText("powershell")
        QApplication.processEvents()
        assert table.proxy_model.rowCount() == 1

        window.search_box.setText("")
        QApplication.processEvents()
        assert table.proxy_model.rowCount() == 4

        window.source_combo.setCurrentText("Registry")
        QApplication.processEvents()
        assert table.proxy_model.rowCount() == 1

        window.reset_filters()
        table.selectRow(0)
        QApplication.processEvents()
        entry = table.table_model.entry_at(0)
        window.details_panel.set_entry(entry)

        out = tmp_path / "smoke.txt"
        from app.reports import txt_export
        assert txt_export.export_txt(result, str(out))
        assert "PersistMap" in out.read_text(encoding="utf-8")
    finally:
        window.close()


def test_smoke_pages_and_overview(qapp):
    from app.ui.main_window import MainWindow
    from app.models.scan_result import ScanResult

    window = MainWindow()
    try:
        from tests.conftest import sample_batch
        result = ScanResult(scan_started="x", scan_finished="y", computer_name="SMOKE",
                            os_name="Windows", tool_version="1", scan_id="s1",
                            privilege="Standard User")
        result.entries = sample_batch()
        window._on_scan_finished(result)
        for page in ("reports", "settings", "overview", "all"):
            window.sidebar.select_page(page)
            QApplication.processEvents()
        window.overview.refresh(result)
        assert window.entries_value.text() == str(len(result.entries))
    finally:
        window.close()