"""Main application window: toolbar, sidebar, stacked pages, details."""

from __future__ import annotations

import datetime
import os
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QSplitter,
    QStackedWidget, QVBoxLayout, QWidget,
)

import config
from app.models.scan_result import ScanResult
from app.reports import csv_export, html_export, json_export, txt_export
from app.ui.details_panel import DetailsPanel
from app.ui.overview import OverviewPage
from app.ui.sidebar import (
    PAGE_ALL, PAGE_DUPLICATES, PAGE_OVERVIEW, PAGE_REGISTRY, PAGE_REPORTS,
    PAGE_SERVICES, PAGE_SETTINGS, PAGE_STARTUP, PAGE_TASKS, PAGE_WMI, Sidebar,
)
from app.ui.table_view import COL_INDEX, EntryTableView
from app.utils.logging import get_logger, get_logs_file
from app.workers.scan_worker import ScanWorker, detect_privilege

log = get_logger()

SOURCE_NAV = {
    PAGE_REGISTRY: ("Registry", "All Entries - Registry"),
    PAGE_STARTUP: ("Startup", "All Entries - Startup"),
    PAGE_TASKS: ("Scheduled Task", "All Entries - Scheduled Tasks"),
    PAGE_SERVICES: ("Service", "All Entries - Services"),
    PAGE_WMI: ("WMI", "All Entries - WMI"),
}

RISK_LEVELS = ["", "Low", "Medium", "Elevated", "High", "Critical"]
SIGNER_STATES = ["", "Signed", "Unsigned", "Invalid", "Unknown", "Unavailable"]


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"PersistMap — {config.APP_SUBTITLE}")
        self.resize(1280, 820)
        self.setMinimumSize(960, 620)

        self._result: Optional[ScanResult] = None
        self._worker: Optional[ScanWorker] = None
        self._privilege = detect_privilege()

        central = QWidget()
        central.setObjectName("centralRoot")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- sidebar ----------------------------------------------------
        self.sidebar = Sidebar()
        self.sidebar.page_selected.connect(self._on_navigate)
        root.addWidget(self.sidebar)

        # ---- right side -------------------------------------------------
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        root.addLayout(right, 1)

        self._build_toolbar(right)
        self._build_pages(right)
        self._build_statusbar()

        self._apply_current_filters = False
        self._navigate(PAGE_OVERVIEW)

    # ------------------------------------------------------------------
    # toolbar
    # ------------------------------------------------------------------
    def _build_toolbar(self, parent_layout: QVBoxLayout) -> None:
        bar = QWidget()
        bar.setObjectName("toolbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(14)

        self.scan_button = QPushButton("SCAN")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.clicked.connect(self.start_scan)
        lay.addWidget(self.scan_button)

        self.progress_label = QLabel("Ready.")
        self.progress_label.setObjectName("progressLabel")
        self.progress_label.setStyleSheet("color:#E53935;font-size:11px;font-weight:600;")
        lay.addWidget(self.progress_label)
        lay.addStretch(1)

        self.last_scan_label = QLabel("Last Scan:")
        self.last_scan_label.setObjectName("toolbarLabel")
        lay.addWidget(self.last_scan_label)
        self.last_scan_value = QLabel("—")
        self.last_scan_value.setObjectName("toolbarValue")
        lay.addWidget(self.last_scan_value)

        self.entries_label = QLabel("Entries:")
        self.entries_label.setObjectName("toolbarLabel")
        lay.addWidget(self.entries_label)
        self.entries_value = QLabel("0")
        self.entries_value.setObjectName("toolbarValue")
        lay.addWidget(self.entries_value)

        self.flagged_label = QLabel("Flagged:")
        self.flagged_label.setObjectName("toolbarLabel")
        lay.addWidget(self.flagged_label)
        self.flagged_value = QLabel("0")
        self.flagged_value.setObjectName("flagRed")
        lay.addWidget(self.flagged_value)

        self.export_button = QPushButton("EXPORT")
        self.export_button.setObjectName("toolButton")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_report)
        lay.addWidget(self.export_button)

        parent_layout.addWidget(bar)

    # ------------------------------------------------------------------
    # pages
    # ------------------------------------------------------------------
    def _build_pages(self, parent_layout: QVBoxLayout) -> None:
        self.stack = QStackedWidget()
        parent_layout.addWidget(self.stack, 1)

        self.overview = OverviewPage()
        self.stack.addWidget(self.overview)

        self.entries_page = self._build_entries_page()
        self.stack.addWidget(self.entries_page)

        self.reports_page = self._build_reports_page()
        self.stack.addWidget(self.reports_page)

        self.settings_page = self._build_settings_page()
        self.stack.addWidget(self.settings_page)

    def _build_entries_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # page title
        self.entries_title = QLabel("ALL ENTRIES")
        self.entries_title.setObjectName("pageTitle")
        titlebar = QWidget()
        t = QHBoxLayout(titlebar)
        t.setContentsMargins(12, 8, 12, 4)
        t.addWidget(self.entries_title)
        t.addStretch(1)
        self.visible_count_label = QLabel("")
        self.visible_count_label.setObjectName("toolbarLabel")
        t.addWidget(self.visible_count_label)

        # table + details FIRST so the filter bar can connect to them
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.entries_table = EntryTableView()
        splitter.addWidget(self.entries_table)

        self.details_panel = DetailsPanel()
        self.details_panel.setMinimumHeight(180)
        splitter.addWidget(self.details_panel)
        splitter.setSizes([460, 300])
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self.entries_table.selection_changed.connect(self.details_panel.set_entry)
        self.entries_table.entry_activated.connect(self.details_panel.set_entry)
        self.entries_table.proxy_model.rowsInserted.connect(self._update_visible_count)
        self.entries_table.proxy_model.rowsRemoved.connect(self._update_visible_count)
        self.entries_table.proxy_model.modelReset.connect(self._update_visible_count)

        empty_overlay_label = QLabel("No persistence entries found.", self.entries_table)
        empty_overlay_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_overlay_label.setStyleSheet("color:#555;font-size:13px;")
        empty_overlay_label.hide()
        self.empty_overlay = empty_overlay_label
        self._empty_overlay_widget = empty_overlay_label

        v.addWidget(titlebar)
        v.addWidget(self._build_filterbar())
        v.addWidget(splitter, 1)
        return page

    def _build_filterbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("toolbar")
        bar.setStyleSheet("border-bottom:1px solid #1A1A1A;")
        grid = QGridLayout(bar)
        grid.setContentsMargins(12, 6, 12, 6)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(4)

        self.search_box = QLineEdit()
        self.search_box.setObjectName("searchBox")
        self.search_box.setPlaceholderText("Search name, path, command, user, publisher, indicators...")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(self.entries_table.proxy_model.set_search)
        grid.addWidget(self.search_box, 0, 0, 1, 6)

        def combo():
            cb = QComboBox()
            cb.setMinimumWidth(130)
            return cb

        self.source_combo = combo()
        self.source_combo.addItem("All Sources", None)
        for s in ["Registry", "Startup", "Scheduled Task", "Service", "WMI"]:
            self.source_combo.addItem(s, s)
        self.source_combo.currentIndexChanged.connect(
            lambda _i: self.entries_table.proxy_model.set_source(
                self.source_combo.currentData() or None))
        grid.addWidget(QLabel("Source"), 1, 0)
        grid.addWidget(self.source_combo, 1, 1)

        self.risk_combo = combo()
        self.risk_combo.addItem("All Risks")
        for lvl in RISK_LEVELS[1:]:
            self.risk_combo.addItem(lvl)
        self.risk_combo.currentIndexChanged.connect(
            lambda _i: self.entries_table.proxy_model.set_risk_min_level(
                self.risk_combo.currentText() or None))
        grid.addWidget(QLabel("Risk ≥"), 1, 2)
        grid.addWidget(self.risk_combo, 1, 3)

        self.signer_combo = combo()
        self.signer_combo.addItem("All Signers")
        for st in SIGNER_STATES[1:]:
            self.signer_combo.addItem(st)
        self.signer_combo.currentIndexChanged.connect(
            lambda _i: self.entries_table.proxy_model.set_signer(
                self.signer_combo.currentText() or None))
        grid.addWidget(QLabel("Signer"), 1, 4)
        grid.addWidget(self.signer_combo, 1, 5)

        self.user_combo = combo()
        self.user_combo.setMinimumWidth(150)
        self.user_combo.addItem("All Users")
        self.user_combo.currentIndexChanged.connect(
            lambda _i: self.entries_table.proxy_model.set_user(
                self.user_combo.currentData() or None))
        grid.addWidget(QLabel("User"), 2, 0)
        grid.addWidget(self.user_combo, 2, 1)

        self.status_combo = combo()
        self.status_combo.addItem("All States")
        self.status_combo.currentIndexChanged.connect(
            lambda _i: self.entries_table.proxy_model.set_status(
                self.status_combo.currentData() or None))
        grid.addWidget(QLabel("Status"), 2, 2)
        grid.addWidget(self.status_combo, 2, 3)

        def checkbox(text):
            cb = QCheckBox(text)
            cb.setObjectName("filterCheck")
            return cb

        self.flag_check = checkbox("Flagged only")
        self.flag_check.toggled.connect(self.entries_table.proxy_model.set_flagged_only)
        self.unsigned_check = checkbox("Unsigned only")
        self.unsigned_check.toggled.connect(self.entries_table.proxy_model.set_unsigned_only)
        self.missing_check = checkbox("Missing file")
        self.missing_check.toggled.connect(self.entries_table.proxy_model.set_missing_only)
        self.duplicates_check = checkbox("Duplicates")
        self.duplicates_check.toggled.connect(self.entries_table.proxy_model.set_duplicates_only)
        grid.addWidget(self.flag_check, 2, 4)
        grid.addWidget(self.unsigned_check, 2, 5)
        grid.addWidget(self.missing_check, 3, 4)
        grid.addWidget(self.duplicates_check, 3, 5)

        reset = QPushButton("Reset")
        reset.setObjectName("smallButton")
        reset.clicked.connect(self.reset_filters)
        grid.addWidget(reset, 3, 0)
        return bar

    # ------------------------------------------------------------------
    # reports + settings pages
    # ------------------------------------------------------------------
    def _build_reports_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(20, 16, 20, 16)
        title = QLabel("REPORTS")
        title.setObjectName("pageTitle")
        v.addWidget(title)

        note = QLabel(
            "Export the current scan as an offline report. Every file includes "
            "scan metadata, collection status, entries, indicators, risk reasons "
            "and signature states. Nothing is uploaded anywhere."
        )
        note.setObjectName("bodyText")
        note.setWordWrap(True)
        v.addWidget(note)

        self.report_status = QLabel("")
        self.report_status.setObjectName("toolbarLabel")
        v.addWidget(self.report_status)

        grid = QGridLayout()
        grid.setSpacing(8)
        formats = [
            ("Export JSON", "JSON Report (*.json)", json_export.export_json),
            ("Export CSV", "CSV Report (*.csv)", csv_export.export_csv),
            ("Export TXT", "Text Report (*.txt)", txt_export.export_txt),
            ("Export HTML", "HTML Report (*.html)", html_export.export_html),
        ]
        for idx, (label, _filter, _handler) in enumerate(formats):
            btn = QPushButton(label)
            btn.setObjectName("toolButton")
            btn.clicked.connect(
                lambda checked=False, f=_filter, h=_handler: self._do_export(f, h))
            grid.addWidget(btn, idx // 2, idx % 2)
        v.addLayout(grid)
        v.addStretch(1)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(20, 16, 20, 16)
        title = QLabel("SETTINGS / ABOUT")
        title.setObjectName("pageTitle")
        v.addWidget(title)

        for text in [
            f"Version: {config.APP_VERSION}",
            f"Privilege: {self._privilege}",
            f"Log file: {get_logs_file()}",
            "",
            "Administrator privileges may reveal additional persistence artifacts.",
            "",
            "PERSISTMAP IS A READ-ONLY INVENTORY AND FORENSICS TOOL.",
            "It does not:",
            "  • delete, disable, quarantine or 'fix' anything",
            "  • stop or start services or scheduled tasks",
            "  • modify the registry, WMI or task scheduler",
            "  • execute any discovered command",
            "  • contact the network or send telemetry",
            "",
            "Risk scores are heuristic indicators, not verdicts.",
        ]:
            label = QLabel(text)
            label.setObjectName("bodyText")
            label.setWordWrap(True)
            v.addWidget(label)
        v.addStretch(1)
        return page

    # ------------------------------------------------------------------
    # statusbar
    # ------------------------------------------------------------------
    def _build_statusbar(self) -> None:
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("PersistMap ready. Offline. Read-only.")

    # ------------------------------------------------------------------
    # navigation
    # ------------------------------------------------------------------
    def _on_navigate(self, page: str) -> None:
        self._navigate(page)

    def _navigate(self, page: str) -> None:
        self.sidebar.select_page(page)
        if page == PAGE_OVERVIEW:
            self.stack.setCurrentWidget(self.overview)
            if self._result:
                self.overview.refresh(self._result)
            return
        if page == PAGE_REPORTS:
            self.stack.setCurrentWidget(self.reports_page)
            return
        if page == PAGE_SETTINGS:
            self.stack.setCurrentWidget(self.settings_page)
            return
        # entries table page
        self.stack.setCurrentWidget(self.entries_page)
        self.reset_filters()
        if page == PAGE_ALL:
            self.entries_title.setText("ALL ENTRIES")
            self.entries_table.apply_settings(duplicates=False)
        elif page == PAGE_DUPLICATES:
            self.entries_title.setText("DUPLICATE GROUPS")
            self.entries_table.apply_settings(duplicates=True)
        elif page in SOURCE_NAV:
            source, title = SOURCE_NAV[page]
            self.entries_title.setText(title)
            self.entries_table.apply_settings(source=source)
        else:
            self.entries_title.setText("ALL ENTRIES")
        self._update_visible_count()

    def reset_filters(self) -> None:
        self.search_box.setText("")
        self.source_combo.setCurrentIndex(0)
        self.risk_combo.setCurrentIndex(0)
        self.signer_combo.setCurrentIndex(0)
        self.user_combo.setCurrentIndex(0)
        self.status_combo.setCurrentIndex(0)
        self.flag_check.setChecked(False)
        self.unsigned_check.setChecked(False)
        self.missing_check.setChecked(False)
        self.duplicates_check.setChecked(False)
        self._update_visible_count()

    # ------------------------------------------------------------------
    # scan
    # ------------------------------------------------------------------
    def start_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "PersistMap", "A scan is already running.")
            return
        self.scan_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.progress_label.setText("Scanning...")
        self.status_bar.showMessage("Scan in progress...")
        self._worker = ScanWorker(config.APP_VERSION, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_scan.connect(self._on_scan_finished)
        self._worker.failed.connect(self._on_scan_failed)
        self._worker.start()

    def _on_progress(self, message: str) -> None:
        self.progress_label.setText(message)

    def _on_scan_finished(self, result: ScanResult) -> None:
        self._result = result
        self.scan_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.progress_label.setText("Done.")
        self.status_bar.showMessage(
            f"Scan complete. {len(result.entries)} entries, "
            f"{result.flagged_count} flagged."
            + ("  Collection completed with warnings." if result.has_warnings else ""))

        last = result.scan_finished or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_scan_value.setText(last)
        self.entries_value.setText(str(len(result.entries)))
        self.flagged_value.setText(str(result.flagged_count))

        self.sidebar.update_counts(result.count_by_source())
        self.overview.refresh(result)
        self.entries_table.set_scan_result(result)
        self._populate_filter_combos()
        if self.stack.currentWidget() is self.overview:
            self._navigate(PAGE_OVERVIEW)
        else:
            self._navigate(PAGE_ALL)
        self._update_visible_count()
        self.status_bar.showMessage(
            f"Done. {len(result.entries)} entries | "
            f"{result.unsigned_count} unsigned | {result.missing_target_count} missing targets "
            f"| {result.wmi_count} WMI subscriptions",
            10000,
        )

    def _on_scan_failed(self, message: str) -> None:
        self.scan_button.setEnabled(True)
        self.progress_label.setText("Scan failed.")
        self.status_bar.showMessage(f"Scan failed: {message}")
        QMessageBox.critical(self, "PersistMap", f"Scan failed:\n{message}")

    # ------------------------------------------------------------------
    # filters helpers
    # ------------------------------------------------------------------
    def _populate_filter_combos(self) -> None:
        if not self._result:
            return
        users = sorted({e.user for e in self._result.entries if e.user})
        statuses = sorted({str(e.status) for e in self._result.entries if e.status})
        self.user_combo.clear()
        self.user_combo.addItem("All Users", None)
        for u in users:
            self.user_combo.addItem(u, u)
        self.status_combo.clear()
        self.status_combo.addItem("All States", None)
        for s in statuses:
            self.status_combo.addItem(s, s)

    def _update_visible_count(self) -> None:
        if hasattr(self, "entries_table") and self.entries_table is not None:
            count = self.entries_table.proxy_model.rowCount()
            total = len(self.entries_table.table_model.entries())
            text = f"{count} / {total} shown"
            if count == 0 and total > 0:
                self.empty_overlay.setText("No entries match the current filters.")
                self.empty_overlay.show()
                text += "  |  no matches for filters"
            else:
                self.empty_overlay.hide()
            self.visible_count_label.setText(text)

        if hasattr(self, "entries_table") and self.entries_table is not None:
            if len(self.entries_table.table_model.entries()) == 0:
                self.empty_overlay.show()
                self.empty_overlay.setText("No persistence entries found.")
            elif self.entries_table.proxy_model.rowCount() == 0:
                self.empty_overlay.setText("No entries match the current filters.")
                self.empty_overlay.show()

    # ------------------------------------------------------------------
    # export
    # ------------------------------------------------------------------
    def export_report(self) -> None:
        self.stack.setCurrentWidget(self.reports_page)
        self.report_status.setText("Select a format to save the current scan report.")

    def _do_export(self, file_filter: str, handler) -> None:
        if not self._result:
            QMessageBox.information(self, "PersistMap", "Run a scan before exporting.")
            return
        ext_map = {"json": "json", "csv": "csv", "txt": "txt", "html": "html"}
        default_name = f"persistmap_report_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report",
            os.path.join(os.path.expanduser("~"), "Desktop", default_name),
            file_filter)
        if not path:
            return
        ok = handler(self._result, path, errors=self._report_error)
        if ok:
            self.report_status.setText(f"Report written to:\n{path}")
            self.status_bar.showMessage(f"Report exported: {path}")
        else:
            self.report_status.setText("Export failed. See log for details.")

    def _report_error(self, source: str, msg: str) -> None:
        log.error("%s: %s", source, msg)
        self.report_status.setText(f"Export error [{source}]: {msg}")

    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        event.accept()