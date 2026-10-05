"""Overview dashboard page."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

from app.models.scan_result import ScanResult


class StatBox(QFrame):
    def __init__(self, label: str, value: str = "0", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("statBox")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        self.num = QLabel(value)
        self.num.setObjectName("statNumber")
        self.lbl = QLabel(label)
        self.lbl.setObjectName("statLabel")
        layout.addWidget(self.num)
        layout.addWidget(self.lbl)


class OverviewPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 16, 20, 16)

        title = QLabel("OVERVIEW")
        title.setObjectName("pageTitle")
        outer.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.body = QWidget()
        self.stack = QVBoxLayout(self.body)
        self.stack.setContentsMargins(0, 10, 0, 10)
        self.stack.setSpacing(8)
        scroll.setWidget(self.body)
        outer.addWidget(scroll, 1)

        self._empty = QLabel("No data yet. Run a scan.")
        self._empty.setObjectName("bodyText")
        self.stack.addWidget(self._empty)
        self.stack.addStretch(1)

    # ------------------------------------------------------------------
    def refresh(self, result: Optional[ScanResult], interesting_limit: int = 12) -> None:
        self._clear()
        if result is None:
            empty = QLabel("No data yet. Run a scan.")
            empty.setObjectName("bodyText")
            self.stack.addWidget(empty)
            self.stack.addStretch(1)
            return

        counts = result.count_by_source()
        boxes = QGridLayout()
        boxes.setSpacing(8)
        stats = [
            ("Total Persistence Entries", str(len(result.entries))),
            ("Registry Entries", str(counts.get("Registry", 0))),
            ("Startup Items", str(counts.get("Startup", 0))),
            ("Scheduled Tasks", str(counts.get("Scheduled Task", 0))),
            ("Services", str(counts.get("Service", 0))),
            ("WMI Subscriptions", str(counts.get("WMI", 0))),
            ("Unsigned Items", str(result.unsigned_count)),
            ("Flagged Items", str(result.flagged_count)),
            ("Missing Targets", str(result.missing_target_count)),
        ]
        for idx, (label, value) in enumerate(stats):
            box = StatBox(label, value)
            boxes.addWidget(box, idx // 3, idx % 3)
        self.stack.addLayout(boxes)

        if result.problems:
            warn = QLabel("COLLECTION WARNINGS")
            warn.setObjectName("detailHeader")
            self.stack.addWidget(warn)
            for p in result.problems:
                line = QLabel(f"[{p.level}] {p.source}: {p.message}")
                line.setObjectName("bodyText")
                line.setWordWrap(True)
                self.stack.addWidget(line)

        self.stack.addWidget(self._header_label("POTENTIALLY INTERESTING ENTRIES"))
        flagged = sorted(
            [e for e in result.entries if e.indicators],
            key=lambda e: e.risk_score, reverse=True,
        )[:interesting_limit]
        if not flagged:
            self.stack.addWidget(self._label("No entries with indicators."))
        for e in flagged:
            row = self._label(
                f"{e.risk_level.upper():<10} {str(e.source):<15} {e.name:<30} "
                f"{e.short_path(70)}"
            )
            row.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.stack.addWidget(row)

        if len(result.entries) == 0:
            self.stack.addWidget(self._label("No persistence entries found."))
        self.stack.addStretch(1)

    # ------------------------------------------------------------------
    def _clear(self) -> None:
        def _clear_layout(layout) -> None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
                elif item.layout() is not None:
                    _clear_layout(item.layout())
        _clear_layout(self.stack)

    @staticmethod
    def _header_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("detailHeader")
        return label

    @staticmethod
    def _label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("bodyText")
        label.setWordWrap(True)
        return label