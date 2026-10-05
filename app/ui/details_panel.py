"""Right/bottom details panel for the selected entry."""

from __future__ import annotations

import json
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout, QLabel, QPlainTextEdit, QScrollArea, QVBoxLayout, QWidget,
)

from app.models.entry import PersistenceEntry

_MISSING = ["..", "..."]


class DetailsPanel(QWidget):
    """Read-only evidence view; never an editor."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("detailsPanel")
        self._current: Optional[PersistenceEntry] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 8, 14, 8)

        self.title = QLabel("ENTRY DETAILS")
        self.title.setObjectName("detailTitle")
        outer.addWidget(self.title)

        scroll = QScrollArea()
        scroll.setObjectName("detailsScroll")
        scroll.setWidgetResizable(True)
        container = QWidget()
        self._layout = QVBoxLayout(container)
        self._layout.setContentsMargins(0, 4, 0, 4)
        self._layout.setSpacing(2)
        scroll.setWidget(container)
        outer.addWidget(scroll, 1)

        self._empty_label = QLabel("Select an entry to view its details.")
        self._empty_label.setObjectName("bodyText")
        self._layout.addWidget(self._empty_label)
        self._layout.addStretch(1)

    # ------------------------------------------------------------------
    def set_entry(self, entry: Optional[PersistenceEntry]) -> None:
        self._current = entry
        self._clear()
        if entry is None:
            self._empty_label = QLabel("Select an entry to view its details.")
            self._empty_label.setObjectName("bodyText")
            self._layout.addWidget(self._empty_label)
            self._layout.addStretch(1)
            return
        self._render(entry)

    def _clear(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    # ------------------------------------------------------------------
    def _render(self, e: PersistenceEntry) -> None:
        self.title.setText(f"ENTRY DETAILS — {e.name}")

        def header(text: str) -> None:
            self._layout.addWidget(self._make_label(text, "detailHeader"))

        def grid(pairs: list[tuple[str, str]]) -> None:
            g = QGridLayout()
            g.setHorizontalSpacing(12)
            g.setVerticalSpacing(1)
            for row, (key, value) in enumerate(pairs):
                k = self._make_label(key, "detailKey")
                k.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
                v = self._make_label(value, "detailVal")
                v.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
                v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                v.setWordWrap(True)
                g.addWidget(k, row, 0)
                g.addWidget(v, row, 1)
            g.setColumnStretch(1, 1)
            g.setColumnMinimumWidth(0, 170)
            self._layout.addLayout(g)

        # General --------------------------------------------------------
        header("GENERAL")
        grid([
            ("Source", str(e.source)),
            ("Category", str(e.category)),
            ("Name", e.name),
            ("User", e.user or "Unknown"),
            ("Status", str(e.status or "Unknown")),
            ("Architecture/View", e.architecture or ""),
        ])

        # Execution ------------------------------------------------------
        header("EXECUTION")
        grid([
            ("Path", e.path or "—"),
            ("Command", e.command or "—"),
            ("Arguments", e.arguments or "—"),
            ("Working Directory", e.working_directory or "—"),
        ])

        # Registry context (only when relevant) --------------------------
        if e.hive or e.key_path or e.value_name:
            header("REGISTRY CONTEXT")
            grid([
                ("Hive", e.hive or "—"),
                ("Key Path", e.key_path or "—"),
                ("Value Name", e.value_name or "—"),
            ])

        # Signature ------------------------------------------------------
        header("SIGNATURE")
        grid([
            ("Signer Status", str(e.signer_status or "Unknown")),
            ("Publisher", e.publisher or "—"),
            ("File State", e.file_state or "—"),
            ("SHA256", e.sha256 or "—"),
        ])

        # Timeline -------------------------------------------------------
        header("TIMELINE")
        grid([
            ("Created", e.created_time or "—"),
            ("Modified", e.modified_time or "—"),
            ("Last Run", e.last_run_time or "—"),
            ("Next Run", e.next_run_time or "—"),
        ])

        # Indicators -----------------------------------------------------
        header("INDICATORS")
        if e.indicators:
            grid([(i.label, i.evidence or "—") for i in e.indicators])
        else:
            self._layout.addWidget(self._make_label("(none)", "detailVal"))

        # Risk -----------------------------------------------------------
        header("RISK")
        grid([
            ("Score", str(e.risk_score)),
            ("Level", str(e.risk_level)),
        ])
        if e.risk_reasons:
            reasons = QPlainTextEdit("\n".join(e.risk_reasons))
            reasons.setReadOnly(True)
            reasons.setMaximumHeight(min(40 + 16 * len(e.risk_reasons), 220))
            self._style_text(reasons)
            self._layout.addWidget(reasons)
        else:
            self._layout.addWidget(self._make_label("(no contributing reasons)", "detailKey"))

        # Evidence -------------------------------------------------------
        header("EVIDENCE")
        if e.evidence_raw:
            ev = QPlainTextEdit("\n".join(e.evidence_raw))
            ev.setReadOnly(True)
            ev.setMaximumHeight(min(40 + 16 * len(e.evidence_raw), 220))
            self._style_text(ev)
            self._layout.addWidget(ev)
        else:
            self._layout.addWidget(self._make_label("(no evidence recorded)", "detailKey"))

        # Raw data -------------------------------------------------------
        header("RAW SOURCE DATA")
        raw_text = json.dumps(e.raw_data, indent=2, ensure_ascii=False, default=str) \
            if e.raw_data else "{}"
        raw = QPlainTextEdit(raw_text)
        raw.setReadOnly(True)
        raw.setMaximumHeight(300)
        self._style_text(raw)
        self._layout.addWidget(raw)

        self._layout.addStretch(1)

    # ------------------------------------------------------------------
    @staticmethod
    def _make_label(text: str, obj: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName(obj)
        return label

    @staticmethod
    def _style_text(widget: QPlainTextEdit) -> None:
        widget.setStyleSheet(
            "QPlainTextEdit{background:#080808;color:#c9c9c9;border:1px solid #1C1C1C;"
            "font-family:Consolas,monospace;font-size:11px;}"
        )