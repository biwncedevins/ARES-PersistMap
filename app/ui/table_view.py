"""Unified entries table: model, proxy (search/filters), and view."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QAction, QBrush, QColor
from PySide6.QtWidgets import QHeaderView, QMenu, QTableView

from app.models.scan_result import ScanResult
from app.models.enums import RiskLevel

COL_INDEX = {
    "risk": 0, "source": 1, "name": 2, "signer": 3, "path": 4, "user": 5,
    "status": 6, "indicators": 7, "category": 8, "file": 9,
    "publisher": 10, "args": 11, "hash": 12, "last_run": 13,
    "next_run": 14, "dup_group": 15, "id": 16,
}

HEADERS = [
    "Risk", "Source", "Name", "Signer", "Path", "User", "Status", "Indicators",
    "Category", "File", "Publisher", "Arguments", "SHA256", "Last Run",
    "Next Run", "Dup Group", "ID",
]

DEFAULT_VISIBLE = [0, 1, 2, 3, 4, 5, 6, 7]

RISK_ORDER = {RiskLevel.LOW.value: 0, RiskLevel.MEDIUM.value: 1,
              RiskLevel.ELEVATED.value: 2, RiskLevel.HIGH.value: 3,
              RiskLevel.CRITICAL.value: 4}

_RED = QColor("#E53935")
_FADED_RED = QColor("#E57373")


class EntryTableModel(QAbstractTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._entries: list = []
        self._source: Optional[ScanResult] = None

    def set_result(self, result: Optional[ScanResult]) -> None:
        self.beginResetModel()
        self._source = result
        self._entries = list(result.entries) if result else []
        self.endResetModel()

    def entry_at(self, row: int):
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None

    def entries(self) -> list:
        return self._entries

    # ------------------------- qt api --------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self.entry_at(index.row())
        if entry is None:
            return None
        col = index.column()

        if role == Qt.UserRole:
            return self._sort_value(entry, col)
        if role == Qt.DisplayRole:
            value = self._cell(entry, col)
            if col == COL_INDEX["indicators"]:
                return ", ".join(value[:4]) if value else ""
            return value
        if role == Qt.ForegroundRole:
            if col == COL_INDEX["risk"] and entry.risk_level in (
                    RiskLevel.HIGH.value, RiskLevel.CRITICAL.value):
                return QBrush(_RED)
            if col == COL_INDEX["file"] and entry.file_state == "Missing":
                return QBrush(_RED)
            if col == COL_INDEX["signer"] and entry.signer_status in ("Unsigned", "Invalid"):
                return QBrush(_FADED_RED)
            return None
        if role == Qt.ToolTipRole:
            return entry.display_path()
        if role == Qt.UserRole + 1:
            return entry
        return None

    @staticmethod
    def _sort_value(entry, col: int):
        if col == COL_INDEX["risk"]:
            return entry.risk_score
        if col == COL_INDEX["dup_group"]:
            return entry.duplicate_group_id
        return str(EntryTableModel._cell(entry, col)).lower()

    @staticmethod
    def _cell(entry, col: int):
        if col == COL_INDEX["risk"]:
            if entry.risk_score == 0:
                return ""
            return f"{entry.risk_level} {entry.risk_score}"
        if col == COL_INDEX["source"]:
            return str(entry.source)
        if col == COL_INDEX["name"]:
            return entry.name
        if col == COL_INDEX["signer"]:
            return str(entry.signer_status)
        if col == COL_INDEX["path"]:
            return entry.path or entry.command
        if col == COL_INDEX["user"]:
            return entry.user
        if col == COL_INDEX["status"]:
            return entry.status
        if col == COL_INDEX["indicators"]:
            return [i.label for i in entry.indicators]
        if col == COL_INDEX["category"]:
            return entry.category
        if col == COL_INDEX["file"]:
            return entry.file_state
        if col == COL_INDEX["publisher"]:
            return entry.publisher
        if col == COL_INDEX["args"]:
            return entry.arguments
        if col == COL_INDEX["hash"]:
            return entry.sha256
        if col == COL_INDEX["last_run"]:
            return entry.last_run_time
        if col == COL_INDEX["next_run"]:
            return entry.next_run_time
        if col == COL_INDEX["dup_group"]:
            return entry.duplicate_group_id
        if col == COL_INDEX["id"]:
            return entry.id
        return ""

    def haystack(self, row: int) -> str:
        entry = self.entry_at(row)
        if entry is None:
            return ""
        parts = [
            entry.name, entry.path, entry.command, entry.arguments, entry.user,
            entry.publisher, str(entry.source), entry.category,
            str(entry.signer_status), entry.status,
            " ".join(i.label for i in entry.indicators),
            entry.duplicate_group_id,
        ]
        return " ".join(parts).lower()


class EntryProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._search_tokens: list[str] = []
        self._source_filter: Optional[str] = None
        self._risk_min: Optional[int] = None
        self._signer_filter: Optional[str] = None
        self._user_filter: Optional[str] = None
        self._status_filter: Optional[str] = None
        self._flagged_only = False
        self._unsigned_only = False
        self._missing_only = False
        self._duplicates_only = False

    # -------- filter setters --------
    def _refilter(self) -> None:
        self.beginFilterChange()
        self.endFilterChange()

    def set_search(self, text: str) -> None:
        self._search_tokens = [t for t in text.lower().split() if t]
        self._refilter()

    def set_source(self, value: Optional[str]) -> None:
        self._source_filter = value
        self._refilter()

    def set_risk_min_level(self, level: Optional[str]) -> None:
        self._risk_min = RISK_ORDER.get(level) if level else None
        self._refilter()

    def set_signer(self, value: Optional[str]) -> None:
        self._signer_filter = value
        self._refilter()

    def set_user(self, value: Optional[str]) -> None:
        self._user_filter = value
        self._refilter()

    def set_status(self, value: Optional[str]) -> None:
        self._status_filter = value
        self._refilter()

    def set_flagged_only(self, flag: bool) -> None:
        self._flagged_only = flag
        self._refilter()

    def set_unsigned_only(self, flag: bool) -> None:
        self._unsigned_only = flag
        self._refilter()

    def set_missing_only(self, flag: bool) -> None:
        self._missing_only = flag
        self._refilter()

    def set_duplicates_only(self, flag: bool) -> None:
        self._duplicates_only = flag
        self._refilter()

    # -------- filtering --------
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: EntryTableModel = self.sourceModel()
        if not model:
            return True
        entry = model.entry_at(source_row)
        if entry is None:
            return False

        if self._search_tokens:
            hay = model.haystack(source_row)
            if not all(tok in hay for tok in self._search_tokens):
                return False

        src = str(entry.source or "")
        if self._source_filter and src != self._source_filter:
            return False

        if self._risk_min is not None:
            lvl = RISK_ORDER.get(entry.risk_level, 0)
            if lvl < self._risk_min:
                return False

        if self._signer_filter and str(entry.signer_status) != self._signer_filter:
            return False

        if self._user_filter and entry.user != self._user_filter:
            return False

        if self._status_filter and entry.status != self._status_filter:
            return False

        if self._flagged_only and not entry.flagged:
            return False
        if self._unsigned_only and str(entry.signer_status) != "Unsigned":
            return False
        if self._missing_only and entry.file_state != "Missing":
            return False
        if self._duplicates_only and not entry.duplicate_group_id:
            return False
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        lv = left.data(Qt.UserRole)
        rv = right.data(Qt.UserRole)
        try:
            if lv is None and rv is None:
                return False
            if lv is None:
                return True
            if rv is None:
                return False
            if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
                return lv < rv
            return str(lv) < str(rv)
        except Exception:
            return False


class EntryTableView(QTableView):
    entry_activated = Signal(object)
    selection_changed = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("entryTable")
        self.table_model = EntryTableModel(self)
        self.proxy_model = EntryProxyModel(self)
        self.proxy_model.setSourceModel(self.table_model)
        super().setModel(self.proxy_model)

        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.setSortingEnabled(True)
        self.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.setWordWrap(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        for i in range(len(HEADERS)):
            self.setColumnHidden(i, i not in DEFAULT_VISIBLE)
        for idx, width in [(0, 110), (1, 100), (2, 170), (3, 80), (4, 320),
                           (5, 120), (6, 90), (7, 240)]:
            self.setColumnWidth(idx, width)

        self.sortByColumn(COL_INDEX["risk"], Qt.SortOrder.DescendingOrder)
        self.doubleClicked.connect(self._on_double)
        self.selectionModel().currentRowChanged.connect(self._on_selection)

    # -------- public API --------
    def set_scan_result(self, result: Optional[ScanResult]) -> None:
        self.table_model.set_result(result)

    def apply_settings(self, search_text: str = "", source: Optional[str] = None,
                      risk_min: Optional[str] = None, signer: Optional[str] = None,
                      user: Optional[str] = None, status: Optional[str] = None,
                      flagged: bool = False, unsigned: bool = False,
                      missing: bool = False, duplicates: bool = False) -> None:
        self.proxy_model.set_search(search_text)
        self.proxy_model.set_source(source)
        self.proxy_model.set_risk_min_level(risk_min)
        self.proxy_model.set_signer(signer)
        self.proxy_model.set_user(user)
        self.proxy_model.set_status(status)
        self.proxy_model.set_flagged_only(flagged)
        self.proxy_model.set_unsigned_only(unsigned)
        self.proxy_model.set_missing_only(missing)
        self.proxy_model.set_duplicates_only(duplicates)

    def visible_entries(self) -> list:
        rows = []
        for r in range(self.proxy_model.rowCount()):
            src = self.proxy_model.mapToSource(self.proxy_model.index(r, 0))
            entry = self.table_model.entry_at(src.row())
            if entry:
                rows.append(entry)
        return rows

    def current_entry(self):
        proxy_index = self.currentIndex()
        if not proxy_index.isValid():
            return None
        src = self.proxy_model.mapToSource(proxy_index)
        return self.table_model.entry_at(src.row())

    # -------- signals --------
    def _on_double(self, _index) -> None:
        entry = self.current_entry()
        if entry:
            self.entry_activated.emit(entry)

    def _on_selection(self, current, _previous) -> None:
        if current.isValid():
            entry = self.current_entry()
            if entry:
                self.selection_changed.emit(entry)

    # -------- copy context menu --------
    def contextMenuEvent(self, event) -> None:
        entry = self.current_entry()
        if entry is None:
            return
        menu = QMenu(self)
        copy_value = QAction("Copy Cell Value", menu)
        copy_cell = self._cell_at(event.pos())
        copy_value.triggered.connect(
            lambda checked=False, text=copy_cell: self._copy(text))

        copy_path = QAction("Copy Full Path", menu)
        copy_path.triggered.connect(lambda checked=False: self._copy(entry.display_path()))
        copy_cmd = QAction("Copy Command", menu)
        copy_cmd.triggered.connect(lambda checked=False: self._copy(entry.command))
        copy_raw = QAction("Copy Raw Data (JSON)", menu)
        copy_raw.triggered.connect(lambda checked=False: self._copy(_entry_json(entry)))

        menu.addAction(copy_value)
        menu.addAction(copy_path)
        menu.addAction(copy_cmd)
        menu.addSeparator()
        menu.addAction(copy_raw)
        menu.exec(event.globalPos())

    def _cell_at(self, pos):
        index = self.indexAt(pos)
        if not index.isValid():
            return ""
        value = self.model().data(index, Qt.DisplayRole)
        return str(value) if value is not None else ""

    @staticmethod
    def _copy(text: str) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)


def _entry_json(entry) -> str:
    try:
        import json
        return json.dumps(entry.to_dict(), ensure_ascii=False, indent=2, default=str)
    except Exception:
        return ""