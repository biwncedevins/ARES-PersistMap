"""Left navigation sidebar."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import QLabel, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

# page roles
PAGE_OVERVIEW = "overview"
PAGE_ALL = "all"
PAGE_REGISTRY = "registry"
PAGE_STARTUP = "startup"
PAGE_TASKS = "tasks"
PAGE_SERVICES = "services"
PAGE_WMI = "wmi"
PAGE_DUPLICATES = "duplicates"
PAGE_REPORTS = "reports"
PAGE_SETTINGS = "settings"

ITEMS = [
    (PAGE_OVERVIEW, "Overview", True),
    (None, "", False),
    (PAGE_ALL, "ALL ENTRIES", True),
    (None, "", False),
    (PAGE_REGISTRY, "Registry", True),
    (PAGE_STARTUP, "Startup", True),
    (PAGE_TASKS, "Scheduled Tasks", True),
    (PAGE_SERVICES, "Services", True),
    (PAGE_WMI, "WMI", True),
    (None, "", False),
    (PAGE_DUPLICATES, "Duplicates", True),
    (PAGE_REPORTS, "Reports", True),
    (PAGE_SETTINGS, "Settings", True),
]

_R = Qt.ItemDataRole.UserRole


class Sidebar(QWidget):
    page_selected = Signal(str)

    def __init__(self, counts: dict[str, int] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(228)
        self._counts = counts or {}
        self._items: dict[str, QListWidgetItem] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        title = QLabel("PERSISTMAP")
        title.setObjectName("appTitle")
        subtitle = QLabel("WINDOWS PERSISTENCE INVENTORY")
        subtitle.setObjectName("appSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        section = QLabel("NAVIGATION")
        section.setObjectName("sectionHeader")
        layout.addWidget(section)

        self.nav = QListWidget()
        self.nav.setObjectName("sourceNav")
        self.nav.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.nav.currentTextChanged.connect(self._on_current)
        self.nav.setFrameShape(QListWidget.Shape.NoFrame)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        for page, label, selectable in ITEMS:
            if not selectable:
                item = QListWidgetItem()
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                item.setSizeHint(QSize(0, 8))
                self.nav.addItem(item)
                continue
            item = QListWidgetItem(label)
            item.setData(_R, page)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            self.nav.addItem(item)
            self._items[page] = item

        layout.addWidget(self.nav, 1)
        self.nav.setCurrentRow(0)

    def _on_current(self, _text: str) -> None:
        item = self.nav.currentItem()
        if item:
            page = item.data(_R)
            if page:
                self.page_selected.emit(page)

    def select_page(self, page: str) -> None:
        if page in self._items:
            self.nav.setCurrentItem(self._items[page])

    def update_counts(self, counts: dict[str, int]) -> None:
        self._counts = counts
        mapping = {
            PAGE_REGISTRY: counts.get("Registry", 0),
            PAGE_STARTUP: counts.get("Startup", 0),
            PAGE_TASKS: counts.get("Scheduled Task", 0),
            PAGE_SERVICES: counts.get("Service", 0),
            PAGE_WMI: counts.get("WMI", 0),
        }
        total = sum(mapping.values())
        if PAGE_ALL in self._items:
            self._items[PAGE_ALL].setText(f"ALL ENTRIES   {total}")
        for page, count in mapping.items():
            item = self._items.get(page)
            if not item:
                continue
            base = item.text().split("  ")[0]
            item.setText(f"{base}  {count}")