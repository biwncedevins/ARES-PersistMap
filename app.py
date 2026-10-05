"""PersistMap entry point."""

from __future__ import annotations

import os
import sys

import config
from app.utils.logging import get_logger

log = get_logger()


def main() -> int:
    log.info("PersistMap %s starting (cwd=%s)", config.APP_VERSION, os.getcwd())

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    app.setApplicationName("PersistMap")
    app.setOrganizationName("PersistMap")
    app.setAttribute(Qt.ApplicationAttribute.AA_DontShowIconsInMenus, True)

    # coupe de la cascade de style
    qss_path = os.path.join(os.path.dirname(__file__), "app", "ui", "styles.qss")
    try:
        with open(qss_path, "r", encoding="utf-8") as fh:
            app.setStyleSheet(fh.read())
    except OSError as exc:
        log.warning("Could not load stylesheet: %s", exc)

    from app.ui.main_window import MainWindow

    window = MainWindow()
    window.show()

    code = app.exec()
    log.info("PersistMap exiting with code %s", code)
    return int(code)


if __name__ == "__main__":
    raise SystemExit(main())