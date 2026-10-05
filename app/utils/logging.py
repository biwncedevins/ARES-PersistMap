"""Internal logging.

Logs go to logs/persistmap.log. Levels: DEBUG / INFO / WARNING / ERROR.
The UI only sees high-level scan progress and warnings; technical details
live in this file.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

import config

_LOGGER: logging.Logger | None = None


def _logs_dir() -> str:
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(base, config.LOGS_DIR_NAME)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        path = os.path.join(os.path.expanduser("~"), ".persistmap", "logs")
        os.makedirs(path, exist_ok=True)
    return path


def get_logger() -> logging.Logger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER

    logger = logging.getLogger("persistmap")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if not logger.handlers:
        fmt = logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s [%(module)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        try:
            logfile = os.path.join(_logs_dir(), "persistmap.log")
            fh = RotatingFileHandler(logfile, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError:
            pass  # logging is best-effort, never crash the app

    _LOGGER = logger
    return logger


def get_logs_file() -> str:
    return os.path.join(_logs_dir(), "persistmap.log")