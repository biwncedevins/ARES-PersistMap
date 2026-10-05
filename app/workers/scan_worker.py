"""Scan worker thread. Keeps the UI responsive during collection/analysis."""

from __future__ import annotations

import ctypes
import uuid
from typing import Callable, Optional

from PySide6.QtCore import QThread, Signal

from app.analysis.normalize import normalize_all
from app.analysis.signatures import SignatureEvaluator
from app.collectors import registry as reg_collector
from app.collectors import services as svc_collector
from app.collectors import startup as startup_collector
from app.collectors import tasks as task_collector
from app.collectors import wmi as wmi_collector
from app.models.enums import CollectionStatus, Source
from app.models.scan_result import ScanResult
from app.utils.hashing import HashCache
from app.utils.logging import get_logger

log = get_logger()

SOURCE_ORDER = [
    (Source.REGISTRY.value, reg_collector.collect),
    (Source.STARTUP.value, startup_collector.collect),
    (Source.SCHEDULED_TASK.value, task_collector.collect),
    (Source.SERVICE.value, svc_collector.collect),
    (Source.WMI.value, wmi_collector.collect),
]


def detect_privilege() -> str:
    """Return 'Administrator' or 'Standard User' without escalating."""
    try:
        admin = ctypes.windll.shell32.IsUserAnAdmin()
        return "Administrator" if admin else "Standard User"
    except Exception:
        return "Standard User"


class ScanWorker(QThread):
    progress = Signal(str)
    finished_scan = Signal(object)   # ScanResult
    failed = Signal(str)

    def __init__(self, tool_version: str, parent=None) -> None:
        super().__init__(parent)
        self.tool_version = tool_version
        self.hash_flagged = True
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:  # noqa: C901
        self.progress.emit("Scanning...")
        try:
            result = self.execute()
        except Exception as exc:  # top-level safety net
            log.exception("Scan aborted")
            self.failed.emit(str(exc))
            return
        self.finished_scan.emit(result)

    def execute(self) -> ScanResult:
        """Run the whole pipeline synchronously and return ScanResult.

        Exposed separately so UI smoke tests can drive a scan without a
        running event loop. Collector isolation lives here: one failed
        source never aborts the rest.
        """
        result = ScanResult.begin(self.tool_version, detect_privilege(),
                                  uuid.uuid4().hex[:12])
        signature_eval = SignatureEvaluator()
        hash_cache = HashCache()
        collected: dict[str, list] = {}

        for src_name, collector in SOURCE_ORDER:
            if self._cancelled:
                result.add_problem("Scan", "cancelled by user")
                return result
            self.progress.emit(f"Collecting {src_name}...")
            try:
                entries, status, meta = collector(
                    progress=lambda m: self.progress.emit(m),
                    errors=lambda source, msg: result.add_problem(source, msg),
                )
                collected[src_name] = entries
                result.set_source_status(src_name, status, len(entries))
            except Exception as exc:  # collector-level isolation
                log.exception("Collector %s failed", src_name)
                result.add_problem(src_name, f"collector crash: {exc}", level="ERROR")
                result.set_source_status(src_name, CollectionStatus.FAILED, 0)
            self.progress.emit(f"{src_name}: {len(collected.get(src_name, []))} items")

        # normalize + analyze
        self.progress.emit("Normalizing...")
        all_entries = [e for entries in collected.values() for e in entries]
        meta = normalize_all(all_entries, signature_eval, hash_cache,
                             hash_flagged=self.hash_flagged,
                             progress=lambda m: self.progress.emit(m),
                             errors=lambda source, msg: result.add_problem(source, msg))
        if "signature_errors" in meta:
            for err in meta["signature_errors"]:
                result.add_problem("Signature", err)
        self.progress.emit("Correlating...")
        result.entries = all_entries
        result.finish()
        self.progress.emit("Done")
        return result