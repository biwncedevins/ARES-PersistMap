"""JSON export. Fixed, re-readable schema (see ScanResult.to_dict)."""

from __future__ import annotations

import json
from typing import Optional

from app.models.scan_result import ScanResult


def export_json(result: ScanResult, file_path: str,
                indent: int = 2, errors: Optional[callable] = None) -> bool:
    data = result.to_dict()
    try:
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=indent,
                      default=str)
        return True
    except (OSError, TypeError) as exc:
        if errors:
            errors("JSON Export", f"{file_path}: {exc}")
        return False