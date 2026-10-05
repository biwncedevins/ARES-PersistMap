"""Post-processing pipeline: COLLECT -> NORMALIZE -> SIGN -> FLAG -> CORRELATE.

Turns raw collector output into fully-analysed entries:

1. resolve executable candidate & file state
2. authenticode signature (cached)
3. indicator engine
4. risk scoring
5. hashing of flagged files (capped, cached)
6. duplicate correlation

Warnings never raise; each step degrades gracefully.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from app.analysis import correlation, indicators, risk, signatures
from app.models.entry import PersistenceEntry
from app.models.enums import SignerStatus
from app.utils.hashing import HashCache
from app.utils import paths


def normalize_all(
    entries: list[PersistenceEntry],
    signature_eval: Optional[signatures.SignatureEvaluator] = None,
    hash_cache: Optional[HashCache] = None,
    hash_flagged: bool = True,
    progress: Optional[Callable[[str], None]] = None,
    errors: Optional[Callable[[str, str], None]] = None,
) -> dict:
    """Run the whole analysis over entries. Returns problem-meta dict."""
    meta = {"signature_checked": 0, "hash_computed": 0}
    sig = signature_eval or signatures.SignatureEvaluator()
    hcache = hash_cache or HashCache()
    engine = indicators.IndicatorEngine()

    # 1. structural resolution ------------------------------------------
    for entry in entries:
        _resolve_candidate(entry)

    # 2. signature checks -----------------------------------------------
    for entry in entries:
        candidate = entry.raw_data.get("_signature_candidate", "")
        if not candidate or entry.file_state != "Exists":
            entry.signer_status = (SignerStatus.UNAVAILABLE.value
                                   if entry.file_state == "Missing"
                                   else SignerStatus.UNKNOWN.value)
            entry.publisher = ""
            continue
        entry.signer_status = SignerStatus.UNKNOWN.value
        try:
            result = sig.evaluate(candidate)
        except Exception as exc:  # signature code must never kill the scan
            meta.setdefault("signature_errors", []).append(f"{candidate}: {exc}")
            _log_sig_error(errors, candidate, exc)
            result = signatures.SignatureResult(SignerStatus.UNKNOWN.value, detail="evaluator error")
        entry.signer_status = result.status
        entry.publisher = result.publisher
        entry.raw_data["signature"] = result.to_dict()
        if entry.signer_status not in (SignerStatus.UNKNOWN.value, SignerStatus.UNAVAILABLE.value):
            meta["signature_checked"] += 1

    # 3. indicators + risk -----------------------------------------------
    for entry in entries:
        engine.analyze(entry)
        risk.calculate(entry)

    # 4. hashing flagged files -------------------------------------------
    for entry in entries:
        if not entry.flagged:
            entry.raw_data["hash_status"] = "Not Calculated"
            continue
        candidate = entry.raw_data.get("_signature_candidate", "") or entry.path
        if not candidate or paths.file_extension(candidate) in (".lnk", ".url", ".scf"):
            entry.raw_data["hash_status"] = "Not Hashed (shortcut)"
            continue
        concrete = paths.expand_env(candidate)
        if not os.path.exists(concrete):
            entry.raw_data["hash_status"] = "File Missing"
            continue
        try:
            digest = hcache.sha256_of(concrete)
        except Exception:
            digest = ""
        if digest:
            entry.sha256 = digest
            entry.raw_data["hash_status"] = "Calculated"
            meta["hash_computed"] += 1
        else:
            entry.raw_data["hash_status"] = "Oversized / Unreadable"

    # 5. correlation ------------------------------------------------------
    groups = correlation.correlate(entries)
    meta["duplicate_groups"] = sum(1 for g in groups.values() if len(g) > 1)

    # 6. re-score after correlation so duplicate points are included ------
    for entry in entries:
        risk.calculate(entry)

    for entry in entries:
        entry.raw_data.pop("_signature_candidate", None)

    return meta


def _log_sig_error(errors, candidate: str, exc: Exception) -> None:
    if errors:
        errors("Signature", f"{candidate}: {exc}")


def _resolve_candidate(entry: PersistenceEntry) -> None:
    """Decide the best file to signature/hash and set file_state."""
    path_candidate = ""
    if entry.path:
        path_candidate = entry.path
    elif entry.command:
        program, _ = paths.split_command_line(entry.command)
        path_candidate = program or entry.command

    # prefs: for lnk/url startup artifacts, follow the target
    ext = paths.file_extension(path_candidate)
    if ext in (".lnk", ".url", ".scf") and entry.command and "." in entry.command:
        cmd_ext = paths.file_extension(entry.command)
        if cmd_ext not in (".lnk", ".url", ".scf"):
            path_candidate = entry.command

    if not path_candidate:
        entry.file_state = "N/A"
        entry.raw_data["_signature_candidate"] = ""
        return

    if not entry.file_extension:
        entry.file_extension = paths.file_extension(path_candidate) or entry.file_extension

    concrete = paths.expand_env(path_candidate)
    entry.raw_data["_signature_candidate"] = ""

    has_sep = "\\" in concrete or "/" in concrete
    if not has_sep:
        # bare executable name (notepad.exe): cannot safely resolve
        entry.file_state = "Unknown"
        return
    if not (concrete[1:2] == ":" or concrete.startswith("\\\\") or concrete.startswith("%")):
        # relative-style path (..\x.exe, .\x.exe): record, but too risky to stat
        entry.file_state = "Unknown"
        return
    if "%" in concrete:
        # leftover unexpandable variable
        entry.file_state = "Unknown"
        return

    entry.raw_data["_signature_candidate"] = concrete
    try:
        if os.path.exists(concrete):
            entry.file_state = "Exists"
        else:
            entry.file_state = "Missing"
    except OSError:
        entry.file_state = "Unknown"