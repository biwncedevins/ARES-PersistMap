"""Risk engine.

Scoring is purely additive heuristics. Each contributor records WHY:

    Risk: 74
    +15 Unsigned executable
    +20 User-writable directory
    +15 PowerShell execution
    ...

There is deliberately no base score for "being a service" or "being a run
key". The result is a ``risk_score`` integer plus a list of human-readable
reasons, so the analyst can audit every point.
"""

from __future__ import annotations

import config
from app.models.entry import PersistenceEntry
from app.models.enums import RiskLevel


def _cap(score: int) -> int:
    return max(0, min(config.RISK_WEIGHT_MAX, score))


def calculate(entry: PersistenceEntry) -> tuple[int, list[str]]:
    """Compute risk and return (score, reasons)."""
    score = 0
    reasons: list[str] = []

    # --- dedicated points from indicators --------------------------------
    for ind in entry.indicators:
        if ind.points is None:
            continue
        score += int(ind.points) or 0
        if ind.evidence:
            reasons.append(f"+{ind.points} {ind.label}: {ind.evidence}")
        else:
            reasons.append(f"+{ind.points} {ind.label}")

    # --- signer nuance ---------------------------------------------------
    if str(entry.signer_status) == "Unsigned" and not any(
            i.tag == "Unsigned" for i in entry.indicators):
        score += config.RISK_POINTS["unsigned"]
        reasons.append(f"+{config.RISK_POINTS['unsigned']} Unsigned executable")

    # --- SYSTEM account tasks --------------------------------------------
    user = str(entry.user or "").lower().replace(" ", "")
    if err := _system_bonus(user, entry):
        score += err[0]
        reasons.append(err[1])

    score = _cap(score)

    # keep reasons stable + deduped
    unique: list[str] = []
    for r in reasons:
        if r not in unique:
            unique.append(r)

    # if literally nothing reported, don't fake a score
    if not entry.indicators and score == 0:
        entry.risk_score = 0
        entry.risk_level = RiskLevel.LOW.value
        entry.risk_reasons = []
        entry.flagged = False
        return 0, []

    entry.risk_score = score
    entry.risk_level = _level_for(score)
    entry.risk_reasons = unique
    entry.flagged = score >= 50
    return score, unique


def _system_bonus(user: str, entry: PersistenceEntry):
    if "system" in user and not any(i.tag == "System Account" for i in entry.indicators):
        return config.RISK_POINTS["system_user"], (
            f"+{config.RISK_POINTS['system_user']} Runs as SYSTEM")
    return None


def _level_for(score: int) -> str:
    for threshold, name in config.RISK_LEVELS:
        if score >= threshold:
            level = name
    return level


def relabel_risk_levels(entry: PersistenceEntry) -> None:
    """Standalone helper kept for API symmetry."""
    entry.risk_level = _level_for(entry.risk_score)