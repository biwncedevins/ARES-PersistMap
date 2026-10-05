"""Risk engine: additive, explainable, capped, no verdict inflation."""

from __future__ import annotations

import config
from app.analysis import risk
from app.models.enums import RiskLevel
from tests.conftest import make_entry


def test_low_for_benign():
    e = make_entry(command=r'C:\Windows\System32\notepad.exe',
                   signer_status="Signed", path=r"C:\Windows\System32\notepad.exe")
    e.indicators = []
    score, reasons = risk.calculate(e)
    assert score == 0
    assert reasons == []
    assert e.risk_level == RiskLevel.LOW.value


def test_no_base_score_for_source():
    """Being a Service or Run key alone earns NO points."""
    for source in ("Registry", "Service", "Scheduled Task"):
        e = make_entry(source=source)
        e.indicators = []
        score, _ = risk.calculate(e)
        assert score == 0


def test_reasons_explainable():
    e = make_entry(command="powershell.exe -EncodedCommand AAAA",
                   path=r"C:\Users\a\AppData\Local\Temp\p.ps1",
                   signer_status="Unsigned")
    from app.analysis.indicators import IndicatorEngine
    IndicatorEngine().analyze(e)
    score, reasons = risk.calculate(e)
    assert score >= 21
    assert reasons, "reasons must be populated when score > 0"
    for reason in reasons:
        assert reason.startswith("+"), reason


def test_score_capped():
    e = make_entry()
    e.indicators = [
        __import__("app.models.entry", fromlist=["Indicator"]).Indicator(
            label="a", tag="t", points=config.RISK_POINTS["obfuscation"]) for _ in range(50)
    ]
    score, _ = risk.calculate(e)
    assert score <= config.RISK_WEIGHT_MAX


def test_level_thresholds():
    cases = [(20, RiskLevel.LOW), (40, RiskLevel.MEDIUM), (60, RiskLevel.ELEVATED),
             (80, RiskLevel.HIGH), (90, RiskLevel.CRITICAL)]
    for score, expected in cases:
        e = make_entry()
        e.risk_score = score
        risk.relabel_risk_levels(e)
        assert e.risk_level == expected.value or risk._level_for(score) == expected.value


def test_flagged_at_50():
    e = make_entry()
    e.indicators = [
        __import__("app.models.entry", fromlist=["Indicator"]).Indicator(
            label="tmp", tag="T", points=20)
        for _ in range(3)
    ]
    risk.calculate(e)
    assert e.risk_score >= 50
    assert e.flagged is True


def test_deterministic():
    a = make_entry()
    b = make_entry()
    from app.analysis.indicators import IndicatorEngine
    IndicatorEngine().analyze(a)
    IndicatorEngine().analyze(b)
    ra, _ = risk.calculate(a)
    rb, _ = risk.calculate(b)
    assert ra == rb