"""Models: serialization roundtrips, defaults, risk level mapping."""

from __future__ import annotations

import pytest

from app.models.entry import Indicator, PersistenceEntry, RiskReport, _risk_level_from_score
from app.models.enums import RiskLevel, Source
from tests.conftest import make_entry


def test_risk_level_buckets():
    assert _risk_level_from_score(0) is RiskLevel.LOW
    assert _risk_level_from_score(20) is RiskLevel.LOW
    assert _risk_level_from_score(21) is RiskLevel.MEDIUM
    assert _risk_level_from_score(40) is RiskLevel.MEDIUM
    assert _risk_level_from_score(41) is RiskLevel.ELEVATED
    assert _risk_level_from_score(60) is RiskLevel.ELEVATED
    assert _risk_level_from_score(61) is RiskLevel.HIGH
    assert _risk_level_from_score(80) is RiskLevel.HIGH
    assert _risk_level_from_score(81) is RiskLevel.CRITICAL
    assert _risk_level_from_score(100) is RiskLevel.CRITICAL


def test_to_dict_minimal():
    e = make_entry()
    d = e.to_dict()
    assert d["name"] == "TestEntry"
    assert d["source"] == "Registry"
    assert d["risk_level"]  # always populated


def test_roundtrip():
    e = make_entry(risk_score=55, risk_reasons=["+15 test"], flagged=True)
    e.add_indicator("PowerShell", "Script", evidence="-enc")
    restored = PersistenceEntry.from_dict(e.to_dict())
    assert restored.name == e.name
    assert restored.risk_score == 55
    assert restored.flagged is True
    assert restored.indicators[0].label == "PowerShell"
    assert restored.risk_reasons == ["+15 test"]


def test_stable_id():
    a = make_entry()
    b = make_entry()
    assert a.id == b.id  # deterministic across instances
    c = make_entry(name="Different")
    assert a.id != c.id


def test_default_unknown_not_invented():
    e = PersistenceEntry(source="WMI", category="w", name="x")
    d = e.to_dict()
    assert d["signer_status"]  # never empty
    assert isinstance(d["path"], str)


def test_indicator_serialization():
    ind = Indicator(label="L", tag="T", evidence="ev", points=5)
    d = ind.to_dict()
    assert Indicator.from_dict(d).points == 5


def test_flagged_driven_by_risk():
    e = make_entry(risk_score=70)
    assert e.flagged is True
    e2 = make_entry(risk_score=10)
    assert e2.flagged is False


def test_risk_report():
    r = RiskReport(score=45)
    assert r.level is RiskLevel.ELEVATED
    d = r.to_dict()
    assert RiskReport.from_dict(d).score == 45