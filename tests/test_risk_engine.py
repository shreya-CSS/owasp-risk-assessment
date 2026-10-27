import pytest

from modules.models import Finding
from modules.risk_engine import RiskContext, prioritise, score_finding, score_to_priority


def _f(**kw) -> Finding:
    kw.setdefault("title", "x")
    kw.setdefault("source_tool", "test")
    return Finding(**kw)


@pytest.mark.parametrize("score,level", [(100, "Critical"), (80, "Critical"), (79.9, "High"), (60, "High"),
                                         (35, "Medium"), (34.9, "Low"), (15, "Low"), (14.9, "Informational"),
                                         (0, "Informational")])
def test_thresholds(score, level):
    assert score_to_priority(score) == level


def test_base_scores_neutral_context(mapper):
    ctx = RiskContext()
    assert score_finding(_f(scanner_severity="medium", confidence="high"), mapper, ctx).risk_score == 45
    assert score_finding(_f(scanner_severity="high", confidence="high"), mapper, ctx).priority == "High"
    assert score_finding(_f(scanner_severity="info", confidence="high"), mapper, ctx).priority == "Informational"


def test_confidence_reduces_score(mapper):
    f = score_finding(_f(scanner_severity="medium", confidence="low"), mapper, RiskContext())
    assert f.risk_score == 27.0
    assert f.priority == "Low"
    assert any(r["factor"] == "Evidence confidence" for r in f.rationale)


def test_full_example_is_reproducible(mapper):
    """High SQLi, medium confidence, mapped A03, exploit evidence, high criticality, internet:
    70*0.85 + 10 + 10 + 10 + 5 = 94.5 -> Critical."""
    f = _f(scanner_severity="high", confidence="medium", exploit_evidence=True,
           owasp_id="A03:2021", owasp_name="Injection", owasp_status="mapped")
    f = score_finding(f, mapper, RiskContext("high", "internet"))
    assert f.risk_score == 94.5
    assert f.priority == "Critical"
    factors = [r["factor"] for r in f.rationale]
    assert factors == ["Base (scanner severity)", "Evidence confidence", "Category impact", "Exploitability",
                       "Asset criticality", "Exposure", "Result"]


def test_potential_mapping_gets_half_weight(mapper):
    f = _f(scanner_severity="medium", confidence="high", owasp_id="A03:2021", owasp_status="potential")
    assert score_finding(f, mapper, RiskContext()).risk_score == 50


def test_guardrail_caps_low_severity(mapper):
    f = _f(scanner_severity="info", confidence="high", owasp_id="A01:2021", owasp_status="mapped",
           exploit_evidence=True, locations=[f"http://h/{i}" for i in range(10)])
    f = score_finding(f, mapper, RiskContext("high", "internet"))
    assert f.risk_score == 45
    assert f.priority == "Low"  # info -> at most one level above (Low)
    assert any(r["factor"] == "Guardrail" for r in f.rationale)


def test_scanner_cvss_used_and_labelled(mapper):
    f = score_finding(_f(scanner_severity="medium", confidence="high", cvss_score=9.8), mapper, RiskContext())
    assert f.risk_score == 98
    assert "CVSS" in f.rationale[0]["factor"]


def test_unrated_uses_documented_baseline(mapper):
    f = score_finding(_f(scanner_severity="unrated"), mapper, RiskContext())
    assert f.risk_score == 16.0  # 20 * 0.8 (unknown confidence)
    assert "does not rate" in f.rationale[0]["detail"]


def test_lab_exposure_and_low_criticality_lower_score(mapper):
    f = score_finding(_f(scanner_severity="low", confidence="high"), mapper, RiskContext("low", "lab"))
    assert f.risk_score == 5
    assert f.priority == "Informational"


def test_score_clamped(mapper):
    f = _f(scanner_severity="critical", confidence="confirmed", exploit_evidence=True,
           owasp_id="A03:2021", owasp_status="mapped")
    assert score_finding(f, mapper, RiskContext("high", "internet")).risk_score == 100


def test_prioritise_orders_by_priority_then_score(mapper):
    out = prioritise([_f(title="a", scanner_severity="low", confidence="high"),
                      _f(title="b", scanner_severity="high", confidence="high"),
                      _f(title="c", scanner_severity="medium", confidence="high")], mapper, RiskContext())
    assert [f.title for f in out] == ["b", "c", "a"]
