import pytest

from modules.finding_normalizer import deduplicate
from modules.models import Finding
from modules.owasp_mapper import get_mapper


def _f(**kw) -> Finding:
    kw.setdefault("source_tool", "test")
    kw.setdefault("title", "Something")
    return Finding(**kw)


def test_mapping_file_has_ten_categories(mapper):
    assert sorted(mapper.categories) == [f"A{i:02d}" for i in range(1, 11)]
    assert mapper.title == "OWASP Top 10:2021"


def test_scanner_tag_wins(mapper):
    f = mapper.map_finding(_f(scanner_tags=["OWASP_2021_A05", "OWASP_2017_A06"], cwe_id=79))
    assert (f.owasp_id, f.owasp_status) == ("A05:2021", "mapped")
    assert "tag" in f.owasp_basis


def test_issue_key_rule_before_cwe(mapper):
    f = mapper.map_finding(_f(issue_key="disclosure:server-version", cwe_id=497))
    assert f.owasp_id == "A05:2021"


@pytest.mark.parametrize("cwe,expected", [(89, "A03"), (79, "A03"), (22, "A01"), (319, "A02"), (918, "A10"),
                                          (502, "A08"), (287, "A07"), (1021, "A04")])
def test_cwe_mapping(mapper, cwe, expected):
    f = mapper.map_finding(_f(cwe_id=cwe))
    assert f.owasp_id == f"{expected}:2021"
    assert f.owasp_status == "mapped"
    assert f"CWE-{cwe}" in f.owasp_basis


def test_keyword_mapping_is_only_potential(mapper):
    f = mapper.map_finding(_f(title="Possible SQL Injection in login"))
    assert (f.owasp_id, f.owasp_status) == ("A03:2021", "potential")


def test_open_port_is_potential(mapper):
    f = mapper.map_finding(_f(issue_key="open-port:tcp/22", title="Open port 22/tcp (ssh)"))
    assert f.owasp_status == "potential"


def test_unmapped_when_no_evidence(mapper):
    f = mapper.map_finding(_f(title="Interesting header", cwe_id=99999))
    assert f.owasp_status == "unmapped"
    assert f.owasp_id == ""


def test_unknown_edition_rejected():
    with pytest.raises(FileNotFoundError):
        get_mapper("1999")
    with pytest.raises(ValueError):
        get_mapper("../etc")


# --- normalisation / de-duplication ---------------------------------------------------

def test_duplicates_merged_with_evidence_and_sources_kept():
    a = _f(source_tool="zap", issue_key="header-missing:x-frame-options", affected_url="http://h/?a=1",
           scanner_severity="medium", confidence="medium", evidence="zap evidence")
    b = _f(source_tool="builtin", issue_key="header-missing:x-frame-options", affected_url="http://h/?b=2",
           scanner_severity="low", confidence="high", evidence="builtin evidence")
    out = deduplicate([a, b])
    assert len(out) == 1
    m = out[0]
    assert m.sources == ["zap", "builtin"]
    assert m.occurrences == 2
    assert m.scanner_severity == "medium" and m.confidence == "high"
    assert "zap evidence" in m.evidence and "builtin evidence" in m.evidence


def test_same_issue_on_many_pages_grouped_with_locations():
    out = deduplicate([_f(rule_id="r1", affected_url="http://h/a?x=1"), _f(rule_id="r1", affected_url="http://h/b"),
                       _f(rule_id="r1", affected_url="http://h/a?x=2")])
    assert len(out) == 1
    assert out[0].locations == ["http://h/a", "http://h/b"]
    assert out[0].occurrences == 3


def test_different_host_or_parameter_not_merged():
    assert len(deduplicate([_f(rule_id="r1", affected_url="http://h1/"),
                            _f(rule_id="r1", affected_url="http://h2/")])) == 2
    assert len(deduplicate([_f(rule_id="r1", affected_url="http://h/", parameter="q"),
                            _f(rule_id="r1", affected_url="http://h/", parameter="id")])) == 2


def test_sanitisation_strips_control_chars_and_caps_length():
    f = deduplicate([_f(title="bad\x00title\x1b[31m", evidence="x" * 10000, scanner_severity="Informational",
                        confidence="False Positive", cvss_score=42)])[0]
    assert "\x00" not in f.title and "\x1b" not in f.title
    assert len(f.evidence) <= 2000
    assert f.scanner_severity == "info"
    assert f.confidence == "unknown"
    assert f.cvss_score is None


def test_empty_input():
    assert deduplicate([]) == []
