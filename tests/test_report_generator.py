import csv
import io

import pypdf
import pytest

from modules.report_generator import csv_safe, generate_csv, generate_pdf, safe_report_path
from modules.scan_manager import ScanManager


def _pdf_text(data: bytes) -> str:
    return "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(data)).pages)


@pytest.fixture
def demo(settings, db):
    manager = ScanManager(settings, db=db)
    sid = manager.create_demo_scan()
    return manager, sid


def test_pdf_contains_required_sections(demo):
    manager, sid = demo
    pdf = generate_pdf(manager.db.get_scan(sid), manager.db.get_findings(sid), manager.db.get_tool_runs(sid),
                       manager.mapper.title)
    assert pdf.startswith(b"%PDF")
    text = _pdf_text(pdf)
    for section in ("Target and scan configuration", "Executive summary", "Findings overview",
                    "Finding details", "Priority rationale", "Recommended remediation",
                    "Assessment limitations", "SQL Injection", "DEMO"):
        assert section in text, section


def test_pdf_for_failed_empty_scan_states_failure(settings, db):
    from modules.models import ScanConfig, ToolResult
    sid = db.create_scan("http://127.0.0.1/", "127.0.0.1", ScanConfig(tools=["zap"]), "live", "2021")
    db.add_tool_run(sid, ToolResult(tool="zap", status="unavailable", message="Cannot reach the ZAP API"))
    db.update_scan(sid, status="failed", error="zap: unavailable")
    text = _pdf_text(generate_pdf(db.get_scan(sid), [], db.get_tool_runs(sid), "OWASP Top 10:2021"))
    assert "did not complete" in text
    assert "Cannot reach the ZAP API" in text
    assert "No findings were recorded" in text
    assert "DEMO" not in text


def test_pdf_handles_unicode_and_hostile_evidence(demo):
    manager, sid = demo
    findings = manager.db.get_findings(sid)
    findings[0]["evidence"] = "<script>alert('x')</script> ünïcödé — 漢字 " + "A" * 500
    pdf = generate_pdf(manager.db.get_scan(sid), findings, [], manager.mapper.title)
    assert pdf.startswith(b"%PDF")


def test_csv_export_and_formula_injection(demo):
    manager, sid = demo
    findings = manager.db.get_findings(sid)
    findings[0]["title"] = "=HYPERLINK(\"http://evil\")"
    data = generate_csv(findings).decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(data)))
    assert len(rows) == len(findings)
    assert rows[0]["title"].startswith("'=")
    assert {"priority", "risk_score", "owasp_id", "remediation"} <= set(rows[0])


def test_csv_empty():
    assert generate_csv([]).decode("utf-8-sig").startswith("priority,")


@pytest.mark.parametrize("value,expected", [("=1+1", "'=1+1"), ("+x", "'+x"), ("-x", "'-x"), ("@x", "'@x"),
                                            ("ok", "ok"), (None, "")])
def test_csv_safe(value, expected):
    assert csv_safe(value) == expected


def test_report_path_stays_inside_reports_dir(tmp_path):
    path = safe_report_path(tmp_path, "a" * 32, "pdf")
    assert path.parent == tmp_path.resolve()
    for bad in ("../../etc/passwd", "a" * 31, "A" * 32, ""):
        with pytest.raises(ValueError):
            safe_report_path(tmp_path, bad, "pdf")
    with pytest.raises(ValueError):
        safe_report_path(tmp_path, "a" * 32, "exe")
