"""End-to-end orchestration: statuses for complete, partial, failed, empty and cancelled scans."""
import threading
import time

import pytest

from modules.models import Finding, ScanConfig, ToolResult
from modules.scan_manager import ScanManager, overall_status
from modules.scanner_base import Scanner
from modules.target_validation import TargetValidationError


class FakeScanner(Scanner):
    def __init__(self, settings, name, status="completed", findings=None, delay=0.0, raise_exc=False):
        super().__init__(settings)
        self.name, self.label = name, name
        self._status, self._findings, self._delay, self._raise = status, findings or [], delay, raise_exc

    def availability(self):
        return True, "fake"

    def run(self, target, config, cancel_event):
        if self._raise:
            raise RuntimeError("adapter bug with secret path C:/secret")
        end = time.monotonic() + self._delay
        while time.monotonic() < end:
            if cancel_event.is_set():
                return self.result("cancelled", "cancelled")
            time.sleep(0.05)
        return self.result(self._status, "msg", findings=list(self._findings))


def _manager(settings, db, **scanners):
    return ScanManager(settings, db=db, scanners=scanners)


def _run(manager, tools):
    target, config = manager.prepare("http://127.0.0.1/", ScanConfig(tools=tools))
    sid = manager.db.create_scan(target.url, target.host, config, "live", "2021", target.policy_reason)
    return sid, manager.run_scan(sid, target, config)


def test_overall_status_rules():
    ok, bad = ToolResult("a", "completed"), ToolResult("b", "unavailable", message="x")
    assert overall_status([ok], False)[0] == "completed"
    assert overall_status([ok, bad], False)[0] == "partial"
    assert overall_status([bad], False)[0] == "failed"
    assert overall_status([ok], True)[0] == "cancelled"


def test_complete_scan_persists_scored_findings(settings, db):
    f = Finding(title="X-Content-Type-Options header missing", source_tool="builtin", scanner_severity="low",
                confidence="high", issue_key="header-missing:x-content-type-options", affected_url="http://127.0.0.1/")
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin", findings=[f]))
    sid, status = _run(m, ["builtin"])
    assert status == "completed"
    rows = db.get_findings(sid)
    assert rows[0]["owasp_id"] == "A05:2021" and rows[0]["priority"] in ("Low", "Medium")
    assert rows[0]["rationale"] and rows[0]["remediation"]


def test_partial_scan_when_one_tool_missing(settings, db):
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin"),
                 zap=FakeScanner(settings, "zap", status="unavailable"))
    sid, status = _run(m, ["builtin", "zap"])
    assert status == "partial"
    assert "zap: unavailable" in db.get_scan(sid)["error"]


def test_failed_scan_and_adapter_exception_is_contained(settings, db):
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin", raise_exc=True))
    sid, status = _run(m, ["builtin"])
    assert status == "failed"
    run = db.get_tool_runs(sid)[0]
    assert run["status"] == "failed" and "RuntimeError" in run["message"]
    assert "secret" not in run["message"]  # no exception detail leaks


def test_empty_scan_is_completed_with_no_findings(settings, db):
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin"))
    sid, status = _run(m, ["builtin"])
    assert status == "completed" and db.get_findings(sid) == []


def test_background_scan_can_be_cancelled(settings, db):
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin", delay=10),
                 nmap=FakeScanner(settings, "nmap"))
    sid = m.start_scan("http://127.0.0.1/", ScanConfig(tools=["builtin", "nmap"]), authorized=True)
    time.sleep(0.3)
    assert m.cancel(sid)
    m._threads[sid].join(timeout=10)
    scan = db.get_scan(sid)
    assert scan["status"] == "cancelled"
    assert [r["status"] for r in db.get_tool_runs(sid)] == ["cancelled", "skipped"]


def test_start_requires_authorization_and_valid_target(settings, db):
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin"))
    with pytest.raises(TargetValidationError, match="authorized"):
        m.start_scan("http://127.0.0.1/", ScanConfig(tools=["builtin"]), authorized=False)
    with pytest.raises(TargetValidationError):
        m.start_scan("http://169.254.169.254/", ScanConfig(tools=["builtin"]), authorized=True)
    assert db.list_scans() == []  # nothing stored for rejected targets


def test_only_one_scan_at_a_time(settings, db):
    from modules.scan_manager import ScanBusyError
    m = _manager(settings, db, builtin=FakeScanner(settings, "builtin", delay=5))
    sid = m.start_scan("http://127.0.0.1/", ScanConfig(tools=["builtin"]), authorized=True)
    with pytest.raises(ScanBusyError):
        m.start_scan("http://127.0.0.1/", ScanConfig(tools=["builtin"]), authorized=True)
    m.cancel(sid)
    m._threads[sid].join(timeout=10)


def test_demo_scan_is_labelled_and_separate(settings, db):
    m = ScanManager(settings, db=db)
    sid = m.create_demo_scan()
    assert db.get_scan(sid)["mode"] == "demo"
    assert db.list_scans(mode="live") == []
    rows = db.get_findings(sid)
    assert rows and all(all("demo fixture" in s for s in r["sources"]) for r in rows)
    # cross-tool duplicates merged
    assert any(len(r["sources"]) > 1 for r in rows)


def test_real_builtin_scan_end_to_end(settings, db, lab_url):
    """Real HTTP checks against the local lab: validation -> scan -> SQLite -> report."""
    from modules.report_generator import generate_csv, generate_pdf
    m = ScanManager(settings, db=db)
    target, config = m.prepare(lab_url, ScanConfig(tools=["builtin"], exposure="lab"))
    sid = db.create_scan(target.url, target.host, config, "live", "2021", target.policy_reason)
    assert m.run_scan(sid, target, config, threading.Event()) == "completed"
    rows = db.get_findings(sid)
    assert len(rows) >= 10
    assert {r["owasp_id"] for r in rows} >= {"A01:2021", "A02:2021", "A05:2021"}
    pdf = generate_pdf(db.get_scan(sid), rows, db.get_tool_runs(sid), m.mapper.title)
    assert pdf.startswith(b"%PDF") and generate_csv(rows)
