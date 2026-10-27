from modules.database import Database
from modules.models import Finding, ScanConfig, ToolResult
from modules.scan_comparison import compare_scans


def _finding(title: str, fp: str, priority: str = "Low", score: float = 20.0) -> Finding:
    return Finding(title=title, source_tool="t", fingerprint=fp, priority=priority, risk_score=score,
                   sources=["t"], rationale=[{"factor": "Result", "effect": "x", "detail": "y"}],
                   references=["https://ref"], scanner_tags=["OWASP_2021_A05"])


def test_schema_init_is_idempotent_and_persistent(settings):
    db = Database(settings.db_path)
    sid = db.create_scan("http://127.0.0.1/", "127.0.0.1", ScanConfig(tools=["builtin"]), "live", "2021")
    Database(settings.db_path)  # re-initialise: must not drop data
    assert Database(settings.db_path).get_scan(sid)["target_url"] == "http://127.0.0.1/"


def test_findings_roundtrip(db):
    sid = db.create_scan("http://127.0.0.1/", "127.0.0.1", ScanConfig(tools=["builtin"]), "live", "2021")
    db.save_findings(sid, [_finding("A", "fa", "High", 70), _finding("B", "fb", "Low", 20)])
    db.add_tool_run(sid, ToolResult(tool="builtin", status="completed", message="ok"))
    rows = db.get_findings(sid)
    assert [r["title"] for r in rows] == ["A", "B"]
    assert rows[0]["rationale"][0]["factor"] == "Result"
    assert rows[0]["tags"] == ["OWASP_2021_A05"]
    assert db.get_tool_runs(sid)[0]["status"] == "completed"
    listed = db.list_scans()[0]
    assert listed["findings_count"] == 2 and listed["n_high"] == 1


def test_parameterised_queries_handle_hostile_text(db):
    evil = "x'); DROP TABLE scans; --"
    sid = db.create_scan(evil, evil, ScanConfig(tools=["builtin"]), "live", "2021")
    db.save_findings(sid, [_finding(evil, "f1")])
    assert db.get_scan(sid)["target_url"] == evil
    assert db.get_findings(sid)[0]["title"] == evil


def test_update_scan_ignores_unknown_columns(db):
    sid = db.create_scan("u", "h", ScanConfig(tools=["builtin"]), "live", "2021")
    db.update_scan(sid, status="completed", **{"target_url = 'x' --": "boom"})
    scan = db.get_scan(sid)
    assert scan["status"] == "completed" and scan["target_url"] == "u"


def test_migration_from_v1_adds_locations(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    from modules.database import SCHEMA
    v1_schema = SCHEMA.replace("    locations_json   TEXT NOT NULL DEFAULT '[]',\n", "")
    assert v1_schema != SCHEMA
    conn.executescript(v1_schema + "PRAGMA user_version = 1;")
    conn.close()
    Database(path)
    conn = sqlite3.connect(path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    conn.close()
    assert "locations_json" in cols


def test_mode_filter_separates_demo(db):
    db.create_scan("u", "h", ScanConfig(tools=["builtin"]), "live", "2021")
    db.create_scan("d", "h", ScanConfig(tools=["builtin"]), "demo", "2021")
    assert [s["mode"] for s in db.list_scans(mode="demo")] == ["demo"]
    assert len(db.list_scans()) == 2


def test_interrupted_scans_marked_failed_and_delete_cascade(db):
    sid = db.create_scan("u", "h", ScanConfig(tools=["builtin"]), "live", "2021")
    db.update_scan(sid, status="running")
    assert db.delete_scan(sid) is False  # running scans cannot be deleted
    assert db.mark_interrupted_scans() == 1
    assert db.get_scan(sid)["status"] == "failed"
    db.save_findings(sid, [_finding("A", "fa")])
    assert db.delete_scan(sid) is True
    assert db.get_findings(sid) == []


def test_compare_scans():
    def row(fp, prio, score):
        return {"fingerprint": fp, "title": fp, "priority": prio, "risk_score": score}
    old = [row("a", "High", 70), row("b", "Low", 20)]
    new = [row("a", "Medium", 45), row("c", "Critical", 90)]
    res = compare_scans(old, new)
    assert [f["fingerprint"] for f in res["new"]] == ["c"]
    assert [f["fingerprint"] for f in res["resolved"]] == ["b"]
    assert [f["fingerprint"] for f in res["persistent"]] == ["a"]
    assert res["priority_changes"][0]["direction"] == "better"
    assert res["max_risk_after"] == 90
